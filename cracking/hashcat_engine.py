"""
cracking/hashcat_engine.py - Core hashcat integration

Handles:
  - Binary resolution (bundled hashcat-7.1.2/hashcat.bin → system hashcat)
  - GPU/device detection
  - .cap → .22000 format conversion (via hcxpcapngtool)
  - Multiple attack modes: dictionary, dictionary+rules, mask/brute-force
  - Live progress streaming with JSON status parsing
  - Potfile management (skip already-cracked hashes)
  - Result extraction from stdout or potfile
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from utils.logger import Logger
from utils.tools import check_tool

log = Logger()


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class DeviceInfo:
    """Represents a hashcat compute device (GPU or CPU)."""
    device_id: int
    device_name: str
    device_type: str  # "GPU", "CPU", "FPGA", etc.
    driver_version: str = ""
    is_gpu: bool = False


@dataclass
class CrackResult:
    """Result of a hashcat cracking attempt."""
    cracked: bool = False
    password: str = ""
    hash_file: str = ""
    attack_mode: str = ""
    phase: str = ""
    speed: str = ""
    time_elapsed: float = 0.0
    exhausted: bool = False
    error: str = ""
    skipped: bool = False


# ── Hashcat Engine ────────────────────────────────────────────────────────────

class HashcatEngine:
    """Core wrapper around the hashcat binary.

    Resolves the binary path, detects GPU devices, converts capture files,
    and runs hashcat with live progress streaming.
    """

    # Hash mode for WPA-PBKDF2-PMKID+EAPOL (hashcat ≥ 6.0)
    WPA_HASH_MODE = "22000"

    def __init__(
        self,
        hashcat_path: Optional[str] = None,
        project_root: Optional[str] = None,
    ):
        self._project_root = project_root or self._find_project_root()
        self._hashcat_path = hashcat_path or self._resolve_binary()
        self._rules_dir = os.path.join(self._project_root, "hashcat-7.1.2", "rules")
        self._masks_dir = os.path.join(self._project_root, "hashcat-7.1.2", "masks")
        self._devices: Optional[list[DeviceInfo]] = None

    # ── Binary resolution ─────────────────────────────────────────────────

    @staticmethod
    def _find_project_root() -> str:
        """Walk up from this file to find the WiAuditor project root
        (the directory containing both wauditor/ and hashcat-7.1.2/)."""
        current = Path(__file__).resolve()
        for parent in [current.parent, *current.parents]:
            if (parent / "hashcat-7.1.2" / "hashcat.bin").exists():
                return str(parent)
            # Also check one level up (wauditor/ is inside project root)
            if (parent.parent / "hashcat-7.1.2" / "hashcat.bin").exists():
                return str(parent.parent)
        # Fallback: assume CWD is project root
        return os.getcwd()

    def _resolve_binary(self) -> str:
        """Resolve hashcat binary: bundled first, then system PATH."""
        # 1. Bundled binary
        bundled = os.path.join(self._project_root, "hashcat-7.1.2", "hashcat.bin")
        if os.path.isfile(bundled) and os.access(bundled, os.X_OK):
            log.debug(f"Using bundled hashcat: {bundled}")
            return bundled

        # 2. System hashcat
        system_hashcat = shutil.which("hashcat")
        if system_hashcat:
            log.debug(f"Using system hashcat: {system_hashcat}")
            return system_hashcat

        raise FileNotFoundError(
            "hashcat not found. Install hashcat or ensure hashcat-7.1.2/hashcat.bin exists."
        )

    @property
    def binary_path(self) -> str:
        return self._hashcat_path

    @property
    def rules_dir(self) -> str:
        return self._rules_dir

    @property
    def masks_dir(self) -> str:
        return self._masks_dir

    def is_available(self) -> bool:
        """Check if hashcat binary is available and executable."""
        try:
            self._resolve_binary()
            return True
        except FileNotFoundError:
            return False

    # ── Device detection ──────────────────────────────────────────────────

    # AMD GPU identifiers: RDNA1/2/3 + Vega APU (gfx90c) + marketing names
    _AMD_GFX_PATTERN = re.compile(
        r"(gfx9|gfx10|gfx11|Radeon|RX \d+|680M|780M|vega|navi|RDNA)",
        re.IGNORECASE,
    )

    # HIP SDK warning lines that hashcat emits when HIP isn't installed —
    # non-fatal, OpenCL still works. Filter from progress output.
    _HIP_NOISE = re.compile(
        r"(Failed to initialize.*HIP|Please install.*HIP SDK)",
        re.IGNORECASE,
    )

    def detect_devices(self) -> list[DeviceInfo]:
        """Run hashcat -I to detect available compute devices.

        The hashcat -I output has this structure:
          OpenCL Platform ID #N
            Vendor..: ...
            Name....: <platform name>       ← IGNORE (platform header)
            ...
            Backend Device ID #NN           ← start of a real device block
              Type...........: GPU
              Name...........: AMD Radeon Graphics   ← CAPTURE this
              Driver.Version.: ...
        """
        if self._devices is not None:
            return self._devices

        devices: list[DeviceInfo] = []
        try:
            result = subprocess.run(
                [self._hashcat_path, "-I"],
                capture_output=True, text=True, timeout=15,
            )
            output = result.stdout + result.stderr

            current_id: int = 0
            current_name: str = ""
            current_type: str = ""
            current_driver: str = ""
            current_opencl_ver: str = ""
            inside_device_block: bool = False   # True only after "Backend Device ID"

            for raw_line in output.splitlines():
                stripped = raw_line.strip()

                # ── New Backend Device block ──────────────────────────────────
                dev_match = re.match(r"Backend Device ID #(\d+)", stripped)
                if dev_match:
                    # Save the previous device if we were in one
                    if inside_device_block and current_name:
                        devices.append(self._make_device(
                            current_id, current_name, current_type,
                            current_driver, current_opencl_ver,
                        ))
                    current_id = int(dev_match.group(1))
                    current_name = ""
                    current_type = ""
                    current_driver = ""
                    current_opencl_ver = ""
                    inside_device_block = True
                    continue

                # ── Platform header resets device-block context ───────────────
                if re.match(r"OpenCL Platform ID #\d+", stripped):
                    if inside_device_block and current_name:
                        devices.append(self._make_device(
                            current_id, current_name, current_type,
                            current_driver, current_opencl_ver,
                        ))
                        current_name = ""
                    inside_device_block = False
                    continue

                # ── Only parse fields when inside a real device block ─────────
                if not inside_device_block:
                    continue

                # hashcat pads field names with dots: "Name...........: value"
                # Strip leading dots from key to normalise
                field_match = re.match(r"(\w[\w\s]*?)[\.\s]*:\s*(.*)", stripped)
                if not field_match:
                    continue
                key = field_match.group(1).strip()
                val = field_match.group(2).strip().rstrip(".")

                if key == "Name":
                    current_name = val
                elif key == "Type":
                    current_type = val
                elif key in ("Driver Version", "Driver.Version"):
                    current_driver = val
                elif key in ("OpenCL Version", "OpenCL.Version"):
                    current_opencl_ver = val

            # Save the last device
            if inside_device_block and current_name:
                devices.append(self._make_device(
                    current_id, current_name, current_type,
                    current_driver, current_opencl_ver,
                ))

        except subprocess.TimeoutExpired:
            log.warn("hashcat device detection timed out")
        except FileNotFoundError:
            log.warn("hashcat binary not found during device detection")
        except Exception as e:
            log.warn(f"Device detection failed: {e}")

        self._devices = devices
        return devices

    @classmethod
    def _make_device(
        cls,
        device_id: int,
        name: str,
        device_type: str,
        driver: str,
        opencl_ver: str,
    ) -> DeviceInfo:
        """Build a DeviceInfo, correctly flagging AMD iGPUs as GPU devices.

        hashcat sometimes labels AMD iGPUs as "CPU" in the Type field because
        they share the same PCIe slot, but they are true GPU compute devices.
        We detect them by name pattern (gfx11xx = RDNA3, gfx10xx = RDNA1/2,
        Radeon, 680M, 780M, etc.).
        """
        is_gpu = (
            "GPU" in device_type.upper()
            or "cuda" in driver.lower()
            or bool(cls._AMD_GFX_PATTERN.search(name))
            or bool(cls._AMD_GFX_PATTERN.search(driver))
        )
        return DeviceInfo(
            device_id=device_id,
            device_name=name,
            device_type=device_type,
            driver_version=driver,
            is_gpu=is_gpu,
        )

    def has_gpu(self) -> bool:
        """Check if any GPU device is available."""
        return any(d.is_gpu for d in self.detect_devices())

    def print_devices(self) -> None:
        """Print detected devices to terminal."""
        devices = self.detect_devices()
        if not devices:
            log.warn("No hashcat compute devices detected")
            log.warn("AMD 680M: ensure ROCm OpenCL is installed (rocm-opencl-runtime)")
            return

        log.info("Hashcat compute devices:")
        for dev in devices:
            icon = "🔥" if dev.is_gpu else "🐢"
            gpu_label = " [GPU]" if dev.is_gpu else " [CPU]"
            print(f"   {icon} #{dev.device_id}: {dev.device_name} ({dev.device_type}){gpu_label}")

    def get_device_flags(self) -> list[str]:
        """Build hashcat device selection flags based on detected hardware.

        For AMD iGPU (680M / RDNA3): selects the GPU device explicitly via
        -D 2 (OpenCL GPU platform) so hashcat uses ROCm instead of CPU.
        For CPU-only systems: falls back to --force (allows non-GPU runs).
        Returns an empty list when a dedicated GPU is properly detected.
        """
        devices = self.detect_devices()
        gpu_devices = [d for d in devices if d.is_gpu]

        if not devices:
            # No OpenCL devices detected at all — use --force to allow CPU run
            log.debug("No OpenCL devices — running with --force (CPU mode)")
            return ["--force"]

        if gpu_devices:
            # GPU(s) detected — let hashcat use them naturally, no --force needed.
            # For AMD iGPU (680M RDNA3): explicitly use OpenCL GPU platform (-D 2)
            # so hashcat picks ROCm over the CPU OpenCL fallback.
            is_amd = any(
                self._AMD_GFX_PATTERN.search(d.device_name)
                or self._AMD_GFX_PATTERN.search(d.driver_version)
                for d in gpu_devices
            )
            # Use device IDs explicitly to target GPU only
            gpu_ids = ",".join(str(d.device_id) for d in gpu_devices)
            return ["-D", "2", "-d", gpu_ids]  # platform 2 = OpenCL GPU, device IDs

        # Only CPU devices found
        cpu_ids = ",".join(str(d.device_id) for d in devices)
        log.warn("Only CPU compute devices detected — cracking will be slow")
        return ["--force"]

    # ── Cap-to-22000 conversion ───────────────────────────────────────────

    def convert_cap_to_22000(self, capfile: str) -> Optional[str]:
        """Convert a .cap/.pcap/.pcapng to hashcat 22000 format.

        Returns the path to the .22000 file, or None if conversion fails.
        """
        if not os.path.isfile(capfile):
            log.error(f"Capture file not found: {capfile}")
            return None

        # If already in 22000 format, return as-is
        if capfile.endswith(".22000"):
            return capfile

        hash_file = re.sub(r"\.(cap|pcap|pcapng)$", ".22000", capfile)
        if hash_file == capfile:
            hash_file = capfile + ".22000"

        # Try hcxpcapngtool (newer, preferred)
        if check_tool("hcxpcapngtool"):
            result = subprocess.run(
                ["hcxpcapngtool", "-o", hash_file, capfile],
                capture_output=True, text=True, timeout=30,
            )
            if os.path.isfile(hash_file) and os.path.getsize(hash_file) > 0:
                log.success(f"Converted to hashcat format: {hash_file}")
                return hash_file
            log.debug(f"hcxpcapngtool output: {result.stdout} {result.stderr}")

        # Try hcxpcaptool (older fallback)
        if check_tool("hcxpcaptool"):
            result = subprocess.run(
                ["hcxpcaptool", "-z", hash_file, capfile],
                capture_output=True, text=True, timeout=30,
            )
            if os.path.isfile(hash_file) and os.path.getsize(hash_file) > 0:
                log.success(f"Converted to hashcat format: {hash_file}")
                return hash_file

        log.error("Cap-to-22000 conversion failed — hcxpcapngtool/hcxpcaptool required")
        return None

    # ── Potfile management ────────────────────────────────────────────────

    def check_potfile(self, hash_file: str) -> Optional[str]:
        """Check if the hash was already cracked in a previous session.

        Returns the cracked password if found, None otherwise.
        """
        try:
            result = subprocess.run(
                [self._hashcat_path, "-m", self.WPA_HASH_MODE, hash_file, "--show"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.strip().splitlines():
                if ":" in line and not line.startswith("#"):
                    parts = line.strip().split(":")
                    if len(parts) >= 2 and parts[-1]:
                        return parts[-1]
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass
        return None

    # ── Core cracking ─────────────────────────────────────────────────────

    def crack(
        self,
        hash_file: str,
        wordlist: Optional[str] = None,
        attack_mode: str = "dictionary",
        rules: Optional[list[str]] = None,
        mask: Optional[str] = None,
        timeout: Optional[int] = None,
        phase_name: str = "",
    ) -> CrackResult:
        """Run hashcat with the specified attack configuration.

        Args:
            hash_file: Path to .22000 hash file.
            wordlist: Path to wordlist (required for dictionary/rules modes).
            attack_mode: One of "dictionary", "rules", "mask".
            rules: List of rule file paths (for "rules" mode).
            mask: Mask pattern string (for "mask" mode).
            timeout: Max seconds before aborting. None = no limit.
            phase_name: Human-readable name for this attack phase.

        Returns:
            CrackResult with the outcome.
        """
        if not os.path.isfile(hash_file):
            return CrackResult(error=f"Hash file not found: {hash_file}")

        # ── Check potfile first ───────────────────────────────────────────
        cached = self.check_potfile(hash_file)
        if cached:
            log.success(f"Already cracked (from potfile): {cached}")
            return CrackResult(
                cracked=True,
                password=cached,
                hash_file=hash_file,
                attack_mode=attack_mode,
                phase=phase_name,
                skipped=True,
            )

        # ── Build command ─────────────────────────────────────────────────
        cmd = [self._hashcat_path, "-m", self.WPA_HASH_MODE]

        if attack_mode == "mask":
            cmd += ["-a", "3", hash_file]
            if mask:
                cmd.append(mask)
        else:
            cmd += ["-a", "0", hash_file]
            if wordlist:
                cmd.append(wordlist)
            else:
                return CrackResult(error="Wordlist required for dictionary/rules attack")

        # Append rule files
        if attack_mode == "rules" and rules:
            for rule_file in rules:
                if os.path.isfile(rule_file):
                    cmd += ["-r", rule_file]
                else:
                    log.warn(f"Rule file not found, skipping: {rule_file}")

        # Status + progress flags + device selection
        device_flags = self.get_device_flags()
        cmd += [
            "--status",
            "--status-timer", "5",
            "--status-json",
        ] + device_flags

        # ── Run with live progress ────────────────────────────────────────
        start_time = time.time()
        result = CrackResult(
            hash_file=hash_file,
            attack_mode=attack_mode,
            phase=phase_name,
        )

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            found_password = None

            for raw_line in proc.stdout:
                line = raw_line.strip()
                if not line:
                    continue

                # ── Filter AMD HIP SDK warnings (non-fatal, OpenCL works) ────
                if self._HIP_NOISE.search(line):
                    continue

                # ── Try parsing JSON status lines ─────────────────────────
                if line.startswith("{"):
                    found_password = self._parse_status_json(line)
                    if found_password:
                        break
                    continue

                # ── Fallback: plain-text result lines ─────────────────────
                # hashcat prints "hash:password" when cracked
                if ":" in line and not line.startswith("#") and not line.startswith("{"):
                    # Could be a cracked result — but filter out status noise
                    if "Session" not in line and "Status" not in line and "Speed" not in line:
                        parts = line.split(":")
                        # WPA 22000 format has many colon-separated fields;
                        # the password is the very last segment
                        candidate = parts[-1].strip()
                        if candidate and len(candidate) >= 8:
                            found_password = candidate
                            break

                # ── Check timeout ─────────────────────────────────────────
                if timeout and (time.time() - start_time) > timeout:
                    log.warn(f"Hashcat timeout reached ({timeout}s)")
                    proc.terminate()
                    break

            # Wait for process to finish
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

            elapsed = time.time() - start_time
            result.time_elapsed = elapsed

            # ── If we didn't catch it live, check potfile ─────────────────
            if not found_password:
                found_password = self.check_potfile(hash_file)

            if found_password:
                result.cracked = True
                result.password = found_password
            else:
                # Check exit code: 1 = exhausted, 0 = cracked, -1/other = error
                if proc.returncode == 1:
                    result.exhausted = True
                elif proc.returncode and proc.returncode != 0:
                    result.error = f"hashcat exited with code {proc.returncode}"

        except KeyboardInterrupt:
            log.warn("Hashcat interrupted by user (Ctrl+C)")
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
            result.error = "Interrupted by user"

        except FileNotFoundError:
            result.error = f"hashcat binary not found: {self._hashcat_path}"
            log.error(result.error)

        except Exception as e:
            result.error = str(e)
            log.error(f"Hashcat error: {e}")

        return result

    def _parse_status_json(self, json_line: str) -> Optional[str]:
        """Parse a hashcat JSON status line, print progress, return password if cracked."""
        try:
            data = json.loads(json_line)
        except json.JSONDecodeError:
            return None

        status = data.get("status", -1)

        # Status 5 = cracked
        if status == 5:
            # Try to extract from "recovered_hashes" or directly
            return None  # Password will be in potfile — let caller handle

        # Print live progress
        progress = data.get("progress", [0, 0])
        if len(progress) >= 2 and progress[1] > 0:
            pct = (progress[0] / progress[1]) * 100
        else:
            pct = 0.0

        # Speed from all devices combined
        speed_devices = data.get("devices", [])
        total_speed = sum(d.get("speed", 0) for d in speed_devices)
        speed_str = self._format_speed(total_speed)

        # ETA
        eta = data.get("estimated_stop", "")
        time_started = data.get("time_start", 0)
        if eta and time_started:
            try:
                remaining = int(eta) - int(time.time())
                eta_str = self._format_duration(remaining) if remaining > 0 else "done"
            except (ValueError, TypeError):
                eta_str = "?"
        else:
            eta_str = "?"

        # Temperature (if available)
        temp_str = ""
        for dev in speed_devices:
            temp = dev.get("temp", 0)
            if temp > 0:
                temp_str = f" | {temp}°C"
                break

        print(
            f"\r   [{pct:5.1f}%] {speed_str} | ETA: {eta_str}{temp_str}   ",
            end="", flush=True,
        )

        return None

    @staticmethod
    def _format_speed(hashes_per_sec: float) -> str:
        """Format hash speed to human-readable string."""
        if hashes_per_sec >= 1_000_000_000:
            return f"{hashes_per_sec / 1_000_000_000:.1f} GH/s"
        if hashes_per_sec >= 1_000_000:
            return f"{hashes_per_sec / 1_000_000:.1f} MH/s"
        if hashes_per_sec >= 1_000:
            return f"{hashes_per_sec / 1_000:.1f} kH/s"
        return f"{hashes_per_sec:.0f} H/s"

    @staticmethod
    def _format_duration(seconds: int) -> str:
        """Format seconds to human-readable duration."""
        if seconds < 0:
            return "?"
        if seconds < 60:
            return f"{seconds}s"
        if seconds < 3600:
            return f"{seconds // 60}m {seconds % 60}s"
        hours = seconds // 3600
        mins = (seconds % 3600) // 60
        return f"{hours}h {mins}m"

    # ── Rule file helpers ─────────────────────────────────────────────────

    def get_available_rules(self) -> list[str]:
        """List available rule files from the bundled hashcat rules directory."""
        rules: list[str] = []
        if os.path.isdir(self._rules_dir):
            for f in sorted(os.listdir(self._rules_dir)):
                if f.endswith(".rule"):
                    rules.append(os.path.join(self._rules_dir, f))
        return rules

    def get_rule_path(self, rule_name: str) -> Optional[str]:
        """Resolve a rule name to its full path.

        Accepts both bare names ('best66') and full filenames ('best66.rule').
        """
        if not rule_name.endswith(".rule"):
            rule_name += ".rule"

        # Check bundled rules
        bundled = os.path.join(self._rules_dir, rule_name)
        if os.path.isfile(bundled):
            return bundled

        # Check system hashcat rules
        for system_dir in ["/usr/share/hashcat/rules", "/usr/local/share/hashcat/rules"]:
            system_path = os.path.join(system_dir, rule_name)
            if os.path.isfile(system_path):
                return system_path

        # Check if it's already an absolute path
        if os.path.isfile(rule_name):
            return rule_name

        return None

    # ── Mask helpers ──────────────────────────────────────────────────────

    def get_available_masks(self) -> list[str]:
        """List available mask files from the bundled hashcat masks directory."""
        masks: list[str] = []
        if os.path.isdir(self._masks_dir):
            for f in sorted(os.listdir(self._masks_dir)):
                if f.endswith(".hcmask"):
                    masks.append(os.path.join(self._masks_dir, f))
        return masks
