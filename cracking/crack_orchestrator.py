"""
cracking/crack_orchestrator.py - Escalating cracking strategy

Coordinates cracking attempts across multiple phases:
  Phase 1: Dictionary attack (wordlist only)           — fast, common passwords
  Phase 2: Dictionary + rules (best66.rule)            — 66x candidates, still fast
  Phase 3: Dictionary + rules (rockyou-30000.rule)     — heavy but thorough
  Phase 4: Mask attack (8-digit numeric)               — common Wi-Fi defaults
  Phase 5: Mask attack (extended patterns)             — phone numbers, dates

Falls back to aircrack-ng for WPA2 .cap files when hashcat is unavailable.
"""

import os
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

from utils.logger import Logger
from utils.tools import check_tool

log = Logger()


@dataclass
class CrackConfig:
    """Configuration for the crack orchestrator."""
    cracker: str = "auto"            # "hashcat", "aircrack", "auto"
    wordlist: Optional[str] = None
    custom_rules: Optional[list[str]] = None   # user-specified rule files
    custom_mask: Optional[str] = None           # user-specified mask pattern
    no_escalate: bool = False        # disable auto-escalation
    timeout: Optional[int] = None    # per-phase timeout in seconds
    bssid: str = ""                  # target BSSID (for aircrack-ng -b)


# ── Common Wi-Fi mask patterns ───────────────────────────────────────────────

WIFI_MASKS = [
    # Phase 4: 8-digit numeric (very common default Wi-Fi passwords)
    ("8-digit numeric", "?d?d?d?d?d?d?d?d"),
    # Phase 5: Extended patterns
    ("10-digit numeric (phone)", "?d?d?d?d?d?d?d?d?d?d"),
    ("8-char lowercase", "?l?l?l?l?l?l?l?l"),
]


class CrackOrchestrator:
    """Orchestrates cracking attempts with escalating attack phases.

    Tries each phase in order, stopping as soon as the password is found.
    Supports both hashcat (GPU-accelerated) and aircrack-ng (CPU fallback).
    """

    def __init__(self, config: CrackConfig):
        self.config = config
        self._engine = None

    def _get_engine(self):
        """Lazy-init the hashcat engine."""
        if self._engine is None:
            try:
                from cracking.hashcat_engine import HashcatEngine
                self._engine = HashcatEngine()
            except FileNotFoundError:
                self._engine = None
        return self._engine

    def _should_use_hashcat(self) -> bool:
        """Determine whether to use hashcat based on config and availability."""
        if self.config.cracker == "aircrack":
            return False
        if self.config.cracker == "hashcat":
            engine = self._get_engine()
            if engine is None:
                log.error("hashcat requested but not available — falling back to aircrack-ng")
                return False
            return True
        # auto mode: use hashcat if available
        engine = self._get_engine()
        return engine is not None

    def crack(self, capfile: str) -> Optional[str]:
        """Run the cracking pipeline on a capture/hash file.

        Args:
            capfile: Path to .cap, .pcapng, or .22000 hash file.

        Returns:
            The cracked password string, or None if not found.
        """
        if not os.path.isfile(capfile):
            log.error(f"Capture file not found: {capfile}")
            return None

        use_hashcat = self._should_use_hashcat()

        if use_hashcat:
            return self._crack_with_hashcat(capfile)
        else:
            return self._crack_with_aircrack(capfile)

    # ── Hashcat pipeline ──────────────────────────────────────────────────

    def _crack_with_hashcat(self, capfile: str) -> Optional[str]:
        """Run the full hashcat escalating attack pipeline."""
        engine = self._get_engine()
        if engine is None:
            log.error("Hashcat engine unavailable")
            return None

        # ── Print device info ─────────────────────────────────────────────
        engine.print_devices()

        # ── Convert to .22000 if needed ───────────────────────────────────
        hash_file = capfile
        if not capfile.endswith(".22000"):
            log.info("Converting capture to hashcat format (.22000)...")
            converted = engine.convert_cap_to_22000(capfile)
            if converted:
                hash_file = converted
            else:
                log.warn("Conversion failed — falling back to aircrack-ng")
                return self._crack_with_aircrack(capfile)

        # ── Check potfile for already-cracked hash ────────────────────────
        cached = engine.check_potfile(hash_file)
        if cached:
            log.success(f"Already cracked (previous session): {cached}")
            return cached

        # ── Build attack phases ───────────────────────────────────────────
        phases = self._build_phases(engine)

        log.info(f"Starting hashcat cracking pipeline ({len(phases)} phase(s))...")
        print()

        for i, (phase_name, phase_fn) in enumerate(phases, 1):
            log.info(f"Phase {i}/{len(phases)}: {phase_name}")

            result = phase_fn(engine, hash_file)

            if result.cracked:
                print()
                return result.password
            elif result.error:
                log.warn(f"Phase {i} error: {result.error}")
            elif result.exhausted:
                log.info(f"Phase {i} exhausted — no match")
            elif result.skipped:
                log.info(f"Phase {i} skipped (already attempted)")

            print()  # visual separator between phases

        log.warn("All hashcat phases exhausted — password not found")
        return None

    def _build_phases(self, engine) -> list[tuple[str, callable]]:
        """Build the ordered list of attack phases."""
        phases: list[tuple[str, callable]] = []

        wordlist = self.config.wordlist

        # ── User-specified custom mask overrides everything ───────────────
        if self.config.custom_mask:
            phases.append((
                f"Custom mask: {self.config.custom_mask}",
                lambda eng, hf, m=self.config.custom_mask: eng.crack(
                    hf, attack_mode="mask", mask=m,
                    timeout=self.config.timeout,
                    phase_name=f"Mask: {m}",
                ),
            ))
            if self.config.no_escalate:
                return phases

        # ── User-specified custom rules override default escalation ───────
        if self.config.custom_rules and wordlist:
            resolved_rules = [
                engine.get_rule_path(r) or r for r in self.config.custom_rules
            ]
            phases.append((
                f"Dictionary + custom rules ({', '.join(self.config.custom_rules)})",
                lambda eng, hf, rl=resolved_rules: eng.crack(
                    hf, wordlist=wordlist, attack_mode="rules", rules=rl,
                    timeout=self.config.timeout,
                    phase_name="Custom rules",
                ),
            ))
            if self.config.no_escalate:
                return phases

        # ── Phase 1: Straight dictionary ──────────────────────────────────
        if wordlist:
            phases.append((
                f"Dictionary ({os.path.basename(wordlist)})",
                lambda eng, hf: eng.crack(
                    hf, wordlist=wordlist, attack_mode="dictionary",
                    timeout=self.config.timeout,
                    phase_name="Dictionary",
                ),
            ))

        if self.config.no_escalate:
            return phases

        # ── Phase 2: Dictionary + best66.rule ─────────────────────────────
        if wordlist:
            best66 = engine.get_rule_path("best66")
            if best66:
                phases.append((
                    "Dictionary + best66.rule (66x multiplier)",
                    lambda eng, hf, rf=best66: eng.crack(
                        hf, wordlist=wordlist, attack_mode="rules",
                        rules=[rf], timeout=self.config.timeout,
                        phase_name="Dictionary + best66",
                    ),
                ))

        # ── Phase 3: Dictionary + rockyou-30000.rule ──────────────────────
        if wordlist:
            rk30k = engine.get_rule_path("rockyou-30000")
            if rk30k:
                phases.append((
                    "Dictionary + rockyou-30000.rule (30,000x multiplier — heavy)",
                    lambda eng, hf, rf=rk30k: eng.crack(
                        hf, wordlist=wordlist, attack_mode="rules",
                        rules=[rf], timeout=self.config.timeout,
                        phase_name="Dictionary + rockyou-30000",
                    ),
                ))

        # ── Phase 4+: Mask attacks ────────────────────────────────────────
        for mask_name, mask_pattern in WIFI_MASKS:
            phases.append((
                f"Mask: {mask_name} ({mask_pattern})",
                lambda eng, hf, m=mask_pattern, mn=mask_name: eng.crack(
                    hf, attack_mode="mask", mask=m,
                    timeout=self.config.timeout,
                    phase_name=f"Mask: {mn}",
                ),
            ))

        return phases

    # ── Aircrack-ng fallback ──────────────────────────────────────────────

    def _crack_with_aircrack(self, capfile: str) -> Optional[str]:
        """Fall back to CPU-based aircrack-ng for .cap files."""
        if not self.config.wordlist:
            log.warn("No wordlist provided — cannot crack with aircrack-ng")
            return None

        if not check_tool("aircrack-ng"):
            log.error("aircrack-ng not found")
            return None

        if not os.path.isfile(self.config.wordlist):
            log.error(f"Wordlist not found: {self.config.wordlist}")
            return None

        # .22000 files can't be cracked by aircrack-ng
        if capfile.endswith(".22000"):
            log.error("aircrack-ng cannot crack .22000 files — hashcat required")
            return None

        # ── Pre-validate handshake exists ─────────────────────────────────
        pre = subprocess.run(
            ["aircrack-ng", capfile],
            capture_output=True, text=True, timeout=10,
        )
        pre_out = pre.stdout + pre.stderr
        if "0 handshake" in pre_out and "1 handshake" not in pre_out:
            log.error("No valid WPA handshake found in capture file.")
            log.warn("  Handshake requires a connected client to be deauthed and reconnect.")
            return None

        wl_lines = sum(1 for _ in open(self.config.wordlist, "rb"))
        log.info(f"Cracking with aircrack-ng ({wl_lines:,} passwords)...")
        log.info("Press Ctrl+C to stop early.")

        cmd = [
            "aircrack-ng", capfile,
            "-w", self.config.wordlist,
            "-q",
        ]

        if self.config.bssid:
            cmd += ["-b", self.config.bssid]

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        found = None
        try:
            for raw in proc.stdout:
                line = raw.rstrip()
                if not line:
                    continue

                if "KEY FOUND" in line:
                    match = re.search(r'KEY FOUND! \[ (.+?) \]', line)
                    if match:
                        found = match.group(1)
                    break

                elif "Passphrase not in dictionary" in line or "Failed. Next" in line:
                    print()
                    log.warn("Password not in wordlist")
                    break

                elif "No valid WPA handshakes found" in line:
                    print()
                    log.error("No valid WPA handshake in capture")
                    break

                elif "Packets contained no EAPOL data" in line:
                    print()
                    log.error("Capture contains no EAPOL frames")
                    break

                elif re.search(r'\d+/\d+|keys tested|\d+\.\d+\s*k/s', line, re.I):
                    print(f"\r   {line.strip():<70}", end="", flush=True)

        except KeyboardInterrupt:
            proc.terminate()
            print()
            log.warn("Cracking stopped by user")
        finally:
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
            print()

        return found
