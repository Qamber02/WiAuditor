"""
core/scanner.py - Network scanning via airodump-ng
Parses output and presents targets to user
"""

import subprocess
import threading
import time
import os
import csv
import tempfile
import re
from utils.logger import Logger

log = Logger()


class Scanner:
    def __init__(self, interface, timeout=60, channel=None):
        self.interface = interface
        self.timeout = timeout
        self.channel = channel
        self.targets = []
        self._proc = None
        self._tmpdir = tempfile.mkdtemp()
        self._capfile = os.path.join(self._tmpdir, "scan")

    def scan(self):
        """Run airodump-ng and collect targets"""
        cmd = [
            "airodump-ng",
            "--write", self._capfile,
            "--output-format", "csv",
            "--write-interval", "2",
        ]

        if self.channel:
            cmd += ["--channel", str(self.channel)]

        cmd.append(self.interface)

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # Progress display
            start = time.time()
            while time.time() - start < self.timeout:
                elapsed = int(time.time() - start)
                targets = self._parse_csv()
                count = len(targets)
                print(f"\r[+] Scanning... {elapsed}s elapsed | {count} network(s) found", end="", flush=True)
                time.sleep(1)

            print()  # newline after progress
            self._proc.terminate()
            self._proc.wait()

        except FileNotFoundError:
            log.error("airodump-ng not found. Install aircrack-ng suite.")
            return []
        except KeyboardInterrupt:
            print()
            log.warn("Scan interrupted by user")
            if self._proc:
                self._proc.terminate()

        self.targets = self._parse_csv()
        return self.targets

    def _parse_csv(self):
        """Parse airodump-ng CSV output"""
        csv_file = self._capfile + "-01.csv"
        targets = []

        if not os.path.exists(csv_file):
            return targets

        try:
            with open(csv_file, "r", errors="ignore") as f:
                content = f.read()

            # Split into AP section and client section
            sections = content.split("\r\n\r\n")
            if not sections:
                return targets

            ap_section = sections[0]
            lines = ap_section.strip().splitlines()

            # Skip header line
            for line in lines[2:]:
                line = line.strip()
                if not line:
                    continue

                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 14:
                    continue

                bssid = parts[0].strip()
                if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', bssid):
                    continue

                target = {
                    "bssid": bssid,
                    "channel": parts[3].strip(),
                    "speed": parts[4].strip(),
                    "enc": parts[5].strip(),
                    "cipher": parts[6].strip(),
                    "auth": parts[7].strip(),
                    "power": parts[8].strip(),
                    "beacons": parts[9].strip(),
                    "iv": parts[10].strip(),
                    "essid": parts[13].strip() if len(parts) > 13 else "<hidden>",
                    "clients": [],
                    "wps": False,
                    "capfile": self._capfile + "-01.cap"
                }

                # Parse clients if available
                if len(sections) > 1:
                    target["clients"] = self._parse_clients(sections[1], bssid)

                # Detect encryption type for attack routing
                target["attack_type"] = self._detect_attack_type(target)

                targets.append(target)

        except Exception as e:
            pass  # CSV might be mid-write

        return targets

    def _parse_clients(self, client_section, bssid):
        """Parse client MACs associated with a BSSID"""
        clients = []
        lines = client_section.strip().splitlines()

        for line in lines[2:]:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 2:
                continue
            if parts[1].strip() == bssid:
                clients.append(parts[0].strip())

        return clients

    def _detect_attack_type(self, target):
        """Determine best attack based on encryption"""
        enc = target.get("enc", "").upper()
        auth = target.get("auth", "").upper()

        if "WPA3" in enc or "SAE" in auth:
            return "wpa3"
        elif "WPA2" in enc or "WPA" in enc:
            return "wpa2"
        elif "WEP" in enc:
            return "wep"
        elif "OPN" in enc or enc == "":
            return "open"
        else:
            return "wpa2"

    def print_targets(self, targets):
        """Print targets in a clean table"""
        if not targets:
            log.error("No targets found")
            return

        print(f"\n{'─'*90}")
        print(f"  {'#':<4} {'BSSID':<19} {'CH':<4} {'PWR':<6} {'ENC':<8} "
              f"{'CIPHER':<8} {'AUTH':<6} {'CLIENTS':<8} ESSID")
        print(f"{'─'*90}")

        for i, t in enumerate(targets, 1):
            clients = len(t.get("clients", []))
            enc_color = self._enc_color(t["attack_type"])
            print(
                f"  {i:<4} {t['bssid']:<19} {t['channel']:<4} {t['power']:<6} "
                f"{enc_color}{t['enc']:<8}\033[0m {t['cipher']:<8} {t['auth']:<6} "
                f"{clients:<8} {t['essid']}"
            )

        print(f"{'─'*90}\n")

    def _enc_color(self, attack_type):
        """Color code by encryption type"""
        colors = {
            "wpa3": "\033[92m",   # green
            "wpa2": "\033[93m",   # yellow
            "wep":  "\033[91m",   # red
            "open": "\033[91m",   # red
        }
        return colors.get(attack_type, "\033[0m")

    def select_target(self, targets):
        """Interactive target selection"""
        if len(targets) == 1:
            log.info(f"Auto-selected: {targets[0]['essid']} ({targets[0]['bssid']})")
            return targets[0]

        while True:
            try:
                choice = input("[?] Select target (number, or 'q' to quit): ").strip()
                if choice.lower() == "q":
                    return None
                idx = int(choice) - 1
                if 0 <= idx < len(targets):
                    return targets[idx]
                print("[!] Invalid choice")
            except ValueError:
                print("[!] Enter a number")
            except KeyboardInterrupt:
                return None

    def cleanup(self):
        """Remove temp files"""
        import shutil
        try:
            shutil.rmtree(self._tmpdir)
        except Exception:
            pass
