#!/usr/bin/env python3
"""
wauditor - Modern Wireless Auditing Tool
For educational and authorized testing purposes only.
"""

import os
import sys
import argparse
import signal

# Check root
if os.geteuid() != 0:
    print("[!] wauditor must be run as root (sudo python main.py)")
    sys.exit(1)

from core.interface import InterfaceManager
from core.scanner import Scanner
from core.attack import AttackOrchestrator
from utils.logger import Logger
from utils.banner import print_banner

log = Logger()

def signal_handler(sig, frame):
    log.warn("\n[!] Caught Ctrl+C — cleaning up...")
    InterfaceManager.restore_all()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


def parse_args():
    parser = argparse.ArgumentParser(
        description="wauditor - Modern Wireless Auditor (Educational Use Only)"
    )
    parser.add_argument("-i", "--interface", help="Wireless interface to use")
    parser.add_argument("--kill", action="store_true", help="Kill conflicting processes")
    parser.add_argument("--scan-only", action="store_true", help="Scan and list networks, no attacks")
    parser.add_argument("--attack", choices=["wpa2", "pmkid", "wpa3", "all"], default="all",
                        help="Attack type to use")
    parser.add_argument("--bssid", help="Target specific BSSID")
    parser.add_argument("--essid", help="Target specific ESSID")
    parser.add_argument("--wordlist", help="Path to wordlist for cracking")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Scan timeout in seconds (default: 60)")
    parser.add_argument("--deauth-count", type=int, default=5,
                        help="Number of deauth packets to send (default: 5)")
    parser.add_argument("--channel", type=int, help="Lock to specific channel")
    parser.add_argument("--output", default="./captures", help="Output directory for captures")
    return parser.parse_args()


def main():
    print_banner()
    args = parse_args()

    # Setup output dir
    os.makedirs(args.output, exist_ok=True)

    # Interface setup
    iface_mgr = InterfaceManager()

    if args.kill:
        iface_mgr.kill_conflicting()

    if args.interface:
        interface = args.interface
        log.info(f"Using interface: {interface}")
    else:
        interface = iface_mgr.select_interface()

    if not interface:
        log.error("No wireless interface found. Plug in a compatible adapter.")
        sys.exit(1)

    # Enable monitor mode
    mon_iface = iface_mgr.enable_monitor(interface)
    if not mon_iface:
        log.error("Failed to enable monitor mode.")
        sys.exit(1)

    log.success(f"Monitor mode active on: {mon_iface}")

    # Scan
    scanner = Scanner(mon_iface, timeout=args.timeout, channel=args.channel)
    log.info(f"Scanning for networks ({args.timeout}s)... Press Ctrl+C to stop early")
    targets = scanner.scan()

    if not targets:
        log.error("No networks found.")
        iface_mgr.restore_all()
        sys.exit(0)

    if args.scan_only:
        scanner.print_targets(targets)
        iface_mgr.restore_all()
        sys.exit(0)

    # Filter targets
    if args.bssid:
        targets = [t for t in targets if t["bssid"].lower() == args.bssid.lower()]
    if args.essid:
        targets = [t for t in targets if t["essid"].lower() == args.essid.lower()]

    if not targets:
        log.error("No targets match your filters.")
        iface_mgr.restore_all()
        sys.exit(0)

    scanner.print_targets(targets)

    # Select target
    target = scanner.select_target(targets)
    if not target:
        iface_mgr.restore_all()
        sys.exit(0)

    # Attack
    orchestrator = AttackOrchestrator(
        interface=mon_iface,
        target=target,
        attack_type=args.attack,
        wordlist=args.wordlist,
        output_dir=args.output,
        deauth_count=args.deauth_count
    )
    orchestrator.run()

    # Restore
    iface_mgr.restore_all()
    log.success("Done. Interface restored.")


if __name__ == "__main__":
    main()
