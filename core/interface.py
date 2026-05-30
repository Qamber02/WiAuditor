"""
core/interface.py - Wireless interface management
Handles monitor mode, interface detection, conflicting processes
"""

import subprocess
import re
import os
from utils.logger import Logger

log = Logger()

CONFLICTING_PROCESSES = [
    "NetworkManager", "wpa_supplicant", "avahi-daemon",
    "dhclient", "dhcpcd", "hostapd"
]

class InterfaceManager:
    _monitor_interfaces = []

    def __init__(self):
        pass

    def kill_conflicting(self):
        """Kill processes that interfere with monitor mode"""
        log.info("Checking for conflicting processes...")
        killed = []

        for proc in CONFLICTING_PROCESSES:
            result = subprocess.run(
                ["pgrep", "-x", proc],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                pids = result.stdout.strip().split("\n")
                for pid in pids:
                    try:
                        subprocess.run(["kill", "-9", pid], capture_output=True)
                        killed.append(f"{proc} (PID {pid})")
                    except Exception:
                        pass

        if killed:
            log.warn(f"Killed: {', '.join(killed)}")
        else:
            log.info("No conflicting processes found")

    def get_wireless_interfaces(self):
        """Get list of wireless interfaces with details"""
        interfaces = []

        result = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True
        )

        if result.returncode != 0:
            return interfaces

        current_iface = None
        current_phy = None

        for line in result.stdout.splitlines():
            phy_match = re.match(r'^phy#(\d+)', line)
            iface_match = re.match(r'\s+Interface\s+(\S+)', line)
            type_match = re.match(r'\s+type\s+(\S+)', line)
            addr_match = re.match(r'\s+addr\s+(\S+)', line)

            if phy_match:
                current_phy = f"phy{phy_match.group(1)}"
            elif iface_match:
                current_iface = {
                    "name": iface_match.group(1),
                    "phy": current_phy,
                    "type": "managed",
                    "addr": "",
                    "driver": self._get_driver(iface_match.group(1)),
                    "chipset": self._get_chipset(current_phy)
                }
                interfaces.append(current_iface)
            elif type_match and current_iface:
                current_iface["type"] = type_match.group(1)
            elif addr_match and current_iface:
                current_iface["addr"] = addr_match.group(1)

        return interfaces

    def _get_driver(self, iface):
        """Get driver name for interface"""
        try:
            path = f"/sys/class/net/{iface}/device/driver"
            driver = os.path.basename(os.readlink(path))
            return driver
        except Exception:
            return "unknown"

    def _get_chipset(self, phy):
        """Get chipset info from phy"""
        try:
            result = subprocess.run(
                ["iw", "phy", phy, "info"],
                capture_output=True, text=True
            )
            for line in result.stdout.splitlines():
                if "Wiphy" in line or "Band" in line:
                    continue
                if line.strip():
                    pass
            # Try lshw or /sys approach
            return self._get_chipset_from_sys(phy)
        except Exception:
            return "unknown"

    def _get_chipset_from_sys(self, phy):
        """Read chipset from sysfs"""
        try:
            phy_num = phy.replace("phy", "")
            vendor_path = f"/sys/class/ieee80211/{phy}/device/vendor"
            device_path = f"/sys/class/ieee80211/{phy}/device/device"

            with open(vendor_path) as f:
                vendor = f.read().strip()
            with open(device_path) as f:
                device = f.read().strip()

            return f"{vendor}:{device}"
        except Exception:
            return "unknown"

    def select_interface(self):
        """Interactive interface selection"""
        interfaces = self.get_wireless_interfaces()

        if not interfaces:
            log.error("No wireless interfaces found")
            return None

        if len(interfaces) == 1:
            log.info(f"Auto-selected interface: {interfaces[0]['name']}")
            return interfaces[0]["name"]

        print("\n[+] Available wireless interfaces:\n")
        print(f"  {'#':<4} {'Interface':<12} {'PHY':<8} {'Driver':<20} {'Type':<12} {'MAC'}")
        print(f"  {'-'*4} {'-'*12} {'-'*8} {'-'*20} {'-'*12} {'-'*17}")

        for i, iface in enumerate(interfaces, 1):
            print(f"  {i:<4} {iface['name']:<12} {iface['phy']:<8} "
                  f"{iface['driver']:<20} {iface['type']:<12} {iface['addr']}")

        print()
        while True:
            try:
                choice = input("[?] Select interface (number): ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(interfaces):
                    return interfaces[idx]["name"]
                print("[!] Invalid choice")
            except (ValueError, KeyboardInterrupt):
                return None

    def enable_monitor(self, interface):
        """Enable monitor mode on interface"""
        log.info(f"Enabling monitor mode on {interface}...")

        # Try airmon-ng first
        result = subprocess.run(
            ["airmon-ng", "start", interface],
            capture_output=True, text=True
        )

        if result.returncode == 0:
            # airmon-ng might rename interface to wlan0mon etc
            mon_iface = self._find_monitor_interface(interface)
            if mon_iface:
                InterfaceManager._monitor_interfaces.append(mon_iface)
                return mon_iface

        # Fallback: iw method
        log.warn("airmon-ng failed, trying iw method...")
        try:
            subprocess.run(["ip", "link", "set", interface, "down"],
                          capture_output=True, check=True)
            subprocess.run(["iw", "dev", interface, "set", "type", "monitor"],
                          capture_output=True, check=True)
            subprocess.run(["ip", "link", "set", interface, "up"],
                          capture_output=True, check=True)

            # Verify
            result = subprocess.run(
                ["iw", "dev", interface, "info"],
                capture_output=True, text=True
            )
            if "type monitor" in result.stdout:
                InterfaceManager._monitor_interfaces.append(interface)
                return interface
        except subprocess.CalledProcessError as e:
            log.error(f"iw method failed: {e}")

        return None

    def _find_monitor_interface(self, original):
        """Find monitor interface after airmon-ng potentially renames it"""
        # Check common names
        candidates = [
            f"{original}mon",
            original,
            "wlan0mon", "wlan1mon", "mon0"
        ]

        for name in candidates:
            result = subprocess.run(
                ["iw", "dev", name, "info"],
                capture_output=True, text=True
            )
            if result.returncode == 0 and "type monitor" in result.stdout:
                return name

        return None

    def disable_monitor(self, interface):
        """Restore interface to managed mode"""
        log.info(f"Restoring {interface} to managed mode...")

        # Try airmon-ng stop
        result = subprocess.run(
            ["airmon-ng", "stop", interface],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            # Fallback: iw method
            try:
                subprocess.run(["ip", "link", "set", interface, "down"],
                              capture_output=True)
                subprocess.run(["iw", "dev", interface, "set", "type", "managed"],
                              capture_output=True)
                subprocess.run(["ip", "link", "set", interface, "up"],
                              capture_output=True)
            except Exception as e:
                log.error(f"Failed to restore interface: {e}")

    @classmethod
    def restore_all(cls):
        """Restore all monitor interfaces"""
        for iface in cls._monitor_interfaces:
            try:
                subprocess.run(["ip", "link", "set", iface, "down"],
                              capture_output=True)
                subprocess.run(["iw", "dev", iface, "set", "type", "managed"],
                              capture_output=True)
                subprocess.run(["ip", "link", "set", iface, "up"],
                              capture_output=True)
                log.info(f"Restored {iface} to managed mode")
            except Exception:
                pass

        # Restart NetworkManager
        subprocess.run(["systemctl", "start", "NetworkManager"],
                      capture_output=True)
        cls._monitor_interfaces.clear()
