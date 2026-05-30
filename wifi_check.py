#!/usr/bin/env python3
"""
wifi_check.py - Quick WiFi diagnostic
Checks if your card can actually see networks in monitor mode
"""

import subprocess
import os
import sys
import time

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 1
    except FileNotFoundError:
        return "", f"{cmd[0]} not found", 1

def header(title):
    print(f"\n{CYAN}{BOLD}{'─'*50}")
    print(f"  {title}")
    print(f"{'─'*50}{RESET}")

def ok(msg):   print(f"  {GREEN}✓{RESET} {msg}")
def bad(msg):  print(f"  {RED}✗{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}!{RESET} {msg}")
def info(msg): print(f"  {CYAN}>{RESET} {msg}")


# ── 1. Root check ──────────────────────────────────────────
header("1. Root / Privileges")
if os.geteuid() == 0:
    ok("Running as root")
else:
    bad("NOT root — re-run with sudo")
    sys.exit(1)


# ── 2. Interface detection ─────────────────────────────────
header("2. Wireless Interfaces")
out, _, _ = run(["iw", "dev"])
if not out:
    bad("iw dev returned nothing — no interfaces?")
else:
    print(out)

out2, _, _ = run(["ip", "link"])
for line in out2.splitlines():
    if "wl" in line:
        info(line.strip())


# ── 3. Interface mode ──────────────────────────────────────
header("3. Interface Mode Check")
interfaces = []
for line in out.splitlines():
    import re
    m = re.match(r'\s+Interface\s+(\S+)', line)
    if m:
        interfaces.append(m.group(1))

if not interfaces:
    bad("No wireless interfaces found at all")
    sys.exit(1)

for iface in interfaces:
    out3, _, _ = run(["iw", "dev", iface, "info"])
    if "type monitor" in out3:
        ok(f"{iface} is in MONITOR mode")
    elif "type managed" in out3:
        warn(f"{iface} is in MANAGED mode (need monitor for scanning)")
    else:
        info(f"{iface} info:\n{out3}")


# ── 4. Try to put in monitor mode ─────────────────────────
header("4. Monitor Mode Toggle Test")
iface = interfaces[0]
info(f"Testing on: {iface}")

subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
r = subprocess.run(["iw", "dev", iface, "set", "type", "monitor"], capture_output=True, text=True)
subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)

if r.returncode == 0:
    ok("Monitor mode set successfully via iw")
else:
    bad(f"iw monitor mode failed: {r.stderr.strip()}")
    warn("Driver may not support monitor mode")

# Verify
out4, _, _ = run(["iw", "dev", iface, "info"])
if "type monitor" in out4:
    ok("Confirmed: interface is in monitor mode")
else:
    bad("Interface did NOT enter monitor mode")
    for line in out4.splitlines():
        if "type" in line:
            info(f"Current type: {line.strip()}")


# ── 5. Channel scan test ───────────────────────────────────
header("5. Channel Scan (iw scan)")
info("Trying iw scan (managed mode needed for this)...")

# Switch back to managed for iw scan
subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
subprocess.run(["iw", "dev", iface, "set", "type", "managed"], capture_output=True)
subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
time.sleep(1)

out5, err5, rc5 = run(["iw", "dev", iface, "scan"], timeout=15)
if rc5 == 0 and out5:
    networks = [l for l in out5.splitlines() if "SSID:" in l]
    ok(f"iw scan found {len(networks)} network(s):")
    for n in networks[:10]:
        info(n.strip())
    if len(networks) > 10:
        info(f"  ... and {len(networks)-10} more")
elif "Network is down" in err5:
    bad("Interface went down during scan — NetworkManager interference?")
    warn("Try: sudo systemctl stop NetworkManager")
elif "Device or resource busy" in err5:
    warn("Device busy — another process using the interface")
else:
    warn(f"iw scan returned nothing or failed: {err5[:100]}")


# ── 6. Airodump-ng quick test ─────────────────────────────
header("6. Airodump-ng Quick Test (5 seconds)")

# Back to monitor
subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
subprocess.run(["iw", "dev", iface, "set", "type", "monitor"], capture_output=True)
subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
time.sleep(1)

import tempfile, shutil
tmpdir = tempfile.mkdtemp()
capfile = os.path.join(tmpdir, "test")

proc = subprocess.Popen(
    ["airodump-ng", "--write", capfile, "--output-format", "csv",
     "--write-interval", "1", iface],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)

info("Running airodump-ng for 5 seconds...")
for i in range(5):
    print(f"\r  > Capturing... {i+1}s", end="", flush=True)
    time.sleep(1)
print()

proc.terminate()
proc.wait()

csvfile = capfile + "-01.csv"
if os.path.exists(csvfile):
    with open(csvfile, errors="ignore") as f:
        content = f.read()
    import re
    bssids = re.findall(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', content)
    unique = list(set(bssids))
    if unique:
        ok(f"airodump-ng captured {len(unique)} BSSID(s) in 5s:")
        for b in unique[:5]:
            info(b)
    else:
        bad("airodump-ng captured 0 networks in 5 seconds")
        warn("Possible causes:")
        warn("  - RTL8821CE driver issue with monitor mode")
        warn("  - NetworkManager still running (sudo systemctl stop NetworkManager)")
        warn("  - Need external USB WiFi adapter for reliable monitor mode")
else:
    bad("airodump-ng produced no output file")

shutil.rmtree(tmpdir, ignore_errors=True)


# ── 7. Driver info ────────────────────────────────────────
header("7. Driver & Kernel Module Info")
out6, _, _ = run(["lsmod"])
for line in out6.splitlines():
    if "rtw" in line.lower() or "88" in line.lower():
        info(f"Module: {line}")

out7, _, _ = run(["dmesg"])
rtw_lines = [l for l in out7.splitlines() if "rtw" in l.lower()][-5:]
if rtw_lines:
    info("Recent rtw kernel messages:")
    for l in rtw_lines:
        print(f"    {l}")


# ── Summary ───────────────────────────────────────────────
header("Summary")
info("If airodump-ng found 0 networks, most likely cause:")
info("  RTL8821CE (rtw88) has known monitor mode issues on Linux")
info("  The in-kernel rtw88 driver has limited monitor mode support")
info("")
info("Best fix: install out-of-tree driver")
info("  git clone https://github.com/morrownr/8821ce.git")
info("  cd 8821ce && sudo ./install-driver.sh")
info("")
info("Or use a USB WiFi adapter that has solid monitor mode support")
info("  Recommended: Alfa AWUS036ACH, TP-Link TL-WN722N v1")