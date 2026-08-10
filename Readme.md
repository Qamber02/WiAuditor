# wauditor — Setup & Usage Guide

Modern wireless auditing tool for WPA2, PMKID, and WPA3.
**For authorized testing and educational use only.**

---

## Project Structure

```
wauditor/
├── main.py               # Entry point
├── core/
│   ├── interface.py      # Monitor mode, interface management
│   ├── scanner.py        # Network scanning (airodump-ng wrapper)
│   └── attack.py         # Attack orchestration / routing
├── attacks/
│   ├── wpa2.py           # WPA2 handshake capture + deauth
│   ├── pmkid.py          # Clientless PMKID attack (modern routers)
│   └── wpa3.py           # WPA3 SAE handshake capture
├── utils/
│   ├── logger.py         # Colored terminal output
│   ├── tools.py          # Tool availability checker
│   ├── wordlist.py       # Auto-detects / resolves rockyou.txt
│   └── banner.py         # ASCII banner
└── captures/             # Auto-created, stores all capture files
```

---

## Step 1 — Install Dependencies

### Core (required)
```bash
sudo dnf install aircrack-ng
```

### Optional but recommended
```bash
sudo dnf install wireshark-cli hcxtools --skip-unavailable
```

### hcxdumptool (needed for PMKID attack)
Not in Nobara repos, build from source:
```bash
git clone https://github.com/ZerBea/hcxdumptool.git
cd hcxdumptool
make
sudo make install
```

### AMD iGPU 680M — ROCm OpenCL for hashcat GPU acceleration

The Radeon 680M is an **RDNA3 iGPU** (gfx1103). hashcat supports it via ROCm OpenCL.

```bash
# Install ROCm OpenCL runtime (Nobara/Fedora)
sudo dnf install rocm-opencl clinfo

# Verify GPU is detected by OpenCL
clinfo | grep -i "Device Name"
# Expected output: Device Name: AMD Radeon Graphics (or similar)

# All hashcat commands below must be run from the PROJECT ROOT:
# cd /home/qamber/WiAuditor

# Verify hashcat sees the iGPU
/home/qamber/WiAuditor/hashcat-7.1.2/hashcat.bin -I
# Should list:  Backend Device #1: gfx1103 (Radeon 680M)

# Quick benchmark to confirm GPU cracking works
/home/qamber/WiAuditor/hashcat-7.1.2/hashcat.bin -m 22000 -b
# With 680M: expect ~800 kH/s - 1.5 MH/s for WPA2
```

> **Note:** If `hashcat -I` shows no devices, try:
> ```bash
> /home/qamber/WiAuditor/hashcat-7.1.2/hashcat.bin -I --opencl-platform 1
> lsmod | grep amdgpu   # verify amdgpu driver is loaded
> ```


### iwconfig (if missing)
```bash
# Check if broken
ls -la /usr/sbin/iwconfig

# If broken symlink, rebuild from source
wget https://hewlettpackard.github.io/wireless-tools/wireless_tools.29.tar.gz
tar -xzf wireless_tools.29.tar.gz
cd wireless_tools.29
make
sudo cp iwconfig /usr/sbin/iwconfig
```

---

## Step 2 — Prepare Interface


Enable monitor mode manually before each session:
```bash
sudo ip link set wlp1s0 down
sudo iw dev wlp1s0 set type monitor
sudo ip link set wlp1s0 up
```

Verify:
```bash
iw dev wlp1s0 info
# Should show: type monitor
```

Stop NetworkManager so it doesn't fight you:
```bash
sudo systemctl stop NetworkManager
sudo systemctl stop wpa_supplicant
```

---

## Step 3 — Run wauditor

### Basic scan only
```bash
sudo python main.py -i wlp1s0 --scan-only
```

### Full auto attack (tries PMKID first, then handshake)
```bash
sudo python main.py -i wlp1s0 --kill
```

### Target specific network + wordlist
```bash
sudo python main.py -i wlp1s0 --bssid AA:BB:CC:DD:EE:FF --wordlist /path/to/rockyou.txt
```

### PMKID attack only (clientless, fast)
```bash
sudo python main.py -i wlp1s0 --attack pmkid --wordlist /path/to/wordlist.txt
```

### WPA3 target
```bash
sudo python main.py -i wlp1s0 --attack wpa3
```

### Scan with longer timeout
```bash
sudo python main.py -i wlp1s0 --timeout 120 --scan-only
```

---

## Command Reference

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --interface` | Wireless interface | auto-detect |
| `--kill` | Kill NetworkManager/wpa_supplicant | off |
| `--scan-only` | Scan and list, no attacks | off |
| `--attack` | `wpa2`, `pmkid`, `wpa3`, `all` | `all` |
| `--bssid` | Target specific BSSID | all |
| `--essid` | Target specific network name | all |
| `--wordlist` | Path to wordlist for cracking | auto-detects rockyou.txt |
| `--timeout` | Scan timeout in seconds | 60 |
| `--deauth-count` | Deauth packets per burst | 5 |
| `--channel` | Lock to channel | all channels |
| `--output` | Output dir for captures | `./captures` |

---

## Attack Flow

```
wauditor starts
     │
     ▼
Enable monitor mode
     │
     ▼
Scan networks (airodump-ng)
     │
     ▼
User selects target
     │
     ├─ WPA3? → SAE capture (hcxdumptool) → hashcat -m 22000
     │
     ├─ WPA2? → PMKID first (clientless, fast)
     │               └─ fail? → handshake + deauth
     │                              └─ aircrack-ng / hashcat
     │
     └─ Open/WEP → skip / notify
```

---

## Attack Types Explained

### PMKID (Recommended for WPA2)
- **Clientless** — no need to wait for a user to connect
- Works on most routers made after ~2018
- Captures a single frame from the AP
- Crack with: `hashcat -m 22000 capture.22000 wordlist.txt`

### WPA2 Handshake
- Sends deauth packets to force clients to reconnect
- Captures the 4-way handshake during reconnection
- Crack with: `aircrack-ng capture.cap -w wordlist.txt`

### WPA3 SAE
- Much harder — SAE has offline attack resistance built in
- Still worth capturing for weak password testing
- Crack with: `hashcat -m 22000 capture.pcapng wordlist.txt`

---

## Manual Cracking

After capturing, crack offline:

```bash
# hashcat WPA2/PMKID
hashcat -m 22000 captures/pmkid_*.22000 /usr/share/wordlists/rockyou.txt

# hashcat with rules (better coverage)
hashcat -m 22000 captures/*.22000 rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# aircrack-ng WPA2
aircrack-ng captures/wpa2_*.cap -w rockyou.txt
```

---

## After Testing — Restore Interface

```bash
sudo ip link set wlp1s0 down
sudo iw dev wlp1s0 set type managed
sudo ip link set wlp1s0 up
sudo systemctl start NetworkManager
```

Or wauditor handles this automatically on exit/Ctrl+C.

---

## Wordlists

### rockyou.txt (auto-detected by wauditor)

wauditor automatically searches these locations for `rockyou.txt` — no `--wordlist` flag needed once installed:
- `/usr/share/wordlists/rockyou.txt`
- `/opt/rockyou.txt`
- `/root/rockyou.txt`
- `/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt`

**Nobara / Fedora — install rockyou.txt:**
```bash
# rockyou.txt is not in Fedora/Nobara repos — download directly:
sudo mkdir -p /usr/share/wordlists
sudo curl -L "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
     -o /usr/share/wordlists/rockyou.txt

# Verify (~140 MB, 14 million passwords)
wc -l /usr/share/wordlists/rockyou.txt
# Expected: 14344391
```

**Kali Linux — rockyou.txt is pre-installed (compressed):**
```bash
sudo gzip -d -k /usr/share/wordlists/rockyou.txt.gz
```

### SecLists (extended wordlists)
```bash
git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

---

## Author
Qamber
## Legal Notice

Only use this tool on networks you own or have explicit written permission to test.
Unauthorized access to computer networks is illegal in Pakistan (PECA 2016, Section 3)
and in every other jurisdiction worldwide.

## Author 
Qamber 
