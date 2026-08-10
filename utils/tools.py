"""
utils/tools.py - Check for required/optional tool availability
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from utils.logger import Logger

log = Logger()

REQUIRED_TOOLS = [
    "airmon-ng",
    "airodump-ng",
    "aireplay-ng",
    "aircrack-ng",
    "iw",
    "ip",
]

OPTIONAL_TOOLS = [
    "hcxdumptool",
    "hcxpcapngtool",
    "hcxpcaptool",
    "hashcat",
    "tshark",
    "reaver",
    "bully",
]


def check_tool(name: str) -> bool:
    """Check if a tool exists in PATH"""
    return shutil.which(name) is not None


def resolve_hashcat_binary() -> Optional[str]:
    """Resolve the hashcat binary path.

    Priority:
      1. Bundled hashcat-7.1.2/hashcat.bin (relative to project root)
      2. System hashcat in PATH

    Returns the full path to the binary, or None if not found.
    """
    # 1. Bundled binary — walk up from this file to find project root
    current = Path(__file__).resolve()
    for parent in [current.parent, *current.parents]:
        bundled = parent / "hashcat-7.1.2" / "hashcat.bin"
        if bundled.is_file() and os.access(str(bundled), os.X_OK):
            return str(bundled)
        # wauditor/ is inside the project root
        bundled_up = parent.parent / "hashcat-7.1.2" / "hashcat.bin"
        if bundled_up.is_file() and os.access(str(bundled_up), os.X_OK):
            return str(bundled_up)

    # 2. System hashcat
    system_path = shutil.which("hashcat")
    if system_path:
        return system_path

    return None


def get_hashcat_version() -> str:
    """Get hashcat version string from the resolved binary."""
    binary = resolve_hashcat_binary()
    if not binary:
        return "not found"
    try:
        result = subprocess.run(
            [binary, "--version"],
            capture_output=True, text=True, timeout=5,
        )
        version = result.stdout.strip()
        return version if version else "unknown"
    except Exception:
        return "unknown"


# Install commands for each tool (Nobara/Fedora-based)
INSTALL_COMMANDS: dict[str, str] = {
    "airmon-ng":     "sudo dnf install aircrack-ng",
    "airodump-ng":   "sudo dnf install aircrack-ng",
    "aireplay-ng":   "sudo dnf install aircrack-ng",
    "aircrack-ng":   "sudo dnf install aircrack-ng",
    "iw":            "sudo dnf install iw",
    "ip":            "sudo dnf install iproute",
    "hcxdumptool":   "git clone https://github.com/ZerBea/hcxdumptool && cd hcxdumptool && make && sudo make install",
    "hcxpcapngtool": "sudo dnf install hcxtools  # or: git clone https://github.com/ZerBea/hcxtools && cd hcxtools && make && sudo make install",
    "hcxpcaptool":   "sudo dnf install hcxtools",
    "hashcat":       "sudo dnf install hashcat  # or use bundled hashcat-7.1.2/hashcat.bin",
    "tshark":        "sudo dnf install wireshark-cli",
    "reaver":        "sudo dnf install reaver",
    "bully":         "# bully: build from source — https://github.com/kimocoder/bully",
}

# AMD 680M ROCm OpenCL — needed for hashcat GPU acceleration
ROCM_INSTALL_HINT = (
    "AMD 680M (RDNA3) GPU detected — for hashcat GPU acceleration install ROCm:\n"
    "    sudo dnf install rocm-opencl clinfo\n"
    "    Then verify: /home/qamber/WiAuditor/hashcat-7.1.2/hashcat.bin -I  (should list gfx1103)"
)


def check_all_tools():
    """Check and report all required and optional tools, with install hints."""
    print("\n[*] Tool availability check:\n")

    print("  Required:")
    all_required = True
    missing_required = []
    for tool in REQUIRED_TOOLS:
        found = check_tool(tool)
        status = "\033[92m✓\033[0m" if found else "\033[91m✗\033[0m"
        print(f"    {status} {tool}")
        if not found:
            all_required = False
            missing_required.append(tool)

    print("\n  Optional:")
    missing_optional = []
    for tool in OPTIONAL_TOOLS:
        if tool == "hashcat":
            hc_path = resolve_hashcat_binary()
            found = hc_path is not None
            status = "\033[92m✓\033[0m" if found else "\033[93m-\033[0m"
            extra = ""
            if found:
                version = get_hashcat_version()
                is_bundled = "hashcat-7.1.2" in (hc_path or "")
                source = "bundled" if is_bundled else "system"
                extra = f" ({version}, {source})"
            print(f"    {status} {tool}{extra}")
            if not found:
                missing_optional.append(tool)
        else:
            found = check_tool(tool)
            status = "\033[92m✓\033[0m" if found else "\033[93m-\033[0m"
            print(f"    {status} {tool}")
            if not found:
                missing_optional.append(tool)

    # ── Print install hints for missing tools ────────────────────────────
    if missing_required:
        print("\n  \033[91m[!] Missing required tools — install commands:\033[0m")
        # Group aircrack tools together
        aircrack_tools = {t for t in missing_required if t in
                          {"airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"}}
        shown = set()
        if aircrack_tools:
            print("      sudo dnf install aircrack-ng")
            shown |= aircrack_tools
        for tool in missing_required:
            if tool not in shown:
                cmd = INSTALL_COMMANDS.get(tool)
                if cmd:
                    print(f"      {cmd}")

    if missing_optional:
        print("\n  \033[93m[-] Missing optional tools — install commands:\033[0m")
        shown = set()
        for tool in missing_optional:
            if tool not in shown:
                cmd = INSTALL_COMMANDS.get(tool)
                if cmd:
                    print(f"      {cmd}")
                    shown.add(tool)

    print()

    if not all_required:
        log.warn("Some required tools are missing. See install commands above.")
        return False

    return True


def get_tool_version(tool: str) -> str:
    """Get version string of a tool"""
    try:
        result = subprocess.run(
            [tool, "--version"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.splitlines()[0] if result.stdout else "unknown"
    except Exception:
        return "unknown"
