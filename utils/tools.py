"""
utils/tools.py - Check for required/optional tool availability
"""

import shutil
import subprocess
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


def check_tool(name):
    """Check if a tool exists in PATH"""
    return shutil.which(name) is not None


def check_all_tools():
    """Check and report all required and optional tools"""
    print("\n[*] Tool availability check:\n")

    print("  Required:")
    all_required = True
    for tool in REQUIRED_TOOLS:
        found = check_tool(tool)
        status = "\033[92m✓\033[0m" if found else "\033[91m✗\033[0m"
        print(f"    {status} {tool}")
        if not found:
            all_required = False

    print("\n  Optional:")
    for tool in OPTIONAL_TOOLS:
        found = check_tool(tool)
        status = "\033[92m✓\033[0m" if found else "\033[93m-\033[0m"
        print(f"    {status} {tool}")

    print()

    if not all_required:
        log.warn("Some required tools are missing. Install aircrack-ng suite.")
        return False

    return True


def get_tool_version(tool):
    """Get version string of a tool"""
    try:
        result = subprocess.run(
            [tool, "--version"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.splitlines()[0] if result.stdout else "unknown"
    except Exception:
        return "unknown"
