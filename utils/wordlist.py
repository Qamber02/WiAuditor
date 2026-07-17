"""
utils/wordlist.py - Wordlist discovery and resolution
Automatically locates rockyou.txt or prompts the user for a path.
"""

import os
import subprocess
from utils.logger import Logger

log = Logger()

# Common locations for rockyou.txt across Kali, Parrot, Ubuntu, BlackArch, Nobara
ROCKYOU_CANDIDATES = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/usr/share/john/password.lst",
    "/opt/rockyou.txt",
    "/root/rockyou.txt",
    "/home/kali/rockyou.txt",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
    "/usr/share/seclists/Passwords/rockyou.txt",
    "/tmp/wordlists/rockyou.txt",   # fallback: downloaded but not yet moved
]


def _decompress_rockyou(gz_path: str) -> str | None:
    """
    Decompress rockyou.txt.gz to the same directory and return the plain path.
    Returns None if decompression fails.
    """
    plain_path = gz_path[:-3]  # strip .gz
    if os.path.exists(plain_path):
        return plain_path  # already decompressed before

    log.info(f"[*] Decompressing {gz_path} → {plain_path} ...")
    try:
        result = subprocess.run(
            ["gunzip", "-k", gz_path],   # -k keeps the .gz
            capture_output=True, timeout=60
        )
        if result.returncode == 0 and os.path.exists(plain_path):
            log.success(f"[+] Decompressed: {plain_path}")
            return plain_path
    except FileNotFoundError:
        # gunzip not available; try gzip -d -k
        try:
            result = subprocess.run(
                ["gzip", "-d", "-k", gz_path],
                capture_output=True, timeout=60
            )
            if result.returncode == 0 and os.path.exists(plain_path):
                log.success(f"[+] Decompressed: {plain_path}")
                return plain_path
        except Exception:
            pass
    except Exception as e:
        log.warn(f"[!] Decompression failed: {e}")

    return None


def find_rockyou() -> str | None:
    """
    Search common filesystem locations for rockyou.txt.
    If a .gz variant is found, attempt to decompress it first.
    Returns the resolved plain-text path, or None if not found.
    """
    for candidate in ROCKYOU_CANDIDATES:
        if os.path.exists(candidate):
            if candidate.endswith(".gz"):
                plain = _decompress_rockyou(candidate)
                if plain:
                    return plain
                # Cannot decompress — skip
            else:
                return candidate

    return None


def resolve_wordlist(user_provided: str | None) -> str | None:
    """
    Resolve the wordlist to use for cracking:
      1. If the user passed --wordlist, validate it exists and return it.
      2. Otherwise, search for rockyou.txt automatically.
      3. If not found, interactively prompt the user.
      4. Returns None if the user declines to provide one.
    """
    # ── 1. User-specified path ──────────────────────────────────────────────
    if user_provided:
        if os.path.isfile(user_provided):
            log.success(f"[+] Wordlist: {user_provided}")
            return user_provided
        else:
            log.error(f"[!] Wordlist not found: {user_provided}")
            # Fall through to auto-discover

    # ── 2. Auto-discover rockyou.txt ────────────────────────────────────────
    log.info("[*] No wordlist specified — searching for rockyou.txt...")
    found = find_rockyou()
    if found:
        log.success(f"[+] Auto-detected wordlist: {found}")
        return found

    # ── 3. Interactive prompt ───────────────────────────────────────────────
    log.warn("[!] rockyou.txt not found in standard locations.")
    print()
    print("  Common fix on Kali:  sudo gzip -d /usr/share/wordlists/rockyou.txt.gz")
    print("  Or provide a path below.\n")

    try:
        path = input("[?] Enter wordlist path (or press Enter to skip cracking): ").strip()
    except (EOFError, KeyboardInterrupt):
        path = ""

    if path and os.path.isfile(path):
        log.success(f"[+] Using wordlist: {path}")
        return path
    elif path:
        log.error(f"[!] File not found: {path}  — skipping cracking.")
    else:
        log.warn("[!] No wordlist provided. Capture saved for manual cracking.")

    return None
