"""
utils/banner.py - Tool banner
"""


def print_banner():
    banner = """
\033[96m
  ██╗    ██╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗ ██████╗ ██████╗ 
  ██║    ██║██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝██╔═══██╗██╔══██╗
  ██║ █╗ ██║███████║██║   ██║██║  ██║██║   ██║   ██║   ██║██████╔╝
  ██║███╗██║██╔══██║██║   ██║██║  ██║██║   ██║   ██║   ██║██╔══██╗
  ╚███╔███╔╝██║  ██║╚██████╔╝██████╔╝██║   ██║   ╚██████╔╝██║  ██║
   ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
\033[0m
\033[93m  Modern Wireless Auditor — WPA2 / PMKID / WPA3\033[0m
\033[91m  For authorized testing and educational use ONLY\033[0m
\033[2m  github: github.com/Qamber02  |  built on aircrack-ng + hcxtools\033[0m
"""
    print(banner)
