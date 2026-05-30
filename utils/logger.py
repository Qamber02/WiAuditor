"""
utils/logger.py - Colored terminal logging
"""


class Logger:
    RESET   = "\033[0m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"

    def info(self, msg):
        print(f"{self.CYAN}[*]{self.RESET} {msg}")

    def success(self, msg):
        print(f"{self.GREEN}{self.BOLD}[+]{self.RESET} {msg}")

    def warn(self, msg):
        print(f"{self.YELLOW}[!]{self.RESET} {msg}")

    def error(self, msg):
        print(f"{self.RED}[!]{self.RESET} {msg}")

    def debug(self, msg):
        print(f"{self.DIM}[~] {msg}{self.RESET}")
