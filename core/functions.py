#!/usr/bin/env python3
"""
DNSemble - Output helpers, ANSI colors, banner, and display functions.
"""

import sys
from datetime import datetime


class C:
    bold = "\033[1m"
    dim  = "\033[2m"
    rst  = "\033[0m"
    red  = "\033[91m"
    grn  = "\033[92m"
    ylw  = "\033[93m"
    blu  = "\033[94m"
    mag  = "\033[95m"
    cyn  = "\033[96m"

    @classmethod
    def disable(cls):
        """Strip ANSI codes (enabled automatically when not a TTY)."""
        for attr in ("bold", "dim", "rst", "red", "grn", "ylw",
                     "blu", "mag", "cyn"):
            setattr(cls, attr, "")


if not sys.stdout.isatty():
    C.disable()


BANNER = r"""
{cyn}{bold}
    ____  _   _____                 __    __
   / __ \/ | / / ___/___  ____ ___  / /_  / /__
  / / / /  |/ /\__ \/ _ \/ __ `__ \/ __ \/ / _ \
 / /_/ / /|  /___/ /  __/ / / / / /_/ / /  __/
/_____/_/ |_//____/\___/_/ /_/ /_/_.___/_/\___/
{rst}
  {dim}DNS Exfiltration Framework  ·  v1.0{rst}
  {dim}The domain IS the data.  Dynamic mapping.{rst}
"""


def banner_kwargs():
    return {k: getattr(C, k) for k in
            ("bold", "dim", "rst", "red", "grn", "ylw", "blu", "mag", "cyn")}


def get_timestamp():
    return datetime.now().strftime("%H:%M:%S")


def log(tag, color, msg):
    print(f"{C.dim}[{get_timestamp()}]{C.rst} {color}[{tag:>5s}]{C.rst} {msg}")


def warn(msg):
    log("WARN", C.ylw, msg)


def fail(msg, code=1):
    """Print an actionable error and exit nonzero (usage errors use 2)."""
    print(f"{C.red}[!] {msg}{C.rst}", file=sys.stderr)
    sys.exit(code)


def list_payloads(payloads):
    print(BANNER.format(**banner_kwargs()))

    items = list(payloads.items())
    col_n = 4
    col_name = max(len(k) for k, _ in items) + 2
    col_desc = max(len(v["description"]) for _, v in items) + 2

    header = (f"  {C.bold}{'#':>{col_n}s}  "
              f"{'Payload':<{col_name}s}  "
              f"{'Description':<{col_desc}s}{C.rst}")
    sep = f"  {'─' * col_n}  {'─' * col_name}  {'─' * col_desc}"

    print(header)
    print(sep)
    for idx, (key, info) in enumerate(items, 1):
        print(f"  {C.cyn}{idx:>{col_n}d}{C.rst}  "
              f"{C.bold}{key:<{col_name}s}{C.rst}  "
              f"{C.dim}{info['description']}{C.rst}")
    print()
    print(f"  {C.dim}Usage: python DNSemble.py --payload <name_or_#> "
          f"--host <IP> [--port 5353]{C.rst}")
    print(f"  {C.dim}       python DNSemble.py --payload 1 "
          f"--host 10.0.0.1{C.rst}")
    print()
