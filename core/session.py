#!/usr/bin/env python3
"""
DNSemble - Protocol/session state.

A Session owns nothing but state: buffers, phase transitions, and the
integrity of what has been assembled so far.  It is socket-free and
clock-free (time is injected), so it can be exercised in tests without
any network.
"""

import time

from core.domains import (
    QTYPE_A, QTYPE_AAAA, QTYPE_MX,
    CTRL_END_HOSTNAME, CTRL_END_FILENAME, CTRL_END_CONTENT, CTRL_CHUNK_OFFSET,
    MAX_CHUNK, MAX_CONTENT_LEN,
    generate_permutation, build_domain_to_char,
)


class Session:
    # Ordered phases; data for a phase is only accepted while that phase
    # is active, so out-of-order agents cannot silently mix channels.
    PHASES = ("HOSTNAME", "FILENAME", "CONTENT", "COMPLETE")

    _CHANNEL_FOR_QTYPE = {QTYPE_AAAA: "hostname", QTYPE_MX: "filename", QTYPE_A: "content"}

    def __init__(self, client_id, source_ip, seed, now=None):
        self.client_id     = client_id
        self.source_ip     = source_ip
        self.seed          = seed
        self.start_time    = now if now is not None else time.time()
        self.phase         = "HOSTNAME"
        self.hostname_buf  = {}
        self.filename_buf  = {}
        self.content_buf   = {}
        self.content_chunk = 0
        self.hostname      = ""
        self.filename      = ""
        self.content       = ""
        self.stray_packets = 0

        perm = generate_permutation(seed)
        self.domain_to_char = build_domain_to_char(perm)

    # -- data channel -------------------------------------------------------

    def content_pos(self, seq):
        return self.content_chunk * 256 + seq

    def receive_data(self, qtype, seq, char):
        """Record one data character for the active phase.

        Returns the channel name, or None when the packet does not belong
        to the current phase (counted as stray, not silently merged).
        """
        channel = self._CHANNEL_FOR_QTYPE.get(qtype)
        if channel is None:
            self.stray_packets += 1
            return None

        phase_for = {"hostname": "HOSTNAME", "filename": "FILENAME", "content": "CONTENT"}
        if phase_for[channel] != self.phase:
            self.stray_packets += 1
            return None

        if channel == "content" and self.content_pos(seq) >= MAX_CONTENT_LEN:
            self.stray_packets += 1
            return None

        getattr(self, f"{channel}_buf")[seq if channel != "content"
                                        else self.content_pos(seq)] = char
        return channel

    def next_chunk(self, chunk):
        """Switch the content chunk; returns False for invalid transitions."""
        if self.phase != "CONTENT" or chunk <= self.content_chunk:
            self.stray_packets += 1
            return False
        self.content_chunk = chunk
        return True

    # -- control channel ----------------------------------------------------

    def end_phase(self, ctrl_code):
        """Close the active phase; returns False on invalid transitions."""
        transitions = {
            CTRL_END_HOSTNAME: ("HOSTNAME", "FILENAME"),
            CTRL_END_FILENAME: ("FILENAME", "CONTENT"),
            CTRL_END_CONTENT:  ("CONTENT",  "COMPLETE"),
        }
        transition = transitions.get(ctrl_code)
        if transition is None or self.phase != transition[0]:
            self.stray_packets += 1
            return False
        if transition[0] == "HOSTNAME":
            self.hostname = self.assemble(self.hostname_buf)
        elif transition[0] == "FILENAME":
            self.filename = self.assemble(self.filename_buf)
        else:
            self.content = self.assemble(self.content_buf)
        self.phase = transition[1]
        return True

    # -- assembly / integrity -----------------------------------------------

    @staticmethod
    def assemble(buf):
        if not buf:
            return ""
        return "".join(buf[k] for k in sorted(buf.keys()))

    def integrity(self):
        """Compare received characters against contiguous positions.

        The seq byte wraps blindly, so a lost packet leaves a gap and every
        later character in that chunk lands one position early - this is
        how incomplete transfers are made visible instead of saved as if
        they were complete.
        """
        def stats(buf):
            received = len(buf)
            expected = (max(buf.keys()) + 1) if buf else 0
            gaps = expected - received
            return {"received": received, "expected": expected, "gaps": gaps}

        report = {
            "hostname": stats(self.hostname_buf),
            "filename": stats(self.filename_buf),
            "content":  stats(self.content_buf),
            "complete": self.phase == "COMPLETE",
        }
        report["ok"] = (
            report["complete"]
            and report["hostname"]["gaps"] == 0
            and report["filename"]["gaps"] == 0
            and report["content"]["gaps"] == 0
        )
        return report

    def age(self, now=None):
        return (now if now is not None else time.time()) - self.start_time

    def query_count(self):
        return (len(self.hostname_buf) + len(self.filename_buf)
                + len(self.content_buf) + 4)
