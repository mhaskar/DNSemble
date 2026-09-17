#!/usr/bin/env python3
"""
DNSemble - DNS wire-format helpers (pure Python, zero dependencies).

Every parser here is bounded: label lengths, name lengths, compression
pointer depth, and buffer offsets are all checked, and malformed input
is reported explicitly (WireError, or None from the parse_* helpers)
instead of raising deep inside a handler.

Builders mirror the parsers so round trips can be tested offline.
"""

import struct

MAX_PACKET_LEN = 4096     # matches the server's recvfrom() budget
MAX_NAME_LEN   = 255      # RFC 1035 limit on an encoded name
MAX_LABEL_LEN  = 63       # RFC 1035 limit on a single label
MAX_PTR_DEPTH  = 16       # compression pointer chain bound


class WireError(Exception):
    """Raised when a DNS message cannot be built or parsed."""


def encode_domain_name(domain):
    """Encode a dotted name; raises WireError on oversize labels/names."""
    out = b""
    for label in domain.split("."):
        raw = label.encode("ascii")
        if not raw or len(raw) > MAX_LABEL_LEN:
            raise WireError(
                f"Invalid DNS label (length {len(raw)}): {label!r}")
        out += struct.pack("B", len(raw)) + raw
    if len(out) + 1 > MAX_NAME_LEN:
        raise WireError(f"DNS name too long (> {MAX_NAME_LEN} bytes): {domain!r}")
    return out + b"\x00"


def decode_domain_name(data, offset):
    """Decode a name at `offset`, following compression pointers.

    Returns (name, offset_after_name_in_this_message).  Raises WireError
    on truncation, oversize names, or pointer loops.
    """
    labels = []
    end = None              # offset just past the name in the original stream
    seen = set()
    depth = 0
    pos = offset
    length = 0              # total encoded length, pointer-compressed or not

    while True:
        if pos >= len(data):
            raise WireError("Truncated DNS name")
        length_byte = data[pos]
        if length_byte == 0:
            pos += 1
            if end is None:
                end = pos
            break
        if (length_byte & 0xC0) == 0xC0:
            if pos + 2 > len(data):
                raise WireError("Truncated DNS compression pointer")
            ptr = struct.unpack("!H", data[pos:pos + 2])[0] & 0x3FFF
            if end is None:
                end = pos + 2
            if ptr in seen or ptr < 12:
                raise WireError("DNS compression pointer loop")
            seen.add(ptr)
            depth += 1
            if depth > MAX_PTR_DEPTH:
                raise WireError("DNS compression pointer chain too deep")
            pos = ptr
            continue
        if (length_byte & 0xC0) != 0:
            raise WireError(f"Reserved DNS label type: 0x{length_byte:02x}")
        if length_byte > MAX_LABEL_LEN:
            raise WireError(f"DNS label too long: {length_byte}")
        if pos + 1 + length_byte > len(data):
            raise WireError("Truncated DNS label")
        length += length_byte + 1
        if length > MAX_NAME_LEN:
            raise WireError("DNS name too long")
        labels.append(data[pos + 1:pos + 1 + length_byte].decode("latin-1"))
        pos += 1 + length_byte

    if not labels:
        return ".", end
    return ".".join(labels), end


def build_dns_query(txid, domain, qtype):
    header = struct.pack("!6H", txid, 0x0100, 1, 0, 0, 0)
    question = encode_domain_name(domain) + struct.pack("!2H", qtype, 1)
    return header + question


def parse_dns_query(data):
    """Parse a client query → (txid, qname, qtype), or None if malformed."""
    try:
        return _parse_dns_query(data)
    except (WireError, struct.error, UnicodeDecodeError, IndexError):
        return None


def _parse_dns_query(data):
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


def question_end(data):
    """Offset just past the question section of a query, or None."""
    try:
        _, end = decode_domain_name(data, 12)
        if end + 4 > len(data):
            return None
        return end + 4
    except (WireError, IndexError):
        return None


def _answer_header(query_data):
    if len(query_data) < 12:
        raise WireError("Query too short to answer")
    txid = query_data[0:2]
    flags = struct.pack("!H", 0x8180)
    counts = struct.pack("!4H", 1, 1, 0, 0)
    qend = question_end(query_data)
    if qend is None:
        raise WireError("Query question section is malformed")
    return txid + flags + counts + query_data[12:qend]


def build_dns_response(query_data, ip="0.0.0.0"):
    header_and_q = _answer_header(query_data)
    octets = [int(o) for o in ip.split(".")]
    if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
        raise WireError(f"Invalid IPv4 answer address: {ip!r}")
    answer = (
        struct.pack("!H", 0xC00C)
        + struct.pack("!HHI", 1, 1, 300)
        + struct.pack("!H", 4)
        + bytes(octets)
    )
    return header_and_q + answer


def build_dns_txt_response(query_data, text):
    header_and_q = _answer_header(query_data)
    text_bytes = text.encode("ascii", errors="replace")
    rdata = b""
    off = 0
    while off < len(text_bytes):
        chunk = text_bytes[off:off + 255]
        rdata += struct.pack("B", len(chunk)) + chunk
        off += 255
    answer = (
        struct.pack("!H", 0xC00C)
        + struct.pack("!HHI", 16, 1, 300)
        + struct.pack("!H", len(rdata))
        + rdata
    )
    return header_and_q + answer


def build_servfail(query_data):
    if len(query_data) < 12:
        return query_data
    return query_data[0:2] + struct.pack("!H", 0x8182) + query_data[4:]


def parse_a_record(data):
    """Extract the 4-byte A-record rdata from a response, or None."""
    try:
        return _parse_a_record(data)
    except (WireError, struct.error, IndexError):
        return None


def _parse_a_record(data):
    if len(data) < 12:
        return None
    ancount = struct.unpack("!H", data[6:8])[0]
    if ancount < 1:
        return None
    offset = 12
    _, offset = decode_domain_name(data, offset)          # question name
    offset += 4                                           # qtype + qclass
    _, offset = decode_domain_name(data, offset)          # answer name
    if offset + 10 > len(data):
        raise WireError("Truncated DNS answer")
    rtype = struct.unpack("!H", data[offset:offset + 2])[0]
    offset += 8
    rdlen = struct.unpack("!H", data[offset:offset + 2])[0]
    offset += 2
    if rtype == 1 and rdlen == 4 and offset + 4 <= len(data):
        return data[offset:offset + 4]
    return None


def response_matches_query(resp, query_data):
    """True if `resp` plausibly answers `query_data`.

    Compares the echoed transaction ID, requires the QR (response) flag,
    and compares the question section byte-for-byte.  Guards against
    consuming unrelated UDP datagrams that happen to arrive on the same
    ephemeral port.
    """
    if len(resp) < 12 or len(query_data) < 12:
        return False
    if resp[0:2] != query_data[0:2]:                      # transaction ID
        return False
    flags = struct.unpack("!H", resp[2:4])[0]
    if not flags & 0x8000:                                # QR bit
        return False
    qend = question_end(query_data)
    if qend is None or len(resp) < qend:
        return False
    return resp[12:qend] == query_data[12:qend]
