#!/usr/bin/env python3
"""
DNSemble - Upstream forwarding.

Forwards client queries to a real resolver so every answer is
legitimate.  The response is only relayed when its identity matches the
query (transaction ID + question section); anything else that lands on
the ephemeral port within the timeout window is discarded.
"""

import socket

from core.dnswire import build_servfail, response_matches_query


class Forwarder:
    DEFAULT_UPSTREAM_PORT = 53

    def __init__(self, upstream_ip, timeout=2.0, upstream_port=None):
        self.upstream_ip = upstream_ip
        self.timeout = timeout
        self.upstream_port = upstream_port or self.DEFAULT_UPSTREAM_PORT

    def forward(self, sock, data, addr):
        """Send `data` upstream and relay the matching response to `addr`.

        Returns True when a validated response was relayed.  On any
        failure the client gets SERVFAIL, and the upstream socket is
        always closed - including on timeouts and errors.
        """
        up = None
        try:
            up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up.settimeout(self.timeout)
            up.sendto(data, (self.upstream_ip, self.upstream_port))
            deadline = self.timeout
            while deadline > 0:
                up.settimeout(deadline)
                try:
                    resp, _ = up.recvfrom(4096)
                except socket.timeout:
                    break
                if response_matches_query(resp, data):
                    sock.sendto(resp, addr)
                    return True
                deadline -= self._elapsed_budget(resp)
        except OSError:
            pass
        finally:
            if up is not None:
                try:
                    up.close()
                except OSError:
                    pass
        try:
            sock.sendto(build_servfail(data), addr)
        except OSError:
            pass
        return False

    @staticmethod
    def _elapsed_budget(_resp):
        """Charge a fixed slice of the timeout per non-matching datagram."""
        return 0.1
