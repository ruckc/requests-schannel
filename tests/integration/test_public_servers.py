"""Integration tests against public HTTPS servers (requires internet)."""

from __future__ import annotations

import sys

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.network,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestPublicServers:
    """Test against real public HTTPS servers using the Windows trust store."""

    @pytest.mark.timeout(30)
    def test_connect_httpbin(self, backend_name: str) -> None:
        """Connect to httpbin.org and verify TLS works end-to-end."""
        import socket

        from requests_schannel.context import SchannelContext

        ctx = SchannelContext(backend=backend_name)

        raw_sock = socket.create_connection(("httpbin.org", 443), timeout=15)
        try:
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname="httpbin.org")
            version = tls_sock.version()
            assert version in ("TLSv1.2", "TLSv1.3")

            # Send a minimal HTTP request
            tls_sock.send(b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
            response = b""
            while True:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                response += chunk

            assert b"200 OK" in response
            tls_sock.close()
        except Exception:
            raw_sock.close()
            raise

    @pytest.mark.timeout(30)
    def test_connect_with_alpn(self, backend_name: str) -> None:
        """Connect with ALPN to a public server."""
        import socket

        from requests_schannel.context import SchannelContext

        ctx = SchannelContext(backend=backend_name)
        ctx.set_alpn_protocols(["http/1.1"])

        raw_sock = socket.create_connection(("httpbin.org", 443), timeout=15)
        try:
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname="httpbin.org")
            protocol = tls_sock.selected_alpn_protocol()
            # httpbin.org should support http/1.1
            assert protocol == "http/1.1"
            tls_sock.close()
        except Exception:
            raw_sock.close()
            raise
