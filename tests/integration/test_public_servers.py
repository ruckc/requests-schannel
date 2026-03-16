"""Integration tests against a local HTTPS server (no external dependencies)."""

from __future__ import annotations

import sys

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestLocalServer:
    """Test against a local HTTPS server using the test PKI certs."""

    @pytest.mark.timeout(30)
    def test_connect_and_get(self, tls_test_server: tuple[str, int], backend_name: str) -> None:
        """Connect to local HTTPS server and verify TLS works end-to-end."""
        import socket
        import ssl

        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.create_connection((host, port), timeout=15)
        try:
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
            version = tls_sock.version()
            assert version in ("TLSv1.2", "TLSv1.3")

            # Send a minimal HTTP request
            request = f"GET / HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n"
            tls_sock.send(request.encode())
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
    def test_connect_with_alpn(self, tls_test_server: tuple[str, int], backend_name: str) -> None:
        """Connect with ALPN to the local server."""
        import socket
        import ssl

        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])

        raw_sock = socket.create_connection((host, port), timeout=15)
        try:
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
            protocol = tls_sock.selected_alpn_protocol()
            # Local server advertises h2 and http/1.1
            assert protocol == "http/1.1"
            tls_sock.close()
        except Exception:
            raw_sock.close()
            raise
