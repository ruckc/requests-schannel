"""Integration tests for TLS handshake against a local test server."""

from __future__ import annotations

import sys

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestTlsHandshake:
    """Real SChannel TLS handshake to a local HTTPS server."""

    def test_basic_tls_connection(
        self, tls_test_server: tuple[str, int], backend_name: str
    ) -> None:
        """Connect to local HTTPS server via SChannel."""
        import socket

        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        # Disable verification since we're using self-signed certs
        import ssl

        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.create_connection((host, port), timeout=10)
        try:
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
            assert tls_sock.version() is not None
            tls_sock.close()
        except Exception:
            raw_sock.close()
            raise

    def test_handshake_returns_version(
        self, tls_test_server: tuple[str, int], backend_name: str
    ) -> None:
        """Verify TLS version is reported after handshake."""
        import socket
        import ssl

        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.create_connection((host, port), timeout=10)
        try:
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
            version = tls_sock.version()
            assert version in ("TLSv1.2", "TLSv1.3")
            tls_sock.close()
        except Exception:
            raw_sock.close()
            raise

    def test_cipher_info(self, tls_test_server: tuple[str, int], backend_name: str) -> None:
        """Verify cipher info is available after handshake."""
        import socket
        import ssl

        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.create_connection((host, port), timeout=10)
        try:
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
            cipher = tls_sock.cipher()
            assert cipher is not None
            assert len(cipher) == 3
            assert cipher[2] > 0  # Key strength > 0
            tls_sock.close()
        except Exception:
            raw_sock.close()
            raise

    def test_peer_certificate(self, tls_test_server: tuple[str, int], backend_name: str) -> None:
        """Verify peer certificate is available."""
        import socket
        import ssl

        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.create_connection((host, port), timeout=10)
        try:
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
            cert = tls_sock.getpeercert(binary_form=True)
            assert isinstance(cert, bytes)
            assert len(cert) > 0
            tls_sock.close()
        except Exception:
            raw_sock.close()
            raise

    def test_send_recv(self, tls_test_server: tuple[str, int], backend_name: str) -> None:
        """Send an HTTP request and receive a response over TLS."""
        import socket
        import ssl

        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.create_connection((host, port), timeout=10)
        try:
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
            request = f"GET / HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n"
            tls_sock.send(request.encode())
            response = b""
            while True:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            assert b"200" in response
            assert b"OK" in response
            tls_sock.close()
        except Exception:
            raw_sock.close()
            raise
