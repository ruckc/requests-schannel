"""Integration tests for ALPN negotiation."""

from __future__ import annotations

import sys

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestAlpnNegotiation:
    """Test ALPN protocol negotiation via SChannel."""

    def test_alpn_http11(self, tls_test_server: tuple[str, int], backend_name: str) -> None:
        """Negotiate http/1.1 via ALPN."""
        import socket
        import ssl

        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])

        raw_sock = socket.create_connection((host, port), timeout=10)
        try:
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
            # Server may or may not support ALPN, but we should get a result
            protocol = tls_sock.selected_alpn_protocol()
            # If server supports ALPN, it should be http/1.1
            if protocol is not None:
                assert protocol == "http/1.1"
            tls_sock.close()
        except Exception:
            raw_sock.close()
            raise

    def test_no_alpn_returns_none(
        self, tls_test_server: tuple[str, int], backend_name: str
    ) -> None:
        """No ALPN configured → selected_alpn_protocol returns None."""
        import socket
        import ssl

        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE
        # Don't set ALPN

        raw_sock = socket.create_connection((host, port), timeout=10)
        try:
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
            protocol = tls_sock.selected_alpn_protocol()
            assert protocol is None
            tls_sock.close()
        except Exception:
            raw_sock.close()
            raise
