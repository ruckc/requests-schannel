"""Integration tests for server certificate verification."""

from __future__ import annotations

import sys

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestServerVerification:
    """Test SChannel server certificate verification."""

    def test_verify_none_allows_self_signed(
        self, tls_test_server: tuple[str, int], backend_name: str
    ) -> None:
        """CERT_NONE should allow self-signed certs."""
        import socket
        import ssl

        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.create_connection((host, port), timeout=10)
        try:
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
            assert tls_sock.version() is not None
            tls_sock.close()
        except Exception:
            raw_sock.close()
            raise

    def test_verify_required_with_trusted_ca(
        self, tls_test_server: tuple[str, int], tls_certs: object, backend_name: str
    ) -> None:
        """CERT_REQUIRED should succeed when CA is in the trusted store.

        The tls_certs fixture imports the Root CA into CurrentUser\\Root,
        so verification should succeed.
        """
        import socket
        import ssl

        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_REQUIRED

        raw_sock = socket.create_connection((host, port), timeout=10)
        try:
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
            assert tls_sock.version() is not None
            tls_sock.close()
        except Exception:
            raw_sock.close()
            raise
