"""Integration tests for mutual TLS (client certificate authentication)."""

from __future__ import annotations

import sys

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestMtlsConnection:
    """Test mTLS with client certificates from the Windows store."""

    def test_connect_with_thumbprint(
        self, tls_test_server: tuple[str, int], tls_certs: object, backend_name: str
    ) -> None:
        """Connect with client cert selected by thumbprint."""
        import socket
        import ssl

        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE
        ctx.client_cert_thumbprint = tls_certs.client_thumbprint  # type: ignore[attr-defined]

        raw_sock = socket.create_connection((host, port), timeout=10)
        try:
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
            # Connection should succeed
            assert tls_sock.version() is not None
            tls_sock.close()
        except Exception:
            raw_sock.close()
            raise

    def test_connect_with_subject(
        self, tls_test_server: tuple[str, int], tls_certs: object, backend_name: str
    ) -> None:
        """Connect with client cert selected by subject name."""
        import socket
        import ssl

        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE
        ctx.client_cert_subject = "Test Client"

        raw_sock = socket.create_connection((host, port), timeout=10)
        try:
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
            assert tls_sock.version() is not None
            tls_sock.close()
        except Exception:
            raw_sock.close()
            raise

    def test_wrong_cert_thumbprint(
        self, tls_test_server: tuple[str, int], backend_name: str
    ) -> None:
        """Non-existent cert thumbprint should raise error."""
        import socket
        import ssl

        from requests_schannel._errors import CertificateNotFoundError, SchannelError
        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE
        ctx.client_cert_thumbprint = "0000000000000000000000000000000000000000"

        raw_sock = socket.create_connection((host, port), timeout=10)
        with pytest.raises((CertificateNotFoundError, SchannelError)):
            ctx.wrap_socket(raw_sock, server_hostname="localhost")
        raw_sock.close()
