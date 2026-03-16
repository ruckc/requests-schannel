"""Integration tests for mutual TLS (client certificate authentication)."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from tests.conftest import InstalledTestCerts

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestMtlsConnection:
    """Test mTLS with client certificates from the Windows store."""

    @pytest.mark.smartcard
    def test_connect_with_thumbprint(
        self,
        tls_test_server: tuple[str, int],
        backend_name: str,
        smartcard_certs: InstalledTestCerts,
    ) -> None:
        """Connect with client cert selected by thumbprint."""
        import socket
        import ssl

        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE
        ctx.client_cert_thumbprint = smartcard_certs.client_thumbprint

        raw_sock = socket.create_connection((host, port), timeout=10)
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
        assert tls_sock.version() is not None
        tls_sock.close()

    @pytest.mark.smartcard
    def test_connect_with_subject(
        self,
        tls_test_server: tuple[str, int],
        backend_name: str,
        smartcard_certs: InstalledTestCerts,
    ) -> None:
        """Connect with client cert selected by subject name."""
        import socket
        import ssl

        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE
        ctx.client_cert_subject = smartcard_certs.client_subject

        raw_sock = socket.create_connection((host, port), timeout=10)
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
        assert tls_sock.version() is not None
        tls_sock.close()

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
