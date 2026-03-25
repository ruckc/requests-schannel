"""Integration tests for AsyncSchannelSocket against a local HTTPS server.

Mirrors the sync integration tests in test_tls_handshake.py, test_alpn.py,
test_public_servers.py, test_server_verification.py, and test_mtls.py.
"""

from __future__ import annotations

import ssl
import sys
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from tests.conftest import InstalledTestCerts

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestAsyncTlsHandshake:
    """Real SChannel TLS handshake via AsyncSchannelSocket."""

    @pytest.mark.timeout(30)
    async def test_basic_tls_connection(
        self, tls_test_server: tuple[str, int], backend_name: str
    ) -> None:
        """Connect to local HTTPS server via async SChannel."""
        from requests_schannel.async_socket import AsyncSchannelSocket
        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE

        async with await AsyncSchannelSocket.connect(
            host, port, ctx, server_hostname="localhost", timeout=10.0
        ) as sock:
            assert sock.version() is not None

    @pytest.mark.timeout(30)
    async def test_handshake_returns_version(
        self, tls_test_server: tuple[str, int], backend_name: str
    ) -> None:
        """Verify TLS version is reported after async handshake."""
        from requests_schannel.async_socket import AsyncSchannelSocket
        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE

        async with await AsyncSchannelSocket.connect(
            host, port, ctx, server_hostname="localhost", timeout=10.0
        ) as sock:
            version = sock.version()
            assert version in ("TLSv1.2", "TLSv1.3")

    @pytest.mark.timeout(30)
    async def test_cipher_info(self, tls_test_server: tuple[str, int], backend_name: str) -> None:
        """Verify cipher info is available after async handshake."""
        from requests_schannel.async_socket import AsyncSchannelSocket
        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE

        async with await AsyncSchannelSocket.connect(
            host, port, ctx, server_hostname="localhost", timeout=10.0
        ) as sock:
            cipher = sock.cipher()
            assert cipher is not None
            assert len(cipher) == 3
            assert cipher[2] > 0  # Key strength > 0

    @pytest.mark.timeout(30)
    async def test_send_recv(self, tls_test_server: tuple[str, int], backend_name: str) -> None:
        """Send HTTP request and receive response over async TLS."""
        from requests_schannel.async_socket import AsyncSchannelSocket
        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE

        async with await AsyncSchannelSocket.connect(
            host, port, ctx, server_hostname="localhost", timeout=10.0
        ) as sock:
            request = f"GET / HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n"
            await sock.send(request.encode())
            response = b""
            while True:
                chunk = await sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            assert b"200" in response
            assert b"OK" in response


class TestAsyncAlpnNegotiation:
    """Test ALPN negotiation via async SChannel."""

    @pytest.mark.timeout(30)
    async def test_alpn_http11(self, tls_test_server: tuple[str, int], backend_name: str) -> None:
        """Negotiate http/1.1 via ALPN."""
        from requests_schannel.async_socket import AsyncSchannelSocket
        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])

        async with await AsyncSchannelSocket.connect(
            host, port, ctx, server_hostname="localhost", timeout=10.0
        ) as sock:
            protocol = sock.selected_alpn_protocol()
            if protocol is not None:
                assert protocol == "http/1.1"

    @pytest.mark.timeout(30)
    async def test_no_alpn_returns_none(
        self, tls_test_server: tuple[str, int], backend_name: str
    ) -> None:
        """No ALPN configured → selected_alpn_protocol returns None."""
        from requests_schannel.async_socket import AsyncSchannelSocket
        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE

        async with await AsyncSchannelSocket.connect(
            host, port, ctx, server_hostname="localhost", timeout=10.0
        ) as sock:
            assert sock.selected_alpn_protocol() is None


class TestAsyncServerVerification:
    """Test async SChannel server certificate verification."""

    @pytest.mark.timeout(30)
    async def test_verify_none_allows_self_signed(
        self, tls_test_server: tuple[str, int], backend_name: str
    ) -> None:
        """CERT_NONE should allow self-signed certs."""
        from requests_schannel.async_socket import AsyncSchannelSocket
        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE

        async with await AsyncSchannelSocket.connect(
            host, port, ctx, server_hostname="localhost", timeout=10.0
        ) as sock:
            assert sock.version() is not None


class TestAsyncWrap:
    """Test AsyncSchannelSocket.wrap() with an existing socket."""

    @pytest.mark.timeout(30)
    async def test_wrap_existing_socket(
        self, tls_test_server: tuple[str, int], backend_name: str
    ) -> None:
        """Wrap a pre-connected TCP socket with async SChannel TLS."""
        import socket

        from requests_schannel.async_socket import AsyncSchannelSocket
        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.create_connection((host, port), timeout=10)
        try:
            async with await AsyncSchannelSocket.wrap(raw_sock, ctx, "localhost") as sock:
                assert sock.version() is not None
                request = f"GET / HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n"
                await sock.send(request.encode())
                response = b""
                while True:
                    chunk = await sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                assert b"200 OK" in response
        except Exception:
            raw_sock.close()
            raise


class TestAsyncMtls:
    """Test async mTLS with client certificates from the Windows store."""

    @pytest.mark.smartcard
    @pytest.mark.timeout(30)
    async def test_connect_with_thumbprint(
        self,
        tls_test_server: tuple[str, int],
        backend_name: str,
        smartcard_certs: InstalledTestCerts,
    ) -> None:
        """Connect with client cert selected by thumbprint (async)."""
        from requests_schannel.async_socket import AsyncSchannelSocket
        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE
        ctx.client_cert_thumbprint = smartcard_certs.client_thumbprint

        async with await AsyncSchannelSocket.connect(
            host, port, ctx, server_hostname="localhost", timeout=10.0
        ) as sock:
            assert sock.version() is not None

    @pytest.mark.smartcard
    @pytest.mark.timeout(30)
    async def test_connect_with_subject(
        self,
        tls_test_server: tuple[str, int],
        backend_name: str,
        smartcard_certs: InstalledTestCerts,
    ) -> None:
        """Connect with client cert selected by subject name (async)."""
        from requests_schannel.async_socket import AsyncSchannelSocket
        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE
        ctx.client_cert_subject = smartcard_certs.client_subject

        async with await AsyncSchannelSocket.connect(
            host, port, ctx, server_hostname="localhost", timeout=10.0
        ) as sock:
            assert sock.version() is not None

    @pytest.mark.timeout(30)
    async def test_wrong_cert_thumbprint(
        self, tls_test_server: tuple[str, int], backend_name: str
    ) -> None:
        """Non-existent cert thumbprint should raise error (async)."""
        from requests_schannel._errors import CertificateNotFoundError, SchannelError
        from requests_schannel.async_socket import AsyncSchannelSocket
        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE
        ctx.client_cert_thumbprint = "0000000000000000000000000000000000000000"

        with pytest.raises((CertificateNotFoundError, SchannelError)):
            await AsyncSchannelSocket.connect(
                host, port, ctx, server_hostname="localhost", timeout=10.0
            )
