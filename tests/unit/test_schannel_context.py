"""Tests for SchannelContext configuration and ssl.SSLContext compatibility."""

from __future__ import annotations

import socket
import ssl
from unittest.mock import MagicMock, patch

import pytest

from requests_schannel._constants import (
    ISC_REQ_TLS_CLIENT_MTLS,
)
from requests_schannel._errors import SchannelError
from requests_schannel.backend import (
    CredentialHandle,
    TlsVersion,
)
from requests_schannel.context import SchannelContext


@pytest.mark.unit
class TestContextCreation:
    """Test SchannelContext creation and configuration."""

    def test_default_creation(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True
        assert ctx.client_cert_thumbprint is None
        assert ctx.client_cert_subject is None
        assert ctx.auto_select_client_cert is False
        assert ctx.cert_store_name == "MY"

    def test_backend_property(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        assert ctx.backend is mock_backend


@pytest.mark.unit
class TestTlsVersionConfig:
    """Test TLS version configuration."""

    def test_default_versions(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        assert ctx.minimum_version == TlsVersion.TLSv1_2
        assert ctx.maximum_version == TlsVersion.TLSv1_3

    def test_set_minimum_tls13(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        ctx.minimum_version = TlsVersion.TLSv1_3
        assert ctx.minimum_version == TlsVersion.TLSv1_3

    def test_set_maximum_tls12(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        ctx.maximum_version = TlsVersion.TLSv1_2
        assert ctx.maximum_version == TlsVersion.TLSv1_2

    def test_set_minimum_invalidates_credential(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        ctx._credential = CredentialHandle(handle="old")
        ctx.minimum_version = TlsVersion.TLSv1_3
        assert ctx._credential is None


@pytest.mark.unit
class TestCertificateConfig:
    """Test client certificate configuration."""

    def test_set_thumbprint(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        ctx.client_cert_thumbprint = "AABBCCDD"
        assert ctx.client_cert_thumbprint == "AABBCCDD"

    def test_set_thumbprint_invalidates_credential(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        ctx._credential = CredentialHandle(handle="old")
        ctx.client_cert_thumbprint = "AABB"
        assert ctx._credential is None

    def test_set_subject(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        ctx.client_cert_subject = "CN=Test"
        assert ctx.client_cert_subject == "CN=Test"

    def test_auto_select(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        ctx.auto_select_client_cert = True
        assert ctx.auto_select_client_cert is True

    def test_cert_store_name(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        ctx.cert_store_name = "ROOT"
        assert ctx.cert_store_name == "ROOT"


@pytest.mark.unit
class TestAlpn:
    """Test ALPN configuration."""

    def test_set_alpn_protocols(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        assert ctx._alpn_protocols == ["h2", "http/1.1"]

    def test_alpn_copies_list(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        original = ["h2"]
        ctx.set_alpn_protocols(original)
        original.append("http/1.1")
        assert ctx._alpn_protocols == ["h2"]  # Not modified


@pytest.mark.unit
class TestVerifyMode:
    """Test verification mode configuration."""

    def test_default_verify_required(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_set_verify_none(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        ctx.verify_mode = ssl.CERT_NONE
        assert ctx.verify_mode == ssl.CERT_NONE

    def test_verify_mode_invalidates_credential(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        ctx._credential = CredentialHandle(handle="old")
        ctx.verify_mode = ssl.CERT_NONE
        assert ctx._credential is None


@pytest.mark.unit
class TestSslCompatStubs:
    """Test ssl.SSLContext compatibility no-op methods."""

    def test_load_cert_chain_noop(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        ctx.load_cert_chain("cert.pem", "key.pem")  # Should not raise

    def test_load_verify_locations_noop(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        ctx.load_verify_locations(cafile="ca.pem")  # Should not raise

    def test_load_default_certs_noop(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        ctx.load_default_certs()  # Should not raise

    def test_set_ciphers_noop(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        ctx.set_ciphers("AES256")  # Should not raise

    def test_set_default_verify_paths_noop(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        ctx.set_default_verify_paths()  # Should not raise


@pytest.mark.unit
class TestWrapSocket:
    """Test wrap_socket() creates correctly configured SchannelSocket."""

    def test_wrap_socket_basic(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        raw_sock = MagicMock(spec=socket.socket)

        with patch("requests_schannel.context.SchannelSocket") as MockSock:
            MockSock.return_value = MagicMock()
            MockSock.return_value.do_handshake = MagicMock()

            ctx.wrap_socket(raw_sock, server_hostname="example.com")
            MockSock.assert_called_once()
            call_kwargs = MockSock.call_args
            assert call_kwargs.kwargs["server_hostname"] == "example.com"

    def test_wrap_socket_requires_hostname(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        raw_sock = MagicMock(spec=socket.socket)
        with pytest.raises(SchannelError, match="server_hostname"):
            ctx.wrap_socket(raw_sock)

    def test_wrap_socket_rejects_server_side(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        raw_sock = MagicMock(spec=socket.socket)
        with pytest.raises(SchannelError, match="[Ss]erver"):
            ctx.wrap_socket(raw_sock, server_side=True, server_hostname="host")

    def test_wrap_socket_uses_mtls_flags_with_thumbprint(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        ctx.client_cert_thumbprint = "AABB"
        raw_sock = MagicMock(spec=socket.socket)

        with patch("requests_schannel.context.SchannelSocket") as MockSock:
            with patch.object(ctx, "_resolve_client_cert", return_value=None):
                MockSock.return_value = MagicMock()
                MockSock.return_value.do_handshake = MagicMock()
                ctx.wrap_socket(raw_sock, server_hostname="host")

                call_kwargs = MockSock.call_args
                flags = call_kwargs.kwargs["flags"]
                assert flags & ISC_REQ_TLS_CLIENT_MTLS

    def test_wrap_socket_reuses_credential(self, mock_backend: MagicMock) -> None:
        """Credential handle should be created once and reused."""
        ctx = SchannelContext(backend=mock_backend)
        raw_sock1 = MagicMock(spec=socket.socket)
        raw_sock2 = MagicMock(spec=socket.socket)

        with patch("requests_schannel.context.SchannelSocket") as MockSock:
            MockSock.return_value = MagicMock()
            MockSock.return_value.do_handshake = MagicMock()

            ctx.wrap_socket(raw_sock1, server_hostname="host")
            ctx.wrap_socket(raw_sock2, server_hostname="host")

            # acquire_credentials should only be called once
            assert mock_backend.acquire_credentials.call_count == 1

    def test_wrap_socket_no_handshake_on_connect_false(self, mock_backend: MagicMock) -> None:
        ctx = SchannelContext(backend=mock_backend)
        raw_sock = MagicMock(spec=socket.socket)

        with patch("requests_schannel.context.SchannelSocket") as MockSock:
            mock_ss = MagicMock()
            MockSock.return_value = mock_ss

            ctx.wrap_socket(raw_sock, server_hostname="host", do_handshake_on_connect=False)
            mock_ss.do_handshake.assert_not_called()
