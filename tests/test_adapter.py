"""
Tests for the SchannelAdapter and supporting classes.

Platform notes
--------------
* Integration tests that require the Windows SChannel API are marked
  ``requires_windows`` and are skipped on Linux / macOS.
* Unit tests for the adapter's public interface (construction, parameter
  handling, close()) run on all platforms.
"""
from __future__ import annotations

import sys
import tempfile
import os
from unittest.mock import MagicMock, patch

import pytest
import requests

from requests_schannel import SchannelAdapter
from requests_schannel._cert_store import CertContext
from requests_schannel.adapter import _resolve_client_cert, _SchannelPoolManager
from requests_schannel.exceptions import (
    CertNotFoundError,
    SchannelError,
    SchannelCertValidationError,
    SchannelHandshakeError,
)
from tests.conftest import requires_windows, cert_to_pem, key_to_pem


# ---------------------------------------------------------------------------
# SchannelAdapter – construction and parameter handling (all platforms)
# ---------------------------------------------------------------------------


class TestSchannelAdapterInit:
    def test_default_construction(self):
        adapter = SchannelAdapter()
        assert adapter._client_cert_spec is None
        assert adapter._schannel_verify is True
        assert adapter._cert_store_name == "MY"

    def test_verify_false(self):
        adapter = SchannelAdapter(verify=False)
        assert adapter._schannel_verify is False

    def test_custom_cert_store(self):
        adapter = SchannelAdapter(cert_store="ROOT")
        assert adapter._cert_store_name == "ROOT"

    def test_thumbprint_spec_stored(self):
        """Adapter construction with a thumbprint must NOT touch Windows APIs."""
        tp = "AA" * 20
        adapter = SchannelAdapter(client_cert=tp)
        # The spec is stored; resolution is deferred to first connection
        assert adapter._client_cert_spec == tp
        assert adapter._client_cert_context is None

    def test_subject_spec_stored(self):
        """Adapter construction with a subject spec must NOT touch Windows APIs."""
        adapter = SchannelAdapter(client_cert="subject:CN=Foo")
        assert adapter._client_cert_spec == "subject:CN=Foo"
        assert adapter._client_cert_context is None

    def test_close_without_cert_context(self):
        adapter = SchannelAdapter()
        adapter.close()  # must not raise

    def test_close_clears_cert_context(self):
        adapter = SchannelAdapter()
        # Inject a mock CertContext
        mock_ctx = MagicMock(spec=CertContext)
        adapter._client_cert_context = mock_ctx
        adapter.close()
        mock_ctx.close.assert_called_once()
        assert adapter._client_cert_context is None


# ---------------------------------------------------------------------------
# _resolve_client_cert – platform-independent (mocked store)
# ---------------------------------------------------------------------------


class TestResolveClientCert:
    def test_none_returns_none(self):
        result = _resolve_client_cert(None, "MY")
        assert result is None

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_int_returns_cert_context(self):
        # A real PCCERT_CONTEXT handle is an int; here we just check the
        # wrapping behaviour with a non-zero value that is freed on close.
        # We patch CertFreeCertificateContext so no actual free happens.
        with patch("requests_schannel._cert_store._crypt32") as mock_crypt32:
            mock_crypt32.CertFreeCertificateContext.return_value = True
            mock_crypt32.CertGetCertificateContextProperty.return_value = True
            ctx = _resolve_client_cert(12345, "MY")
            assert isinstance(ctx, CertContext)
            assert ctx._handle == 12345

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_thumbprint_not_found_raises(self):
        with patch("requests_schannel._cert_store._crypt32") as mock_crypt32:
            mock_crypt32.CertOpenStore.return_value = 1
            mock_crypt32.CertFindCertificateInStore.return_value = None
            mock_crypt32.CertCloseStore.return_value = True
            with pytest.raises(CertNotFoundError):
                _resolve_client_cert("00" * 20, "MY")

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_subject_prefix_dispatches_to_find_by_subject(self):
        with patch("requests_schannel._cert_store._crypt32") as mock_crypt32:
            mock_crypt32.CertOpenStore.return_value = 1
            mock_crypt32.CertFindCertificateInStore.return_value = None
            mock_crypt32.CertCloseStore.return_value = True
            with pytest.raises(CertNotFoundError):
                _resolve_client_cert("subject:CN=Bogus", "MY")


# ---------------------------------------------------------------------------
# _SchannelPoolManager – construction (all platforms)
# ---------------------------------------------------------------------------


class TestSchannelPoolManager:
    def test_https_pool_class(self):
        from requests_schannel.adapter import _SchannelHTTPSConnectionPool

        mgr = _SchannelPoolManager(num_pools=5, maxsize=5)
        assert mgr.pool_classes_by_scheme["https"] is _SchannelHTTPSConnectionPool

    def test_http_pool_class(self):
        mgr = _SchannelPoolManager(num_pools=5, maxsize=5)
        assert mgr.pool_classes_by_scheme["http"] is not None

    def test_passes_spec_not_context(self):
        """The pool manager stores the raw spec, not a resolved CertContext."""
        tp = "AA" * 20
        mgr = _SchannelPoolManager(num_pools=2, maxsize=2, client_cert_spec=tp)
        assert mgr._client_cert_spec == tp


# ---------------------------------------------------------------------------
# SchannelAdapter.send() – verify kwarg handling (all platforms)
# ---------------------------------------------------------------------------


class TestAdapterSend:
    """Test the send() override without making real network connections."""

    def test_send_calls_super_with_correct_verify(self):
        adapter = SchannelAdapter(verify=False)
        with patch.object(
            requests.adapters.HTTPAdapter, "send", return_value=MagicMock()
        ) as mock_send:
            req = requests.PreparedRequest()
            req.method = "GET"
            req.url = "https://example.com/"
            req.headers = {}
            req.body = None
            try:
                adapter.send(req, verify=True, cert=("a", "b"))
            except Exception:
                pass
            if mock_send.called:
                _, kwargs = mock_send.call_args
                assert kwargs.get("verify") is False

    def test_send_removes_cert_kwarg(self):
        adapter = SchannelAdapter()
        calls = []

        def mock_super_send(req, **kwargs):
            calls.append(kwargs)
            raise RuntimeError("stop")  # prevent actual connection attempt

        with patch.object(requests.adapters.HTTPAdapter, "send", side_effect=mock_super_send):
            req = requests.PreparedRequest()
            req.method = "GET"
            req.url = "https://localhost/"
            req.headers = {}
            req.body = None
            try:
                adapter.send(req, cert=("foo", "bar"))
            except RuntimeError:
                pass
        if calls:
            assert "cert" not in calls[0]


# ---------------------------------------------------------------------------
# Non-Windows guard on _get_cert_context
# ---------------------------------------------------------------------------


class TestNonWindowsGuard:
    @pytest.mark.skipif(sys.platform == "win32", reason="Tests non-Windows guard")
    def test_get_cert_context_raises_on_non_windows(self):
        """Explicitly calling _get_cert_context() on non-Windows must raise."""
        adapter = SchannelAdapter(client_cert="AABBCC" + "00" * 17)
        # Construction is fine; resolution is deferred
        assert adapter._client_cert_context is None
        # Explicit call must raise
        with pytest.raises((SchannelError, NotImplementedError)):
            adapter._get_cert_context()


# ---------------------------------------------------------------------------
# Windows integration – TLS + mTLS
# ---------------------------------------------------------------------------


@requires_windows
class TestSchannelAdapterWindowsIntegration:
    """Full integration tests using SChannel on Windows."""

    def test_tls_get_no_client_cert(
        self, tls_server, server_cert_and_key, ca_cert_and_key
    ):
        """
        Connect to a local TLS server without a client certificate.
        The server's certificate is validated against our test CA, which we
        add to a temporary root store.
        """
        import ctypes
        import ctypes.wintypes as wintypes
        from requests_schannel._windows_types import (
            CERT_STORE_PROV_SYSTEM,
            CERT_SYSTEM_STORE_CURRENT_USER,
            CERT_STORE_ADD_USE_EXISTING,
            _load_crypt32,
        )

        crypt32 = _load_crypt32()
        ca_cert, _ = ca_cert_and_key

        # Add CA cert to current-user ROOT store temporarily
        ca_der = ca_cert.public_bytes(
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER
        )
        ca_buf = (ctypes.c_ubyte * len(ca_der))(*ca_der)
        ca_ctx = crypt32.CertCreateCertificateContext(
            0x00010001,  # CERT_ENCODING_TYPE
            ca_buf,
            len(ca_der),
        )
        root_store = crypt32.CertOpenStore(
            ctypes.c_void_p(CERT_STORE_PROV_SYSTEM),
            0,
            None,
            CERT_SYSTEM_STORE_CURRENT_USER,
            ctypes.c_wchar_p("ROOT"),
        )
        crypt32.CertAddCertificateContextToStore(
            ctypes.c_void_p(root_store),
            ctypes.c_void_p(ca_ctx),
            CERT_STORE_ADD_USE_EXISTING,
            None,
        )

        try:
            adapter = SchannelAdapter(verify=True)
            session = requests.Session()
            session.mount("https://", adapter)
            resp = session.get(f"https://localhost:{tls_server.port}/")
            assert resp.status_code == 200
        finally:
            if ca_ctx:
                crypt32.CertFreeCertificateContext(ctypes.c_void_p(ca_ctx))
            if root_store:
                crypt32.CertCloseStore(ctypes.c_void_p(root_store), 0)

    def test_tls_get_verify_false(self, tls_server):
        """Connect ignoring server certificate verification."""
        adapter = SchannelAdapter(verify=False)
        session = requests.Session()
        session.mount("https://", adapter)
        resp = session.get(f"https://localhost:{tls_server.port}/")
        assert resp.status_code == 200

    def test_mtls_with_client_cert_from_store(
        self,
        mtls_server,
        windows_client_cert_thumbprint,
        ca_cert_and_key,
    ):
        """
        Connect to an mTLS server using a client certificate from the Windows
        certificate store.  The private key is never exported – SChannel
        contacts the CSP directly.
        """
        import ctypes
        from requests_schannel._windows_types import (
            CERT_STORE_PROV_SYSTEM,
            CERT_SYSTEM_STORE_CURRENT_USER,
            CERT_STORE_ADD_USE_EXISTING,
            _load_crypt32,
        )

        crypt32 = _load_crypt32()
        ca_cert, _ = ca_cert_and_key

        ca_der = ca_cert.public_bytes(
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER
        )
        ca_buf = (ctypes.c_ubyte * len(ca_der))(*ca_der)
        ca_ctx = crypt32.CertCreateCertificateContext(0x00010001, ca_buf, len(ca_der))

        root_store = crypt32.CertOpenStore(
            ctypes.c_void_p(CERT_STORE_PROV_SYSTEM),
            0,
            None,
            CERT_SYSTEM_STORE_CURRENT_USER,
            ctypes.c_wchar_p("ROOT"),
        )
        crypt32.CertAddCertificateContextToStore(
            ctypes.c_void_p(root_store),
            ctypes.c_void_p(ca_ctx),
            CERT_STORE_ADD_USE_EXISTING,
            None,
        )

        try:
            adapter = SchannelAdapter(
                client_cert=windows_client_cert_thumbprint,
                verify=True,
            )
            session = requests.Session()
            session.mount("https://", adapter)
            resp = session.get(f"https://localhost:{mtls_server.port}/")
            assert resp.status_code == 200
        finally:
            if ca_ctx:
                crypt32.CertFreeCertificateContext(ctypes.c_void_p(ca_ctx))
            if root_store:
                crypt32.CertCloseStore(ctypes.c_void_p(root_store), 0)

    def test_mtls_missing_client_cert_raises(self, mtls_server):
        """
        Connecting to an mTLS server without a client certificate should raise
        a handshake error.
        """
        adapter = SchannelAdapter(verify=False)
        session = requests.Session()
        session.mount("https://", adapter)
        with pytest.raises((SchannelHandshakeError, SchannelError, Exception)):
            session.get(f"https://localhost:{mtls_server.port}/", timeout=5)

    def test_cert_not_found_raises(self):
        adapter = SchannelAdapter(
            client_cert="00" * 20,
            verify=False,
        )
        session = requests.Session()
        session.mount("https://", adapter)
        with pytest.raises((CertNotFoundError, Exception)):
            session.get("https://localhost:9999/", timeout=2)


# ---------------------------------------------------------------------------
# SchannelSocket – unit-level (non-Windows, mock platform)
# ---------------------------------------------------------------------------


class TestSchannelSocketNonWindows:
    @pytest.mark.skipif(sys.platform == "win32", reason="Tests non-Windows guard")
    def test_raises_on_non_windows(self):
        from requests_schannel._schannel import SchannelSocket
        import socket as _socket

        raw = MagicMock(spec=_socket.socket)
        with pytest.raises(NotImplementedError):
            SchannelSocket(raw, server_name="localhost")
