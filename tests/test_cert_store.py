"""
Tests for the Windows Certificate Store integration (_cert_store.py).

Platform notes
--------------
Tests that call into the Windows CryptoAPI are marked ``requires_windows``
and will be skipped automatically on Linux / macOS.  The pure-Python helpers
(thumbprint parsing, exception hierarchy, etc.) are tested on all platforms.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from requests_schannel._cert_store import CertStore, CertContext, _parse_thumbprint
from requests_schannel.exceptions import (
    CertNotFoundError,
    CertStoreError,
    SchannelError,
)
from tests.conftest import requires_windows


# ---------------------------------------------------------------------------
# _parse_thumbprint – platform-independent
# ---------------------------------------------------------------------------


class TestParseThumbprint:
    def test_colon_separated(self):
        raw = _parse_thumbprint("AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD")
        assert raw == bytes.fromhex("AABBCCDDEEFF00112233445566778899AABBCCDD")

    def test_no_separator(self):
        raw = _parse_thumbprint("AABBCCDDEEFF00112233445566778899AABBCCDD")
        assert raw == bytes.fromhex("AABBCCDDEEFF00112233445566778899AABBCCDD")

    def test_lowercase(self):
        raw = _parse_thumbprint("aabbccddeeff00112233445566778899aabbccdd")
        assert raw == bytes.fromhex("AABBCCDDEEFF00112233445566778899AABBCCDD")

    def test_space_separated(self):
        raw = _parse_thumbprint("AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB CC DD")
        assert raw == bytes.fromhex("AABBCCDDEEFF00112233445566778899AABBCCDD")

    def test_invalid_length_raises(self):
        with pytest.raises(ValueError, match="Invalid SHA-1 thumbprint"):
            _parse_thumbprint("AABB")

    def test_invalid_hex_raises(self):
        with pytest.raises(ValueError):
            _parse_thumbprint("ZZ" * 20)


# ---------------------------------------------------------------------------
# Exception hierarchy – platform-independent
# ---------------------------------------------------------------------------


class TestExceptions:
    def test_schannel_error_str_with_code(self):
        err = SchannelError("handshake failed", error_code=0x80090308)
        assert "0x80090308" in str(err)
        assert "handshake failed" in str(err)

    def test_schannel_error_repr_with_code(self):
        err = SchannelError("handshake failed", error_code=0x80090308)
        assert "0x80090308" in repr(err)
        assert "handshake failed" in repr(err)

    def test_schannel_error_str_without_code(self):
        err = SchannelError("something went wrong")
        assert "something went wrong" in str(err)

    def test_schannel_error_repr_without_code(self):
        err = SchannelError("something went wrong")
        assert "something went wrong" in repr(err)

    def test_cert_store_error_str_with_code(self):
        err = CertStoreError("store open failed", error_code=5)
        assert "Win32 error 5" in str(err)

    def test_cert_not_found_is_cert_store_error(self):
        err = CertNotFoundError("not found")
        assert isinstance(err, CertStoreError)
        assert isinstance(err, OSError)

    def test_schannel_error_is_os_error(self):
        err = SchannelError("err")
        assert isinstance(err, OSError)


# ---------------------------------------------------------------------------
# CertContext – lightweight / mock-based (platform-independent)
# ---------------------------------------------------------------------------


class TestCertContextMock:
    """Tests that do not require a real Windows CERT_CONTEXT."""

    def test_null_handle_raises(self):
        with pytest.raises(CertStoreError, match="NULL"):
            CertContext(0)

    def test_close_idempotent(self):
        # Patch crypt32 so we don't need Windows
        with patch("requests_schannel._cert_store.sys") as mock_sys:
            mock_sys.platform = "linux"  # pretend non-Windows
            ctx = CertContext.__new__(CertContext)
            ctx._handle = 1
            ctx._closed = False
            ctx.close()
            ctx.close()  # second call must not raise

    def test_repr(self):
        with patch("requests_schannel._cert_store.sys") as mock_sys:
            mock_sys.platform = "linux"
            ctx = CertContext.__new__(CertContext)
            ctx._handle = 1
            ctx._closed = False
            r = repr(ctx)
            assert "CertContext" in r
            # Mark closed before the mock exits so __del__ does not call the
            # real CertFreeCertificateContext with a fake pointer value later.
            ctx._closed = True

    def test_access_after_close_raises(self):
        with patch("requests_schannel._cert_store.sys") as mock_sys:
            mock_sys.platform = "linux"
            ctx = CertContext.__new__(CertContext)
            ctx._handle = 1
            ctx._closed = True
            with pytest.raises(CertStoreError, match="closed"):
                _ = ctx.handle

    def test_context_manager(self):
        """__enter__ returns self; __exit__ calls close."""
        with patch("requests_schannel._cert_store.sys") as mock_sys:
            mock_sys.platform = "linux"
            ctx = CertContext.__new__(CertContext)
            ctx._handle = 99
            ctx._closed = False
            with ctx as c:
                assert c is ctx
            assert ctx._closed


# ---------------------------------------------------------------------------
# CertStore – Windows-only integration tests
# ---------------------------------------------------------------------------


@requires_windows
class TestCertStoreWindows:
    def test_open_my_store(self):
        store = CertStore("MY", location="user")
        assert store.handle != 0
        store.close()

    def test_open_root_store(self):
        store = CertStore("ROOT", location="user")
        assert store.handle != 0
        store.close()

    def test_open_machine_store(self):
        store = CertStore("ROOT", location="machine")
        assert store.handle != 0
        store.close()

    def test_context_manager(self):
        with CertStore("MY") as store:
            assert store.handle != 0

    def test_close_idempotent(self):
        store = CertStore("MY")
        store.close()
        store.close()  # must not raise

    def test_find_nonexistent_thumbprint_raises(self):
        with CertStore("MY") as store:
            with pytest.raises(CertNotFoundError):
                store.find_by_thumbprint("00" * 20)

    def test_find_nonexistent_subject_raises(self):
        with CertStore("MY") as store:
            with pytest.raises(CertNotFoundError):
                store.find_by_subject("___NO_SUCH_SUBJECT_XYZ___")

    def test_iter_certs_returns_iterator(self):
        with CertStore("MY") as store:
            certs = list(store.iter_certs())
            # There may be zero or more certs; the call must not raise
            assert isinstance(certs, list)

    def test_find_by_thumbprint_after_install(self, windows_client_cert_thumbprint):
        """Find the test client cert that was installed by the session fixture."""
        with CertStore("MY") as store:
            ctx = store.find_by_thumbprint(windows_client_cert_thumbprint)
            assert ctx is not None
            assert ctx.thumbprint_hex == windows_client_cert_thumbprint
            ctx.close()

    def test_find_by_subject_after_install(self, windows_client_cert_thumbprint):
        """Find the test client cert by subject substring."""
        with CertStore("MY") as store:
            ctx = store.find_by_subject("Test Client")
            assert ctx is not None
            ctx.close()

    def test_cert_context_thumbprint_property(self, windows_client_cert_thumbprint):
        with CertStore("MY") as store:
            ctx = store.find_by_thumbprint(windows_client_cert_thumbprint)
            tp_bytes = ctx.thumbprint
            assert len(tp_bytes) == 20
            assert ctx.thumbprint_hex == windows_client_cert_thumbprint
            ctx.close()
