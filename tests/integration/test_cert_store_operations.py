"""Integration tests for Windows certificate store operations."""

from __future__ import annotations

import sys

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestCertStoreOperations:
    """Test real Windows certificate store operations."""

    def test_open_my_store(self) -> None:
        """Open the CurrentUser\\MY store."""
        from requests_schannel.backends import get_cert_store

        store = get_cert_store()
        handle = store.open("MY", machine=False)
        assert handle is not None
        store.close(handle)

    def test_enum_certificates(self) -> None:
        """Enumerate certificates in MY store."""
        from requests_schannel.backends import get_cert_store

        store = get_cert_store()
        handle = store.open("MY", machine=False)
        try:
            certs = store.enumerate(handle)
            # MY store may be empty, but should return a list
            assert isinstance(certs, list)
        finally:
            store.close(handle)

    def test_find_by_thumbprint_with_test_cert(self, tls_certs: object) -> None:
        """Find test client cert by thumbprint."""
        from requests_schannel.backends import get_cert_store

        store = get_cert_store()
        handle = store.open("MY", machine=False)
        try:
            cert = store.find_by_thumbprint(
                handle, tls_certs.client_thumbprint  # type: ignore[attr-defined]
            )
            assert cert is not None
        finally:
            store.close(handle)

    def test_find_nonexistent_thumbprint(self) -> None:
        """Finding a nonexistent cert should raise."""
        from requests_schannel._errors import CertificateNotFoundError
        from requests_schannel.backends import get_cert_store

        store = get_cert_store()
        handle = store.open("MY", machine=False)
        try:
            with pytest.raises(CertificateNotFoundError):
                store.find_by_thumbprint(handle, "0" * 40)
        finally:
            store.close(handle)

    def test_find_by_subject(self, tls_certs: object) -> None:
        """Find test cert by subject."""
        from requests_schannel.backends import get_cert_store

        store = get_cert_store()
        handle = store.open("MY", machine=False)
        try:
            cert = store.find_by_subject(handle, "Test Client")
            assert cert is not None
        finally:
            store.close(handle)
