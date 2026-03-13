"""Tests for certificate store operations (mocked)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from requests_schannel._errors import CertificateNotFoundError
from requests_schannel.backend import CertInfo, CertStore


@pytest.mark.unit
class TestCertStoreInterface:
    """Test the CertStore abstract interface."""

    def test_cannot_instantiate(self) -> None:
        with pytest.raises(TypeError, match="abstract"):
            CertStore()  # type: ignore[abstract]


@pytest.mark.unit
class TestCertStoreOperations:
    """Test cert store operations via mock."""

    def _make_mock_store(self) -> MagicMock:
        store = MagicMock(spec=CertStore)
        store.open.return_value = "store_handle"
        store.find_by_thumbprint.return_value = "cert_context"
        store.find_by_subject.return_value = "cert_context"
        store.enumerate.return_value = [
            CertInfo(
                thumbprint="AABB",
                subject="CN=Test",
                issuer="CN=CA",
                friendly_name="Test",
                not_before=0.0,
                not_after=1e10,
                has_private_key=True,
                serial_number="01",
                der_encoded=b"\x30",
            )
        ]
        return store

    def test_open_store(self) -> None:
        store = self._make_mock_store()
        handle = store.open("MY", False)
        store.open.assert_called_once_with("MY", False)
        assert handle == "store_handle"

    def test_find_by_thumbprint(self) -> None:
        store = self._make_mock_store()
        handle = store.open("MY", False)
        cert = store.find_by_thumbprint(handle, "AABB")
        store.find_by_thumbprint.assert_called_once_with(handle, "AABB")
        assert cert == "cert_context"

    def test_find_by_subject(self) -> None:
        store = self._make_mock_store()
        handle = store.open("MY", False)
        cert = store.find_by_subject(handle, "CN=Test")
        store.find_by_subject.assert_called_once_with(handle, "CN=Test")
        assert cert == "cert_context"

    def test_enumerate_certificates(self) -> None:
        store = self._make_mock_store()
        handle = store.open("MY", False)
        certs = store.enumerate(handle)
        assert len(certs) == 1
        assert certs[0].thumbprint == "AABB"
        assert certs[0].has_private_key is True

    def test_find_by_thumbprint_not_found(self) -> None:
        store = self._make_mock_store()
        store.find_by_thumbprint.side_effect = CertificateNotFoundError("Not found")
        handle = store.open("MY", False)

        with pytest.raises(CertificateNotFoundError):
            store.find_by_thumbprint(handle, "NONEXISTENT")

    def test_close_store(self) -> None:
        store = self._make_mock_store()
        handle = store.open("MY", False)
        store.close(handle)
        store.close.assert_called_once_with(handle)

    def test_store_lifecycle(self) -> None:
        """Open → enumerate → close lifecycle."""
        store = self._make_mock_store()
        handle = store.open("MY", False)
        certs = store.enumerate(handle)
        store.close(handle)

        assert len(certs) == 1
        store.open.assert_called_once()
        store.enumerate.assert_called_once()
        store.close.assert_called_once()
