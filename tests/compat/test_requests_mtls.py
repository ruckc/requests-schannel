"""Compatibility tests: requests with mTLS via SchannelAdapter."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from tests.conftest import InstalledTestCerts

pytestmark = [
    pytest.mark.compat,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestRequestsMtls:
    """Test requests.Session with client cert authentication."""

    @pytest.mark.smartcard
    def test_get_with_client_cert_thumbprint(
        self,
        tls_test_server: tuple[str, int],
        smartcard_certs: InstalledTestCerts,
    ) -> None:
        """GET with client cert via thumbprint."""
        import requests

        from requests_schannel.adapters import SchannelAdapter

        host, port = tls_test_server
        session = requests.Session()
        adapter = SchannelAdapter(client_cert_thumbprint=smartcard_certs.client_thumbprint)
        session.mount("https://", adapter)
        resp = session.get(f"https://{host}:{port}/")
        assert resp.status_code == 200
        session.close()

    @pytest.mark.smartcard
    def test_get_with_client_cert_subject(
        self,
        tls_test_server: tuple[str, int],
        smartcard_certs: InstalledTestCerts,
    ) -> None:
        """GET with client cert via subject name."""
        import requests

        from requests_schannel.adapters import SchannelAdapter

        host, port = tls_test_server
        session = requests.Session()
        adapter = SchannelAdapter(client_cert_subject=smartcard_certs.client_subject)
        session.mount("https://", adapter)
        resp = session.get(f"https://{host}:{port}/")
        assert resp.status_code == 200
        session.close()
