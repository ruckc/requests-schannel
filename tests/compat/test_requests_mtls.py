"""Compatibility tests: requests with mTLS via SchannelAdapter."""

from __future__ import annotations

import sys

import pytest

pytestmark = [
    pytest.mark.compat,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestRequestsMtls:
    """Test requests.Session with client cert authentication."""

    def test_get_with_client_cert_thumbprint(
        self, tls_test_server: tuple[str, int], tls_certs: object
    ) -> None:
        """GET with client cert via thumbprint."""
        import ssl

        import requests

        from requests_schannel.adapters import SchannelAdapter

        host, port = tls_test_server
        session = requests.Session()
        adapter = SchannelAdapter(
            client_cert_thumbprint=tls_certs.client_thumbprint  # type: ignore[attr-defined]
        )
        adapter.schannel_context.verify_mode = ssl.CERT_NONE
        session.mount("https://", adapter)

        resp = session.get(f"https://localhost:{port}/")
        assert resp.status_code == 200
        session.close()

    def test_get_with_client_cert_subject(
        self, tls_test_server: tuple[str, int], tls_certs: object
    ) -> None:
        """GET with client cert via subject name."""
        import ssl

        import requests

        from requests_schannel.adapters import SchannelAdapter

        host, port = tls_test_server
        session = requests.Session()
        adapter = SchannelAdapter(client_cert_subject="Test Client")
        adapter.schannel_context.verify_mode = ssl.CERT_NONE
        session.mount("https://", adapter)

        resp = session.get(f"https://localhost:{port}/")
        assert resp.status_code == 200
        session.close()
