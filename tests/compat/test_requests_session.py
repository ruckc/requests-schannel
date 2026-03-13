"""Compatibility tests: requests.Session with SchannelAdapter."""

from __future__ import annotations

import sys

import pytest

pytestmark = [
    pytest.mark.compat,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestRequestsSession:
    """Test full requests.Session with SchannelAdapter mounted."""

    def test_get_request(self, tls_test_server: tuple[str, int]) -> None:
        """GET request via requests + SchannelAdapter."""
        import ssl

        import requests

        from requests_schannel.adapters import SchannelAdapter

        host, port = tls_test_server
        session = requests.Session()
        adapter = SchannelAdapter()
        adapter.schannel_context.verify_mode = ssl.CERT_NONE
        session.mount("https://", adapter)

        resp = session.get(f"https://localhost:{port}/")
        assert resp.status_code == 200
        assert resp.text == "OK"
        session.close()

    def test_post_request(self, tls_test_server: tuple[str, int]) -> None:
        """POST request with body."""
        import ssl

        import requests

        from requests_schannel.adapters import SchannelAdapter

        host, port = tls_test_server
        session = requests.Session()
        adapter = SchannelAdapter()
        adapter.schannel_context.verify_mode = ssl.CERT_NONE
        session.mount("https://", adapter)

        resp = session.post(f"https://localhost:{port}/", data=b"hello")
        assert resp.status_code == 200
        assert resp.content == b"hello"
        session.close()

    def test_session_reuse(self, tls_test_server: tuple[str, int]) -> None:
        """Multiple requests on same session (connection pool)."""
        import ssl

        import requests

        from requests_schannel.adapters import SchannelAdapter

        host, port = tls_test_server
        session = requests.Session()
        adapter = SchannelAdapter()
        adapter.schannel_context.verify_mode = ssl.CERT_NONE
        session.mount("https://", adapter)

        for _ in range(3):
            resp = session.get(f"https://localhost:{port}/")
            assert resp.status_code == 200
        session.close()


class TestCreateSessionFactory:
    """Test create_session() convenience function."""

    def test_create_session(self, tls_test_server: tuple[str, int]) -> None:
        """create_session() returns a working session."""
        import ssl

        from requests_schannel.adapters import create_session

        host, port = tls_test_server
        session = create_session()
        # Need to disable verification for self-signed certs
        adapter = session.get_adapter(f"https://localhost:{port}/")
        adapter.schannel_context.verify_mode = ssl.CERT_NONE

        resp = session.get(f"https://localhost:{port}/")
        assert resp.status_code == 200
        session.close()
