"""Compatibility tests: direct urllib3.PoolManager with SchannelContext."""

from __future__ import annotations

import sys

import pytest

pytestmark = [
    pytest.mark.compat,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestUrllib3Direct:
    """Test urllib3 directly with SchannelContext as ssl_context."""

    def test_poolmanager_with_schannel_context(
        self, tls_test_server: tuple[str, int]
    ) -> None:
        """Use SchannelContext directly with urllib3.PoolManager."""
        import ssl

        import urllib3

        from requests_schannel.context import SchannelContext

        host, port = tls_test_server
        ctx = SchannelContext()
        ctx.verify_mode = ssl.CERT_NONE

        pool = urllib3.PoolManager(ssl_context=ctx)
        try:
            resp = pool.request("GET", f"https://localhost:{port}/")
            assert resp.status == 200
            assert resp.data == b"OK"
        finally:
            pool.clear()
