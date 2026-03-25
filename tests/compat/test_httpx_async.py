"""Compatibility tests: httpx.AsyncClient with AsyncSchannelTransport.

Mirrors ``test_requests_session.py`` for the async httpx transport.
"""

from __future__ import annotations

import ssl
import sys

import pytest

pytestmark = [
    pytest.mark.compat,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestAsyncHttpxClient:
    """Test httpx.AsyncClient with AsyncSchannelTransport against a local HTTPS server."""

    @pytest.mark.timeout(30)
    async def test_get_request(self, tls_test_server: tuple[str, int]) -> None:
        """GET request via async httpx + AsyncSchannelTransport."""
        import httpx

        from requests_schannel.httpx_transport import AsyncSchannelTransport

        host, port = tls_test_server
        transport = AsyncSchannelTransport()
        transport.schannel_context.verify_mode = ssl.CERT_NONE

        async with httpx.AsyncClient(transport=transport, verify=False) as client:
            resp = await client.get(f"https://localhost:{port}/")
            assert resp.status_code == 200
            assert resp.text == "OK"

    @pytest.mark.timeout(30)
    async def test_post_request(self, tls_test_server: tuple[str, int]) -> None:
        """POST request with body via async httpx."""
        import httpx

        from requests_schannel.httpx_transport import AsyncSchannelTransport

        host, port = tls_test_server
        transport = AsyncSchannelTransport()
        transport.schannel_context.verify_mode = ssl.CERT_NONE

        async with httpx.AsyncClient(transport=transport, verify=False) as client:
            resp = await client.post(f"https://localhost:{port}/", content=b"hello")
            assert resp.status_code == 200
            assert resp.content == b"hello"

    @pytest.mark.timeout(30)
    async def test_session_reuse(self, tls_test_server: tuple[str, int]) -> None:
        """Multiple requests on same async client (connection pool)."""
        import httpx

        from requests_schannel.httpx_transport import AsyncSchannelTransport

        host, port = tls_test_server
        transport = AsyncSchannelTransport()
        transport.schannel_context.verify_mode = ssl.CERT_NONE

        async with httpx.AsyncClient(transport=transport, verify=False) as client:
            for _ in range(3):
                resp = await client.get(f"https://localhost:{port}/")
                assert resp.status_code == 200

    @pytest.mark.timeout(30)
    async def test_streaming_response(self, tls_test_server: tuple[str, int]) -> None:
        """Stream a response body via async httpx."""
        import httpx

        from requests_schannel.httpx_transport import AsyncSchannelTransport

        host, port = tls_test_server
        transport = AsyncSchannelTransport()
        transport.schannel_context.verify_mode = ssl.CERT_NONE

        async with httpx.AsyncClient(transport=transport, verify=False) as client:
            async with client.stream("GET", f"https://localhost:{port}/") as resp:
                assert resp.status_code == 200
                body = b""
                async for chunk in resp.aiter_bytes():
                    body += chunk
                assert body == b"OK"


class TestCreateAsyncHttpxClientFactory:
    """Test create_async_httpx_client() convenience function."""

    @pytest.mark.timeout(30)
    async def test_create_async_httpx_client(self, tls_test_server: tuple[str, int]) -> None:
        """Factory returns a working async client."""
        from requests_schannel.httpx_transport import create_async_httpx_client

        host, port = tls_test_server
        client = create_async_httpx_client()
        # Disable verification for self-signed certs
        client._transport.schannel_context.verify_mode = ssl.CERT_NONE

        async with client:
            resp = await client.get(f"https://localhost:{port}/")
            assert resp.status_code == 200
