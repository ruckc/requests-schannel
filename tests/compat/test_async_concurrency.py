"""Concurrency tests: asyncio.gather with AsyncSchannelTransport.

Mirrors ``test_concurrency.py`` for the async httpx transport, verifying
that multiple concurrent async HTTPS requests work correctly.
"""

from __future__ import annotations

import asyncio
import ssl
import sys

import pytest

pytestmark = [
    pytest.mark.compat,
    pytest.mark.slow,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestAsyncConcurrency:
    """Verify concurrent async requests via AsyncSchannelTransport."""

    @pytest.mark.timeout(60)
    async def test_concurrent_requests_shared_client(
        self, tls_test_server: tuple[str, int]
    ) -> None:
        """Multiple concurrent requests on a single async client."""
        from requests_schannel.httpx_transport import AsyncSchannelTransport

        import httpx

        _, port = tls_test_server
        url = f"https://localhost:{port}/"
        num_requests = 10

        transport = AsyncSchannelTransport()
        transport.schannel_context.verify_mode = ssl.CERT_NONE

        async with httpx.AsyncClient(
            transport=transport, verify=False
        ) as client:

            async def _do_request() -> int:
                resp = await client.get(url)
                return resp.status_code

            results = await asyncio.gather(
                *[_do_request() for _ in range(num_requests)]
            )

        assert len(results) == num_requests
        assert all(status == 200 for status in results)

    @pytest.mark.timeout(60)
    async def test_concurrent_requests_separate_clients(
        self, tls_test_server: tuple[str, int]
    ) -> None:
        """Each task creates its own async client and transport."""
        _, port = tls_test_server
        url = f"https://localhost:{port}/"
        num_requests = 5

        async def _do_request() -> int:
            from requests_schannel.httpx_transport import AsyncSchannelTransport

            import httpx

            transport = AsyncSchannelTransport()
            transport.schannel_context.verify_mode = ssl.CERT_NONE
            async with httpx.AsyncClient(
                transport=transport, verify=False
            ) as client:
                resp = await client.get(url)
                return resp.status_code

        results = await asyncio.gather(
            *[_do_request() for _ in range(num_requests)]
        )

        assert len(results) == num_requests
        assert all(status == 200 for status in results)
