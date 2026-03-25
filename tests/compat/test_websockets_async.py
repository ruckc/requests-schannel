"""Compatibility tests: websockets async client with SChannel TLS via schannel_connect.

Mirrors ``test_websockets.py`` for the async schannel_connect() helper.
"""

from __future__ import annotations

import ssl
import sys
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from requests_schannel.context import SchannelContext

pytestmark = [
    pytest.mark.compat,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestSchannelConnect:
    """Test schannel_connect() against a local WSS echo server."""

    @pytest.mark.timeout(30)
    async def test_connect_and_echo(
        self, wss_echo_server: tuple[str, int]
    ) -> None:
        """Connect to local WSS echo server via schannel_connect, send and receive."""
        from requests_schannel.ws import schannel_connect

        host, port = wss_echo_server

        async with schannel_connect(
            f"wss://{host}:{port}/",
            context=self._no_verify_context(),
        ) as ws:
            await ws.send("hello from async schannel")
            response = await ws.recv()
            assert response == "hello from async schannel"

    @pytest.mark.timeout(30)
    async def test_multiple_messages(
        self, wss_echo_server: tuple[str, int]
    ) -> None:
        """Send and receive multiple messages on a single connection."""
        from requests_schannel.ws import schannel_connect

        host, port = wss_echo_server

        async with schannel_connect(
            f"wss://{host}:{port}/",
            context=self._no_verify_context(),
        ) as ws:
            for i in range(5):
                msg = f"message {i}"
                await ws.send(msg)
                response = await ws.recv()
                assert response == msg

    @pytest.mark.timeout(30)
    async def test_binary_message(
        self, wss_echo_server: tuple[str, int]
    ) -> None:
        """Send and receive binary data."""
        from requests_schannel.ws import schannel_connect

        host, port = wss_echo_server

        async with schannel_connect(
            f"wss://{host}:{port}/",
            context=self._no_verify_context(),
        ) as ws:
            data = b"\x00\x01\x02\xff"
            await ws.send(data)
            response = await ws.recv()
            assert response == data

    @pytest.mark.timeout(30)
    async def test_connect_with_backend(
        self, wss_echo_server: tuple[str, int], backend_name: str
    ) -> None:
        """Connect using an explicit backend selection."""
        from requests_schannel.context import SchannelContext
        from requests_schannel.ws import schannel_connect

        host, port = wss_echo_server
        ctx = SchannelContext(backend=backend_name)
        ctx.verify_mode = ssl.CERT_NONE

        async with schannel_connect(
            f"wss://{host}:{port}/",
            context=ctx,
        ) as ws:
            await ws.send("backend test")
            response = await ws.recv()
            assert response == "backend test"

    @staticmethod
    def _no_verify_context() -> SchannelContext:
        """Create a SchannelContext with CERT_NONE for self-signed certs."""
        from requests_schannel.context import SchannelContext

        ctx = SchannelContext()
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
