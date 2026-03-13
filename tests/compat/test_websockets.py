"""Compatibility tests: websockets with SChannel TLS."""

from __future__ import annotations

import asyncio
import sys

import pytest

pytestmark = [
    pytest.mark.compat,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestWebsocketsConnect:
    """Test websocket connections via schannel_connect."""

    @pytest.mark.network
    @pytest.mark.timeout(30)
    async def test_connect_public_echo_server(self) -> None:
        """Connect to a public websocket echo server."""
        try:
            from requests_schannel.ws import schannel_connect
        except ImportError:
            pytest.skip("websockets not installed")

        import socket

        try:
            # Use a simple public echo server
            async with schannel_connect("wss://echo.websocket.events") as ws:
                await ws.send("hello from schannel")
                response = await asyncio.wait_for(ws.recv(), timeout=10)
                assert isinstance(response, (str, bytes))
        except socket.gaierror:
            pytest.skip("DNS resolution failed (network unavailable)")
