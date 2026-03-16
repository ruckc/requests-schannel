"""Compatibility tests: websockets with SChannel TLS."""

from __future__ import annotations

import socket
import ssl
import sys

import pytest

pytestmark = [
    pytest.mark.compat,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestWebsocketsConnect:
    """Test websocket connections via SChannel TLS + websockets sync client."""

    @pytest.mark.timeout(30)
    def test_connect_local_echo_server(self, wss_echo_server: tuple[str, int]) -> None:
        """Connect to a local websocket echo server via SChannel TLS."""
        try:
            from websockets.sync.client import connect
        except ImportError:
            pytest.skip("websockets not installed")

        from requests_schannel.context import SchannelContext

        host, port = wss_echo_server
        ctx = SchannelContext()
        ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.create_connection((host, port), timeout=10)
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)

        ws = connect(f"ws://{host}:{port}/", sock=tls_sock)
        try:
            ws.send("hello from schannel")
            response = ws.recv(timeout=10)
            assert response == "hello from schannel"
        finally:
            ws.close()
