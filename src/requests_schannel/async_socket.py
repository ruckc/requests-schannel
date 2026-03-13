"""Async TLS socket wrapper for use with asyncio and websockets.

Wraps SchannelSocket with asyncio event loop integration so that
blocking handshake/read/write operations run in an executor.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any

from .context import SchannelContext
from .socket import SchannelSocket


class AsyncSchannelSocket:
    """Async wrapper around SchannelSocket for asyncio integration.

    Performs blocking SChannel operations (handshake, decrypt, encrypt)
    in a thread-pool executor so they don't block the event loop.

    Usage::

        ctx = SchannelContext()
        async_sock = await AsyncSchannelSocket.connect(
            "example.com", 443, ctx
        )
        await async_sock.send(b"data")
        data = await async_sock.recv(4096)
        await async_sock.close()
    """

    def __init__(
        self,
        schannel_socket: SchannelSocket,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        self._sock = schannel_socket
        self._loop = loop or asyncio.get_running_loop()

    @classmethod
    async def connect(
        cls,
        host: str,
        port: int,
        context: SchannelContext,
        *,
        server_hostname: str | None = None,
        timeout: float | None = 30.0,
    ) -> AsyncSchannelSocket:
        """Create a TLS connection using SChannel.

        Opens a TCP socket, wraps it with SChannel TLS, and performs
        the handshake — all without blocking the event loop.
        """
        loop = asyncio.get_running_loop()
        hostname = server_hostname or host

        # Create and connect raw socket in executor
        def _create_and_connect() -> SchannelSocket:
            raw_sock = socket.create_connection((host, port), timeout=timeout)
            raw_sock.settimeout(timeout)
            return context.wrap_socket(
                raw_sock,
                server_hostname=hostname,
                do_handshake_on_connect=True,
            )

        schannel_sock = await loop.run_in_executor(None, _create_and_connect)
        return cls(schannel_sock, loop)

    @classmethod
    async def wrap(
        cls,
        sock: socket.socket,
        context: SchannelContext,
        server_hostname: str,
    ) -> AsyncSchannelSocket:
        """Wrap an existing connected socket with SChannel TLS."""
        loop = asyncio.get_running_loop()

        def _wrap_and_handshake() -> SchannelSocket:
            return context.wrap_socket(
                sock,
                server_hostname=server_hostname,
                do_handshake_on_connect=True,
            )

        schannel_sock = await loop.run_in_executor(None, _wrap_and_handshake)
        return cls(schannel_sock, loop)

    async def recv(self, bufsize: int = 4096) -> bytes:
        """Receive decrypted data."""
        return await self._loop.run_in_executor(None, self._sock.recv, bufsize)

    async def send(self, data: bytes) -> int:
        """Send data through the TLS connection."""
        return await self._loop.run_in_executor(None, self._sock.send, data)

    async def close(self) -> None:
        """Close the TLS connection."""
        await self._loop.run_in_executor(None, self._sock.close)

    def selected_alpn_protocol(self) -> str | None:
        """Get the ALPN-negotiated protocol."""
        return self._sock.selected_alpn_protocol()

    def cipher(self) -> tuple[str, str, int] | None:
        """Get current cipher information."""
        return self._sock.cipher()

    def version(self) -> str | None:
        """Get TLS version string."""
        return self._sock.version()

    @property
    def server_hostname(self) -> str:
        return self._sock.server_hostname

    @property
    def underlying_socket(self) -> SchannelSocket:
        """Access to the underlying SchannelSocket."""
        return self._sock

    async def __aenter__(self) -> AsyncSchannelSocket:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
