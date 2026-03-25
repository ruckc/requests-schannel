"""websockets integration — connect helper using SChannel TLS."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlparse

from .context import SchannelContext
from .socket import SchannelSocket

try:
    from websockets.asyncio.client import ClientConnection, connect
except ImportError as exc:
    raise ImportError(
        "websockets is required for schannel_connect. "
        "Install with: pip install requests-schannel[websockets]"
    ) from exc


@asynccontextmanager
async def schannel_connect(
    uri: str,
    *,
    context: SchannelContext | None = None,
    client_cert_thumbprint: str | None = None,
    client_cert_subject: str | None = None,
    auto_select_client_cert: bool = False,
    cert_store_name: str = "MY",
    backend: str | None = None,
    timeout: float | None = 30.0,
    additional_headers: dict[str, str] | None = None,
    **ws_kwargs: Any,
) -> AsyncIterator[ClientConnection]:
    """Connect to a WebSocket server using SChannel TLS.

    Performs the SChannel TLS handshake on a raw socket, then passes the
    pre-handshaked socket to websockets with ``ssl=None`` (TLS already done).

    Usage::

        from requests_schannel.ws import schannel_connect

        async with schannel_connect("wss://example.com/ws") as ws:
            await ws.send("hello")
            response = await ws.recv()
    """
    parsed = urlparse(uri)

    if parsed.scheme not in ("ws", "wss"):
        raise ValueError(f"Unsupported scheme: {parsed.scheme!r} (expected 'ws' or 'wss')")

    use_tls = parsed.scheme == "wss"
    host = parsed.hostname or "localhost"
    default_port = 443 if use_tls else 80
    port = parsed.port or default_port

    if use_tls:
        # Build or use provided SchannelContext
        ctx = context or _build_context(
            client_cert_thumbprint=client_cert_thumbprint,
            client_cert_subject=client_cert_subject,
            auto_select_client_cert=auto_select_client_cert,
            cert_store_name=cert_store_name,
            backend=backend,
        )

        loop = asyncio.get_running_loop()

        # Perform TCP connect + SChannel TLS handshake in executor
        def _connect_tls() -> SchannelSocket:
            raw_sock = socket.create_connection((host, port), timeout=timeout)
            raw_sock.settimeout(timeout)
            schannel_sock = ctx.wrap_socket(
                raw_sock,
                server_hostname=host,
                do_handshake_on_connect=True,
            )
            return schannel_sock

        tls_sock = await loop.run_in_executor(None, _connect_tls)

        # SchannelSocket is blocking-only: its recv/send do SChannel
        # encrypt/decrypt that require full TLS record reads. asyncio's
        # create_connection() sets sockets non-blocking, which breaks
        # SChannel's record processing. Bridge with a local socketpair:
        #   websockets ↔ b_sock ↔ a_sock ↔ (relay via executor) ↔ tls_sock ↔ network
        a_sock, b_sock = socket.socketpair()

        async def _relay_outbound() -> None:
            """Forward websockets writes → SChannel encrypt → network."""
            try:
                while True:
                    data = await loop.run_in_executor(None, a_sock.recv, 65536)
                    if not data:
                        break
                    await loop.run_in_executor(None, tls_sock.send, data)
            except OSError:
                pass

        async def _relay_inbound() -> None:
            """Forward network → SChannel decrypt → websockets reads."""
            try:
                while True:
                    data = await loop.run_in_executor(None, tls_sock.recv, 65536)
                    if not data:
                        try:
                            a_sock.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        break
                    await loop.run_in_executor(None, a_sock.sendall, data)
            except OSError:
                pass

        relay_tasks = [
            asyncio.create_task(_relay_outbound()),
            asyncio.create_task(_relay_inbound()),
        ]

        # Build the websocket URI with ws:// since TLS is already handled
        ws_uri = f"ws://{host}:{port}{parsed.path or '/'}"
        if parsed.query:
            ws_uri += f"?{parsed.query}"

        try:
            # Pass the plain b_sock to websockets (asyncio-compatible)
            async with connect(
                ws_uri,
                sock=b_sock,
                additional_headers=additional_headers,
                **ws_kwargs,
            ) as ws_conn:
                yield ws_conn
        finally:
            for t in relay_tasks:
                t.cancel()
            # Close both relay ends to unblock executor threads
            for s in (a_sock, tls_sock):
                try:
                    s.close()
                except OSError:
                    pass
            await asyncio.gather(*relay_tasks, return_exceptions=True)
    else:
        # Plain WS — no TLS, delegate entirely to websockets
        async with connect(
            uri,
            additional_headers=additional_headers,
            **ws_kwargs,
        ) as ws_conn:
            yield ws_conn


def _build_context(
    client_cert_thumbprint: str | None,
    client_cert_subject: str | None,
    auto_select_client_cert: bool,
    cert_store_name: str,
    backend: str | None,
) -> SchannelContext:
    ctx = SchannelContext(backend=backend)
    if client_cert_thumbprint:
        ctx.client_cert_thumbprint = client_cert_thumbprint
    if client_cert_subject:
        ctx.client_cert_subject = client_cert_subject
    ctx.auto_select_client_cert = auto_select_client_cert
    ctx.cert_store_name = cert_store_name
    return ctx
