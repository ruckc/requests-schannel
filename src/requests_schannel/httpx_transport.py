"""httpx integration — SChannel transports for sync and async HTTP clients.

Provides :class:`SchannelTransport` (sync) and :class:`AsyncSchannelTransport`
(async) that replace httpx's default OpenSSL-based TLS with Windows SChannel,
plus convenience factories :func:`create_httpx_client` and
:func:`create_async_httpx_client`.

Usage (sync)::

    from requests_schannel.httpx_transport import create_httpx_client

    client = create_httpx_client(client_cert_thumbprint="AB12CD...")
    resp = client.get("https://example.com")

Usage (async)::

    from requests_schannel.httpx_transport import create_async_httpx_client

    async with create_async_httpx_client() as client:
        resp = await client.get("https://example.com")
"""

from __future__ import annotations

import asyncio
import socket
import typing

from .context import SchannelContext

try:
    import httpcore
    import httpx
except ImportError as exc:
    raise ImportError(
        "httpx is required for SChannel HTTP transports. "
        "Install with: pip install requests-schannel[httpx]"
    ) from exc

# httpcore's socket option type — union of the three setsockopt() overloads
_SocketOption = (
    tuple[int, int, int] | tuple[int, int, bytes | bytearray] | tuple[int, int, None, int]
)


# ---------------------------------------------------------------------------
# Internal helpers — httpcore request/response mapping
# ---------------------------------------------------------------------------


def _to_httpcore_request(request: httpx.Request) -> httpcore.Request:
    """Convert an httpx Request to an httpcore Request."""
    return httpcore.Request(
        method=request.method,
        url=httpcore.URL(
            scheme=request.url.raw_scheme,
            host=request.url.raw_host,
            port=request.url.port,
            target=request.url.raw_path,
        ),
        headers=request.headers.raw,
        content=request.stream,
        extensions=request.extensions,
    )


class _SyncResponseStream(httpx.SyncByteStream):
    """Wraps an httpcore sync response stream for httpx."""

    def __init__(self, httpcore_stream: typing.Iterable[bytes]) -> None:
        self._stream = httpcore_stream

    def __iter__(self) -> typing.Iterator[bytes]:
        yield from self._stream

    def close(self) -> None:
        if hasattr(self._stream, "close"):
            self._stream.close()


class _AsyncResponseStream(httpx.AsyncByteStream):
    """Wraps an httpcore async response stream for httpx."""

    def __init__(self, httpcore_stream: typing.AsyncIterable[bytes]) -> None:
        self._stream = httpcore_stream

    async def __aiter__(self) -> typing.AsyncIterator[bytes]:
        async for chunk in self._stream:
            yield chunk

    async def aclose(self) -> None:
        if hasattr(self._stream, "aclose"):
            await self._stream.aclose()


# ---------------------------------------------------------------------------
# Async network backend — runs SChannel TLS in a thread-pool executor
# ---------------------------------------------------------------------------


class _SchannelAsyncStream(httpcore.AsyncNetworkStream):
    """Async network stream wrapping a plain or TLS socket.

    Blocking socket operations are offloaded to an executor so they
    don't block the asyncio event loop.
    """

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        loop = asyncio.get_running_loop()

        def _read() -> bytes:
            if timeout is not None:
                self._sock.settimeout(timeout)
            return self._sock.recv(max_bytes)

        return await loop.run_in_executor(None, _read)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        loop = asyncio.get_running_loop()

        def _write() -> None:
            if timeout is not None:
                self._sock.settimeout(timeout)
            self._sock.sendall(buffer)

        await loop.run_in_executor(None, _write)

    async def aclose(self) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._sock.close)

    async def start_tls(
        self,
        ssl_context: typing.Any,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        """Perform TLS handshake using SChannel (via SchannelContext)."""
        loop = asyncio.get_running_loop()

        def _handshake() -> socket.socket:
            if timeout is not None:
                self._sock.settimeout(timeout)
            return typing.cast(
                socket.socket,
                ssl_context.wrap_socket(
                    self._sock,
                    server_hostname=server_hostname,
                    do_handshake_on_connect=True,
                ),
            )

        tls_sock = await loop.run_in_executor(None, _handshake)
        return _SchannelAsyncStream(tls_sock)

    def get_extra_info(self, info: str) -> typing.Any:
        if info == "ssl_object":
            # Return the socket itself if it has selected_alpn_protocol
            # (i.e. it's a SchannelSocket after TLS)
            if hasattr(self._sock, "selected_alpn_protocol"):
                return self._sock
            return None
        if info == "server_addr":
            try:
                return self._sock.getsockname()
            except Exception:
                return None
        if info == "client_addr":
            try:
                return self._sock.getpeername()
            except Exception:
                return None
        if info == "is_readable":
            return True
        return None


class _SchannelAsyncBackend(httpcore.AsyncNetworkBackend):
    """Async network backend that uses SChannel for TLS."""

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[_SocketOption] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        loop = asyncio.get_running_loop()

        def _connect() -> socket.socket:
            source = (local_address, 0) if local_address is not None else None
            sock = socket.create_connection((host, port), timeout=timeout, source_address=source)
            if socket_options is not None:
                for opt in socket_options:
                    sock.setsockopt(*opt)
            return sock

        sock = await loop.run_in_executor(None, _connect)
        return _SchannelAsyncStream(sock)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: typing.Iterable[_SocketOption] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.UnsupportedProtocol("Unix sockets are not supported on Windows")

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


# ---------------------------------------------------------------------------
# Context builder (shared by both transports)
# ---------------------------------------------------------------------------


def _build_context(
    schannel_context: SchannelContext | None,
    client_cert_thumbprint: str | None,
    client_cert_subject: str | None,
    auto_select_client_cert: bool,
    cert_store_name: str,
    alpn_protocols: list[str] | None,
    backend: str | None,
    hwnd: int | None,
) -> SchannelContext:
    """Build or return the SchannelContext for a transport."""
    if schannel_context is not None:
        return schannel_context

    ctx = SchannelContext(backend=backend)
    if client_cert_thumbprint:
        ctx.client_cert_thumbprint = client_cert_thumbprint
    if client_cert_subject:
        ctx.client_cert_subject = client_cert_subject
    ctx.auto_select_client_cert = auto_select_client_cert
    ctx.cert_store_name = cert_store_name
    if alpn_protocols:
        ctx.set_alpn_protocols(alpn_protocols)
    if hwnd is not None:
        ctx.hwnd = hwnd
    return ctx


# ---------------------------------------------------------------------------
# Public API — Transports
# ---------------------------------------------------------------------------


class SchannelTransport(httpx.BaseTransport):
    """httpx sync transport that uses Windows SChannel for TLS.

    Replaces OpenSSL with SChannel, enabling smartcard/PKI client
    authentication via the Windows certificate store.

    Usage::

        from requests_schannel.httpx_transport import SchannelTransport
        from requests_schannel import SchannelContext

        transport = SchannelTransport()
        client = httpx.Client(transport=transport)
        resp = client.get("https://example.com")

        # With mTLS:
        transport = SchannelTransport(client_cert_thumbprint="AB12CD...")
    """

    def __init__(
        self,
        client_cert_thumbprint: str | None = None,
        client_cert_subject: str | None = None,
        auto_select_client_cert: bool = False,
        cert_store_name: str = "MY",
        alpn_protocols: list[str] | None = None,
        backend: str | None = None,
        schannel_context: SchannelContext | None = None,
        hwnd: int | None = None,
        *,
        http1: bool = True,
        http2: bool = False,
        retries: int = 0,
        local_address: str | None = None,
        uds: str | None = None,
        max_connections: int | None = None,
        max_keepalive_connections: int | None = None,
        keepalive_expiry: float | None = 5.0,
        socket_options: typing.Iterable[_SocketOption] | None = None,
    ) -> None:
        self._schannel_context = _build_context(
            schannel_context=schannel_context,
            client_cert_thumbprint=client_cert_thumbprint,
            client_cert_subject=client_cert_subject,
            auto_select_client_cert=auto_select_client_cert,
            cert_store_name=cert_store_name,
            alpn_protocols=alpn_protocols,
            backend=backend,
            hwnd=hwnd,
        )

        self._pool = httpcore.ConnectionPool(
            ssl_context=self._schannel_context,  # type: ignore[arg-type]
            http1=http1,
            http2=http2,
            retries=retries,
            local_address=local_address,
            uds=uds,
            max_connections=max_connections or 100,
            max_keepalive_connections=max_keepalive_connections or 20,
            keepalive_expiry=keepalive_expiry,
            socket_options=socket_options,
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        assert isinstance(request.stream, httpx.SyncByteStream)

        req = _to_httpcore_request(request)
        resp = self._pool.handle_request(req)

        assert isinstance(resp.stream, typing.Iterable)
        return httpx.Response(
            status_code=resp.status,
            headers=resp.headers,
            stream=_SyncResponseStream(resp.stream),
            extensions=resp.extensions,
        )

    def close(self) -> None:
        self._pool.close()

    @property
    def schannel_context(self) -> SchannelContext:
        """The underlying SchannelContext for this transport."""
        return self._schannel_context


class AsyncSchannelTransport(httpx.AsyncBaseTransport):
    """httpx async transport that uses Windows SChannel for TLS.

    Replaces OpenSSL with SChannel for async HTTP requests, enabling
    smartcard/PKI client authentication via the Windows certificate store.

    All blocking SChannel operations (handshake, encrypt, decrypt) run in
    a thread-pool executor so they don't block the asyncio event loop.

    Usage::

        from requests_schannel.httpx_transport import AsyncSchannelTransport

        transport = AsyncSchannelTransport()
        async with httpx.AsyncClient(transport=transport) as client:
            resp = await client.get("https://example.com")
    """

    def __init__(
        self,
        client_cert_thumbprint: str | None = None,
        client_cert_subject: str | None = None,
        auto_select_client_cert: bool = False,
        cert_store_name: str = "MY",
        alpn_protocols: list[str] | None = None,
        backend: str | None = None,
        schannel_context: SchannelContext | None = None,
        hwnd: int | None = None,
        *,
        http1: bool = True,
        http2: bool = False,
        retries: int = 0,
        local_address: str | None = None,
        max_connections: int | None = None,
        max_keepalive_connections: int | None = None,
        keepalive_expiry: float | None = 5.0,
        socket_options: typing.Iterable[_SocketOption] | None = None,
    ) -> None:
        self._schannel_context = _build_context(
            schannel_context=schannel_context,
            client_cert_thumbprint=client_cert_thumbprint,
            client_cert_subject=client_cert_subject,
            auto_select_client_cert=auto_select_client_cert,
            cert_store_name=cert_store_name,
            alpn_protocols=alpn_protocols,
            backend=backend,
            hwnd=hwnd,
        )

        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=self._schannel_context,  # type: ignore[arg-type]
            http1=http1,
            http2=http2,
            retries=retries,
            local_address=local_address,
            max_connections=max_connections or 100,
            max_keepalive_connections=max_keepalive_connections or 20,
            keepalive_expiry=keepalive_expiry,
            network_backend=_SchannelAsyncBackend(),
            socket_options=socket_options,
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        assert isinstance(request.stream, httpx.AsyncByteStream)

        req = _to_httpcore_request(request)
        resp = await self._pool.handle_async_request(req)

        assert isinstance(resp.stream, typing.AsyncIterable)
        return httpx.Response(
            status_code=resp.status,
            headers=resp.headers,
            stream=_AsyncResponseStream(resp.stream),
            extensions=resp.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()

    @property
    def schannel_context(self) -> SchannelContext:
        """The underlying SchannelContext for this transport."""
        return self._schannel_context


# ---------------------------------------------------------------------------
# Public API — Convenience factories
# ---------------------------------------------------------------------------


def create_httpx_client(
    client_cert_thumbprint: str | None = None,
    client_cert_subject: str | None = None,
    auto_select_client_cert: bool = False,
    cert_store_name: str = "MY",
    alpn_protocols: list[str] | None = None,
    backend: str | None = None,
    hwnd: int | None = None,
    **kwargs: typing.Any,
) -> httpx.Client:
    """Create a pre-configured httpx.Client using Windows SChannel for TLS.

    All HTTPS connections will use SChannel instead of OpenSSL.

    Usage::

        from requests_schannel.httpx_transport import create_httpx_client

        client = create_httpx_client(client_cert_thumbprint="AB12CD...")
        resp = client.get("https://example.com")

    Args:
        client_cert_thumbprint: SHA-1 thumbprint of the client certificate for mTLS.
        client_cert_subject: Subject name substring to find the client certificate.
        auto_select_client_cert: Let Windows auto-select a client cert.
        cert_store_name: Windows certificate store name (default ``'MY'``).
        alpn_protocols: ALPN protocol list (e.g. ``["http/1.1"]``).
        backend: SChannel backend name (``'ctypes'`` or ``'sspilib'``).
        hwnd: Parent window handle for Windows Security dialogs.
        **kwargs: Additional keyword arguments forwarded to ``httpx.Client()``.

    Returns:
        A configured :class:`httpx.Client`.
    """
    transport = SchannelTransport(
        client_cert_thumbprint=client_cert_thumbprint,
        client_cert_subject=client_cert_subject,
        auto_select_client_cert=auto_select_client_cert,
        cert_store_name=cert_store_name,
        alpn_protocols=alpn_protocols,
        backend=backend,
        hwnd=hwnd,
    )
    return httpx.Client(transport=transport, **kwargs)


def create_async_httpx_client(
    client_cert_thumbprint: str | None = None,
    client_cert_subject: str | None = None,
    auto_select_client_cert: bool = False,
    cert_store_name: str = "MY",
    alpn_protocols: list[str] | None = None,
    backend: str | None = None,
    hwnd: int | None = None,
    **kwargs: typing.Any,
) -> httpx.AsyncClient:
    """Create a pre-configured httpx.AsyncClient using Windows SChannel for TLS.

    All HTTPS connections will use SChannel instead of OpenSSL.
    Blocking SChannel operations run in an executor, never blocking the event loop.

    Usage::

        from requests_schannel.httpx_transport import create_async_httpx_client

        async with create_async_httpx_client() as client:
            resp = await client.get("https://example.com")

    Args:
        client_cert_thumbprint: SHA-1 thumbprint of the client certificate for mTLS.
        client_cert_subject: Subject name substring to find the client certificate.
        auto_select_client_cert: Let Windows auto-select a client cert.
        cert_store_name: Windows certificate store name (default ``'MY'``).
        alpn_protocols: ALPN protocol list (e.g. ``["http/1.1"]``).
        backend: SChannel backend name (``'ctypes'`` or ``'sspilib'``).
        hwnd: Parent window handle for Windows Security dialogs.
        **kwargs: Additional keyword arguments forwarded to ``httpx.AsyncClient()``.

    Returns:
        A configured :class:`httpx.AsyncClient`.
    """
    transport = AsyncSchannelTransport(
        client_cert_thumbprint=client_cert_thumbprint,
        client_cert_subject=client_cert_subject,
        auto_select_client_cert=auto_select_client_cert,
        cert_store_name=cert_store_name,
        alpn_protocols=alpn_protocols,
        backend=backend,
        hwnd=hwnd,
    )
    return httpx.AsyncClient(transport=transport, **kwargs)
