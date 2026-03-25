"""Tests for the httpx transport integration."""

from __future__ import annotations

import socket
import typing
from unittest.mock import AsyncMock, MagicMock, patch

import httpcore
import httpx
import pytest

_BACKEND_PATCH = "requests_schannel.context.get_backend"


@pytest.mark.unit
class TestSchannelTransport:
    """Test SchannelTransport configuration and request handling."""

    def test_transport_creates_context(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import SchannelTransport

            transport = SchannelTransport()
            assert transport.schannel_context is not None

    def test_transport_with_thumbprint(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import SchannelTransport

            transport = SchannelTransport(client_cert_thumbprint="AABB")
            assert transport.schannel_context.client_cert_thumbprint == "AABB"

    def test_transport_with_subject(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import SchannelTransport

            transport = SchannelTransport(client_cert_subject="CN=Test")
            assert transport.schannel_context.client_cert_subject == "CN=Test"

    def test_transport_with_auto_select(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import SchannelTransport

            transport = SchannelTransport(auto_select_client_cert=True)
            assert transport.schannel_context.auto_select_client_cert is True

    def test_transport_with_custom_context(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.context import SchannelContext
            from requests_schannel.httpx_transport import SchannelTransport

            ctx = SchannelContext(backend=mock_get.return_value)
            transport = SchannelTransport(schannel_context=ctx)
            assert transport.schannel_context is ctx

    def test_transport_with_alpn(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import SchannelTransport

            transport = SchannelTransport(alpn_protocols=["h2", "http/1.1"])
            assert transport.schannel_context._alpn_protocols == ["h2", "http/1.1"]

    def test_transport_with_hwnd(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import SchannelTransport

            transport = SchannelTransport(hwnd=12345)
            assert transport.schannel_context.hwnd == 12345

    def test_transport_close(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import SchannelTransport

            transport = SchannelTransport()
            transport.close()  # Should not raise

    def test_transport_context_manager(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import SchannelTransport

            with SchannelTransport() as transport:
                assert transport.schannel_context is not None


@pytest.mark.unit
class TestAsyncSchannelTransport:
    """Test AsyncSchannelTransport configuration."""

    def test_async_transport_creates_context(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import AsyncSchannelTransport

            transport = AsyncSchannelTransport()
            assert transport.schannel_context is not None

    def test_async_transport_with_thumbprint(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import AsyncSchannelTransport

            transport = AsyncSchannelTransport(client_cert_thumbprint="AABB")
            assert transport.schannel_context.client_cert_thumbprint == "AABB"

    def test_async_transport_with_subject(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import AsyncSchannelTransport

            transport = AsyncSchannelTransport(client_cert_subject="CN=Test")
            assert transport.schannel_context.client_cert_subject == "CN=Test"

    def test_async_transport_with_custom_context(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.context import SchannelContext
            from requests_schannel.httpx_transport import AsyncSchannelTransport

            ctx = SchannelContext(backend=mock_get.return_value)
            transport = AsyncSchannelTransport(schannel_context=ctx)
            assert transport.schannel_context is ctx

    def test_async_transport_with_alpn(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import AsyncSchannelTransport

            transport = AsyncSchannelTransport(alpn_protocols=["http/1.1"])
            assert transport.schannel_context._alpn_protocols == ["http/1.1"]

    async def test_async_transport_aclose(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import AsyncSchannelTransport

            transport = AsyncSchannelTransport()
            await transport.aclose()  # Should not raise

    async def test_async_transport_context_manager(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import AsyncSchannelTransport

            async with AsyncSchannelTransport() as transport:
                assert transport.schannel_context is not None


@pytest.mark.unit
class TestCreateHttpxClient:
    """Test the convenience create_httpx_client factory."""

    def test_creates_client(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            import httpx

            from requests_schannel.httpx_transport import create_httpx_client

            client = create_httpx_client()
            assert isinstance(client, httpx.Client)
            client.close()

    def test_creates_client_with_thumbprint(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import (
                SchannelTransport,
                create_httpx_client,
            )

            client = create_httpx_client(client_cert_thumbprint="AABB")
            # Access the transport to verify configuration
            transport = client._transport
            assert isinstance(transport, SchannelTransport)
            assert transport.schannel_context.client_cert_thumbprint == "AABB"
            client.close()


@pytest.mark.unit
class TestCreateAsyncHttpxClient:
    """Test the convenience create_async_httpx_client factory."""

    async def test_creates_async_client(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            import httpx

            from requests_schannel.httpx_transport import create_async_httpx_client

            client = create_async_httpx_client()
            assert isinstance(client, httpx.AsyncClient)
            await client.aclose()

    async def test_creates_async_client_with_thumbprint(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import (
                AsyncSchannelTransport,
                create_async_httpx_client,
            )

            client = create_async_httpx_client(client_cert_thumbprint="AABB")
            transport = client._transport
            assert isinstance(transport, AsyncSchannelTransport)
            assert transport.schannel_context.client_cert_thumbprint == "AABB"
            await client.aclose()


@pytest.mark.unit
class TestAsyncSchannelTransportConfig:
    """Extended async transport configuration tests (parity with sync)."""

    def test_async_transport_with_auto_select(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import AsyncSchannelTransport

            transport = AsyncSchannelTransport(auto_select_client_cert=True)
            assert transport.schannel_context.auto_select_client_cert is True

    def test_async_transport_with_hwnd(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import AsyncSchannelTransport

            transport = AsyncSchannelTransport(hwnd=12345)
            assert transport.schannel_context.hwnd == 12345


@pytest.mark.unit
class TestAsyncResponseStream:
    """Test _AsyncResponseStream wrapping."""

    async def test_aiter_yields_chunks(self) -> None:
        from requests_schannel.httpx_transport import _AsyncResponseStream

        async def _mock_stream() -> typing.AsyncIterator[bytes]:
            yield b"chunk1"
            yield b"chunk2"

        stream = _AsyncResponseStream(_mock_stream())
        chunks = [chunk async for chunk in stream]
        assert chunks == [b"chunk1", b"chunk2"]

    async def test_aclose_calls_underlying(self) -> None:
        from requests_schannel.httpx_transport import _AsyncResponseStream

        mock_stream = AsyncMock()
        mock_stream.aclose = AsyncMock()
        stream = _AsyncResponseStream(mock_stream)
        await stream.aclose()
        mock_stream.aclose.assert_called_once()

    async def test_aclose_no_aclose_method(self) -> None:
        """aclose() should not raise if the underlying stream has no aclose."""
        from requests_schannel.httpx_transport import _AsyncResponseStream

        mock_stream = MagicMock(spec=[])  # no aclose
        stream = _AsyncResponseStream(mock_stream)
        await stream.aclose()  # Should not raise


@pytest.mark.unit
class TestSchannelAsyncStream:
    """Test _SchannelAsyncStream network stream."""

    async def test_read(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.recv.return_value = b"data"
        stream = _SchannelAsyncStream(mock_sock)

        result = await stream.read(4096)
        assert result == b"data"
        mock_sock.recv.assert_called_once_with(4096)

    async def test_read_with_timeout(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.recv.return_value = b"data"
        stream = _SchannelAsyncStream(mock_sock)

        result = await stream.read(4096, timeout=5.0)
        assert result == b"data"
        mock_sock.settimeout.assert_called_once_with(5.0)

    async def test_read_no_timeout_skips_settimeout(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.recv.return_value = b"data"
        stream = _SchannelAsyncStream(mock_sock)

        await stream.read(4096, timeout=None)
        mock_sock.settimeout.assert_not_called()

    async def test_write(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        stream = _SchannelAsyncStream(mock_sock)

        await stream.write(b"hello")
        mock_sock.sendall.assert_called_once_with(b"hello")

    async def test_write_with_timeout(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        stream = _SchannelAsyncStream(mock_sock)

        await stream.write(b"hello", timeout=5.0)
        mock_sock.settimeout.assert_called_once_with(5.0)
        mock_sock.sendall.assert_called_once_with(b"hello")

    async def test_write_no_timeout_skips_settimeout(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        stream = _SchannelAsyncStream(mock_sock)

        await stream.write(b"hello", timeout=None)
        mock_sock.settimeout.assert_not_called()

    async def test_aclose(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        stream = _SchannelAsyncStream(mock_sock)

        await stream.aclose()
        mock_sock.close.assert_called_once()

    async def test_start_tls(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        mock_ssl_ctx = MagicMock()
        mock_tls_sock = MagicMock(spec=socket.socket)
        mock_ssl_ctx.wrap_socket.return_value = mock_tls_sock

        stream = _SchannelAsyncStream(mock_sock)
        tls_stream = await stream.start_tls(mock_ssl_ctx, server_hostname="example.com")

        mock_ssl_ctx.wrap_socket.assert_called_once_with(
            mock_sock,
            server_hostname="example.com",
            do_handshake_on_connect=True,
        )
        assert isinstance(tls_stream, _SchannelAsyncStream)

    async def test_start_tls_with_timeout(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        mock_ssl_ctx = MagicMock()
        mock_ssl_ctx.wrap_socket.return_value = MagicMock(spec=socket.socket)

        stream = _SchannelAsyncStream(mock_sock)
        await stream.start_tls(mock_ssl_ctx, server_hostname="example.com", timeout=10.0)

        mock_sock.settimeout.assert_called_once_with(10.0)

    def test_get_extra_info_ssl_object(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.selected_alpn_protocol = MagicMock()
        stream = _SchannelAsyncStream(mock_sock)

        assert stream.get_extra_info("ssl_object") is mock_sock

    def test_get_extra_info_ssl_object_no_alpn(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=["recv", "sendall", "close", "settimeout"])
        stream = _SchannelAsyncStream(mock_sock)

        assert stream.get_extra_info("ssl_object") is None

    def test_get_extra_info_server_addr(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.getsockname.return_value = ("127.0.0.1", 8080)
        stream = _SchannelAsyncStream(mock_sock)

        assert stream.get_extra_info("server_addr") == ("127.0.0.1", 8080)

    def test_get_extra_info_server_addr_error(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.getsockname.side_effect = OSError
        stream = _SchannelAsyncStream(mock_sock)

        assert stream.get_extra_info("server_addr") is None

    def test_get_extra_info_client_addr(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.getpeername.return_value = ("10.0.0.1", 443)
        stream = _SchannelAsyncStream(mock_sock)

        assert stream.get_extra_info("client_addr") == ("10.0.0.1", 443)

    def test_get_extra_info_client_addr_error(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.getpeername.side_effect = OSError
        stream = _SchannelAsyncStream(mock_sock)

        assert stream.get_extra_info("client_addr") is None

    def test_get_extra_info_is_readable(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        stream = _SchannelAsyncStream(mock_sock)

        assert stream.get_extra_info("is_readable") is True

    def test_get_extra_info_unknown(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        stream = _SchannelAsyncStream(mock_sock)

        assert stream.get_extra_info("unknown_key") is None


@pytest.mark.unit
class TestSchannelAsyncBackend:
    """Test _SchannelAsyncBackend network backend."""

    async def test_connect_tcp(self) -> None:
        from requests_schannel.httpx_transport import (
            _SchannelAsyncBackend,
            _SchannelAsyncStream,
        )

        backend = _SchannelAsyncBackend()
        mock_sock = MagicMock(spec=socket.socket)

        with patch("requests_schannel.httpx_transport.socket.create_connection") as mock_conn:
            mock_conn.return_value = mock_sock

            stream = await backend.connect_tcp("example.com", 443)

            mock_conn.assert_called_once_with(
                ("example.com", 443), timeout=None, source_address=None
            )
            assert isinstance(stream, _SchannelAsyncStream)

    async def test_connect_tcp_with_timeout(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncBackend

        backend = _SchannelAsyncBackend()

        with patch("requests_schannel.httpx_transport.socket.create_connection") as mock_conn:
            mock_conn.return_value = MagicMock(spec=socket.socket)

            await backend.connect_tcp("example.com", 443, timeout=10.0)

            mock_conn.assert_called_once_with(
                ("example.com", 443), timeout=10.0, source_address=None
            )

    async def test_connect_tcp_with_local_address(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncBackend

        backend = _SchannelAsyncBackend()

        with patch("requests_schannel.httpx_transport.socket.create_connection") as mock_conn:
            mock_conn.return_value = MagicMock(spec=socket.socket)

            await backend.connect_tcp("example.com", 443, local_address="192.168.1.100")

            mock_conn.assert_called_once_with(
                ("example.com", 443), timeout=None, source_address=("192.168.1.100", 0)
            )

    async def test_connect_tcp_with_socket_options(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncBackend

        backend = _SchannelAsyncBackend()
        mock_sock = MagicMock(spec=socket.socket)

        with patch("requests_schannel.httpx_transport.socket.create_connection") as mock_conn:
            mock_conn.return_value = mock_sock

            opts = [(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)]
            await backend.connect_tcp("example.com", 443, socket_options=opts)

            mock_sock.setsockopt.assert_called_once_with(
                socket.IPPROTO_TCP, socket.TCP_NODELAY, 1
            )

    async def test_connect_unix_socket_raises(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncBackend

        backend = _SchannelAsyncBackend()

        with pytest.raises(httpcore.UnsupportedProtocol, match="Unix sockets"):
            await backend.connect_unix_socket("/tmp/test.sock")

    async def test_sleep(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncBackend

        backend = _SchannelAsyncBackend()

        with patch("requests_schannel.httpx_transport.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await backend.sleep(0.5)
            mock_sleep.assert_called_once_with(0.5)


@pytest.mark.unit
class TestAsyncHandleRequest:
    """Test AsyncSchannelTransport.handle_async_request."""

    async def test_handle_async_request(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import AsyncSchannelTransport

            transport = AsyncSchannelTransport()

            # Create a mock httpcore response
            async def _mock_stream() -> typing.AsyncIterator[bytes]:
                yield b"response body"

            mock_resp = MagicMock(spec=httpcore.Response)
            mock_resp.status = 200
            mock_resp.headers = [(b"content-type", b"text/plain")]
            mock_resp.stream = _mock_stream()
            mock_resp.extensions = {}

            transport._pool = MagicMock()
            transport._pool.handle_async_request = AsyncMock(return_value=mock_resp)

            request = httpx.Request("GET", "https://example.com/")
            response = await transport.handle_async_request(request)

            assert response.status_code == 200
            transport._pool.handle_async_request.assert_called_once()


    async def test_creates_async_client_with_thumbprint(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.httpx_transport import (
                AsyncSchannelTransport,
                create_async_httpx_client,
            )

            client = create_async_httpx_client(client_cert_thumbprint="AABB")
            transport = client._transport
            assert isinstance(transport, AsyncSchannelTransport)
            assert transport.schannel_context.client_cert_thumbprint == "AABB"
            await client.aclose()


@pytest.mark.unit
class TestResponseStreams:
    """Test the internal response stream wrappers."""

    def test_sync_response_stream(self) -> None:
        from requests_schannel.httpx_transport import _SyncResponseStream

        data = [b"hello", b" ", b"world"]
        stream = _SyncResponseStream(data)
        result = b"".join(stream)
        assert result == b"hello world"

    def test_sync_response_stream_close(self) -> None:
        from requests_schannel.httpx_transport import _SyncResponseStream

        mock_stream = MagicMock()
        stream = _SyncResponseStream(mock_stream)
        stream.close()
        mock_stream.close.assert_called_once()

    async def test_async_response_stream(self) -> None:
        from requests_schannel.httpx_transport import _AsyncResponseStream

        async def gen() -> __import__("typing").AsyncIterator[bytes]:
            yield b"hello"
            yield b" "
            yield b"world"

        stream = _AsyncResponseStream(gen())
        chunks = [chunk async for chunk in stream]
        assert b"".join(chunks) == b"hello world"

    async def test_async_response_stream_aclose(self) -> None:
        from requests_schannel.httpx_transport import _AsyncResponseStream

        mock_stream = AsyncMock()
        stream = _AsyncResponseStream(mock_stream)
        await stream.aclose()
        mock_stream.aclose.assert_called_once()
