"""Tests for the httpx transport integration."""

from __future__ import annotations

import socket
from unittest.mock import AsyncMock, MagicMock, patch

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
class TestSchannelAsyncStream:
    """Test the internal _SchannelAsyncStream."""

    async def test_read(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.recv.return_value = b"hello"
        stream = _SchannelAsyncStream(mock_sock)

        data = await stream.read(1024)
        assert data == b"hello"
        mock_sock.recv.assert_called_once_with(1024)

    async def test_write(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        stream = _SchannelAsyncStream(mock_sock)

        await stream.write(b"hello")
        mock_sock.sendall.assert_called_once_with(b"hello")

    async def test_aclose(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        stream = _SchannelAsyncStream(mock_sock)

        await stream.aclose()
        mock_sock.close.assert_called_once()

    async def test_start_tls(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        mock_ctx = MagicMock()
        mock_tls_sock = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_tls_sock

        stream = _SchannelAsyncStream(mock_sock)
        tls_stream = await stream.start_tls(
            ssl_context=mock_ctx,
            server_hostname="example.com",
            timeout=30.0,
        )

        mock_ctx.wrap_socket.assert_called_once_with(
            mock_sock,
            server_hostname="example.com",
            do_handshake_on_connect=True,
        )
        assert isinstance(tls_stream, _SchannelAsyncStream)

    async def test_get_extra_info_ssl_object(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        # Plain socket — no ssl_object
        mock_sock = MagicMock(spec=socket.socket)
        stream = _SchannelAsyncStream(mock_sock)
        assert stream.get_extra_info("ssl_object") is None

        # TLS socket — has selected_alpn_protocol
        mock_tls_sock = MagicMock()
        mock_tls_sock.selected_alpn_protocol.return_value = "http/1.1"
        tls_stream = _SchannelAsyncStream(mock_tls_sock)
        assert tls_stream.get_extra_info("ssl_object") is mock_tls_sock

    async def test_get_extra_info_unknown_key(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncStream

        mock_sock = MagicMock(spec=socket.socket)
        stream = _SchannelAsyncStream(mock_sock)
        assert stream.get_extra_info("unknown_key") is None


@pytest.mark.unit
class TestSchannelAsyncBackend:
    """Test the internal _SchannelAsyncBackend."""

    async def test_connect_tcp(self) -> None:
        from requests_schannel.httpx_transport import (
            _SchannelAsyncBackend,
            _SchannelAsyncStream,
        )

        backend = _SchannelAsyncBackend()

        with patch("socket.create_connection") as mock_connect:
            mock_sock = MagicMock(spec=socket.socket)
            mock_connect.return_value = mock_sock

            stream = await backend.connect_tcp("example.com", 443, timeout=30.0)
            assert isinstance(stream, _SchannelAsyncStream)
            mock_connect.assert_called_once_with(
                ("example.com", 443), timeout=30.0, source_address=None
            )

    async def test_connect_unix_socket_raises(self) -> None:
        import httpcore

        from requests_schannel.httpx_transport import _SchannelAsyncBackend

        backend = _SchannelAsyncBackend()
        with pytest.raises(httpcore.UnsupportedProtocol):
            await backend.connect_unix_socket("/tmp/test.sock")

    async def test_sleep(self) -> None:
        from requests_schannel.httpx_transport import _SchannelAsyncBackend

        backend = _SchannelAsyncBackend()
        await backend.sleep(0)  # Should not raise


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
