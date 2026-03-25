"""Tests for AsyncSchannelSocket wrapping and async I/O operations."""

from __future__ import annotations

import asyncio
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from requests_schannel.async_socket import AsyncSchannelSocket
from requests_schannel.socket import SchannelSocket

_BACKEND_PATCH = "requests_schannel.context.get_backend"


@pytest.fixture
def mock_schannel_socket() -> MagicMock:
    """A fully mocked SchannelSocket for unit tests."""
    sock = MagicMock(spec=SchannelSocket)
    sock.recv.return_value = b"decrypted"
    sock.send.return_value = 5
    sock.selected_alpn_protocol.return_value = "http/1.1"
    sock.cipher.return_value = ("AES256-SHA", "TLSv1.2", 256)
    sock.version.return_value = "TLSv1.2"
    sock.server_hostname = "example.com"
    sock.close.return_value = None
    return sock


def _make_async_socket(mock_schannel_socket: MagicMock) -> AsyncSchannelSocket:
    """Create an AsyncSchannelSocket with a mocked underlying socket.

    Must be called from within a running event loop (i.e. from an async test).
    """
    return AsyncSchannelSocket(mock_schannel_socket)


@pytest.mark.unit
class TestConnect:
    """Test the connect() class method."""

    async def test_connect_creates_tcp_and_wraps(self) -> None:
        """connect() should create a TCP socket and wrap it with SChannel."""
        mock_ctx = MagicMock()
        mock_schannel_sock = MagicMock(spec=SchannelSocket)
        mock_ctx.wrap_socket.return_value = mock_schannel_sock

        with patch("requests_schannel.async_socket.socket.create_connection") as mock_conn:
            mock_raw = MagicMock(spec=socket.socket)
            mock_conn.return_value = mock_raw

            result = await AsyncSchannelSocket.connect("example.com", 443, mock_ctx)

            mock_conn.assert_called_once_with(("example.com", 443), timeout=30.0)
            mock_raw.settimeout.assert_called_once_with(30.0)
            mock_ctx.wrap_socket.assert_called_once_with(
                mock_raw,
                server_hostname="example.com",
                do_handshake_on_connect=True,
            )
            assert isinstance(result, AsyncSchannelSocket)
            assert result._sock is mock_schannel_sock

    async def test_connect_custom_server_hostname(self) -> None:
        """connect() uses server_hostname when provided."""
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = MagicMock(spec=SchannelSocket)

        with patch("requests_schannel.async_socket.socket.create_connection") as mock_conn:
            mock_conn.return_value = MagicMock(spec=socket.socket)

            await AsyncSchannelSocket.connect(
                "10.0.0.1", 443, mock_ctx, server_hostname="api.example.com"
            )

            mock_ctx.wrap_socket.assert_called_once_with(
                mock_conn.return_value,
                server_hostname="api.example.com",
                do_handshake_on_connect=True,
            )

    async def test_connect_custom_timeout(self) -> None:
        """connect() passes timeout to create_connection and settimeout."""
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = MagicMock(spec=SchannelSocket)

        with patch("requests_schannel.async_socket.socket.create_connection") as mock_conn:
            mock_raw = MagicMock(spec=socket.socket)
            mock_conn.return_value = mock_raw

            await AsyncSchannelSocket.connect("example.com", 443, mock_ctx, timeout=10.0)

            mock_conn.assert_called_once_with(("example.com", 443), timeout=10.0)
            mock_raw.settimeout.assert_called_once_with(10.0)

    async def test_connect_none_timeout(self) -> None:
        """connect() passes None timeout correctly."""
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = MagicMock(spec=SchannelSocket)

        with patch("requests_schannel.async_socket.socket.create_connection") as mock_conn:
            mock_raw = MagicMock(spec=socket.socket)
            mock_conn.return_value = mock_raw

            await AsyncSchannelSocket.connect("example.com", 443, mock_ctx, timeout=None)

            mock_conn.assert_called_once_with(("example.com", 443), timeout=None)
            mock_raw.settimeout.assert_called_once_with(None)

    async def test_connect_propagates_connection_error(self) -> None:
        """Socket connection errors propagate correctly."""
        mock_ctx = MagicMock()

        with patch(
            "requests_schannel.async_socket.socket.create_connection",
            side_effect=ConnectionRefusedError("Connection refused"),
        ):
            with pytest.raises(ConnectionRefusedError):
                await AsyncSchannelSocket.connect("example.com", 443, mock_ctx)

    async def test_connect_propagates_handshake_error(self) -> None:
        """Handshake errors propagate correctly through the executor."""
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.side_effect = OSError("Handshake failed")

        with patch("requests_schannel.async_socket.socket.create_connection") as mock_conn:
            mock_conn.return_value = MagicMock(spec=socket.socket)

            with pytest.raises(OSError, match="Handshake failed"):
                await AsyncSchannelSocket.connect("example.com", 443, mock_ctx)


@pytest.mark.unit
class TestWrap:
    """Test the wrap() class method."""

    async def test_wrap_wraps_existing_socket(self) -> None:
        """wrap() should wrap an already-connected socket with SChannel TLS."""
        mock_ctx = MagicMock()
        mock_schannel_sock = MagicMock(spec=SchannelSocket)
        mock_ctx.wrap_socket.return_value = mock_schannel_sock
        mock_raw = MagicMock(spec=socket.socket)

        result = await AsyncSchannelSocket.wrap(mock_raw, mock_ctx, "example.com")

        mock_ctx.wrap_socket.assert_called_once_with(
            mock_raw,
            server_hostname="example.com",
            do_handshake_on_connect=True,
        )
        assert isinstance(result, AsyncSchannelSocket)
        assert result._sock is mock_schannel_sock

    async def test_wrap_propagates_error(self) -> None:
        """wrap() propagates errors from wrap_socket."""
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.side_effect = OSError("wrap failed")
        mock_raw = MagicMock(spec=socket.socket)

        with pytest.raises(OSError, match="wrap failed"):
            await AsyncSchannelSocket.wrap(mock_raw, mock_ctx, "example.com")


@pytest.mark.unit
class TestRecv:
    """Test async receive operations."""

    async def test_recv_returns_decrypted_data(
        self, mock_schannel_socket: MagicMock
    ) -> None:
        async_sock = _make_async_socket(mock_schannel_socket)
        mock_schannel_socket.recv.return_value = b"hello world"
        result = await async_sock.recv(4096)
        assert result == b"hello world"
        mock_schannel_socket.recv.assert_called_once_with(4096)

    async def test_recv_default_bufsize(
        self, mock_schannel_socket: MagicMock
    ) -> None:
        async_sock = _make_async_socket(mock_schannel_socket)
        await async_sock.recv()
        mock_schannel_socket.recv.assert_called_once_with(4096)

    async def test_recv_eof(
        self, mock_schannel_socket: MagicMock
    ) -> None:
        async_sock = _make_async_socket(mock_schannel_socket)
        mock_schannel_socket.recv.return_value = b""
        result = await async_sock.recv(4096)
        assert result == b""


@pytest.mark.unit
class TestSend:
    """Test async send operations."""

    async def test_send_data(
        self, mock_schannel_socket: MagicMock
    ) -> None:
        async_sock = _make_async_socket(mock_schannel_socket)
        mock_schannel_socket.send.return_value = 5
        result = await async_sock.send(b"hello")
        assert result == 5
        mock_schannel_socket.send.assert_called_once_with(b"hello")

    async def test_send_large_data(
        self, mock_schannel_socket: MagicMock
    ) -> None:
        async_sock = _make_async_socket(mock_schannel_socket)
        large_data = b"x" * 65536
        mock_schannel_socket.send.return_value = 65536
        result = await async_sock.send(large_data)
        assert result == 65536


@pytest.mark.unit
class TestClose:
    """Test async close operations."""

    async def test_close(
        self, mock_schannel_socket: MagicMock
    ) -> None:
        async_sock = _make_async_socket(mock_schannel_socket)
        await async_sock.close()
        mock_schannel_socket.close.assert_called_once()


@pytest.mark.unit
class TestMetadata:
    """Test TLS metadata accessors (synchronous delegation)."""

    async def test_selected_alpn_protocol(
        self, mock_schannel_socket: MagicMock
    ) -> None:
        async_sock = _make_async_socket(mock_schannel_socket)
        mock_schannel_socket.selected_alpn_protocol.return_value = "h2"
        assert async_sock.selected_alpn_protocol() == "h2"

    async def test_selected_alpn_protocol_none(
        self, mock_schannel_socket: MagicMock
    ) -> None:
        async_sock = _make_async_socket(mock_schannel_socket)
        mock_schannel_socket.selected_alpn_protocol.return_value = None
        assert async_sock.selected_alpn_protocol() is None

    async def test_cipher(
        self, mock_schannel_socket: MagicMock
    ) -> None:
        async_sock = _make_async_socket(mock_schannel_socket)
        mock_schannel_socket.cipher.return_value = ("AES256-SHA", "TLSv1.3", 256)
        result = async_sock.cipher()
        assert result == ("AES256-SHA", "TLSv1.3", 256)

    async def test_cipher_none(
        self, mock_schannel_socket: MagicMock
    ) -> None:
        async_sock = _make_async_socket(mock_schannel_socket)
        mock_schannel_socket.cipher.return_value = None
        assert async_sock.cipher() is None

    async def test_version(
        self, mock_schannel_socket: MagicMock
    ) -> None:
        async_sock = _make_async_socket(mock_schannel_socket)
        mock_schannel_socket.version.return_value = "TLSv1.3"
        assert async_sock.version() == "TLSv1.3"

    async def test_version_none(
        self, mock_schannel_socket: MagicMock
    ) -> None:
        async_sock = _make_async_socket(mock_schannel_socket)
        mock_schannel_socket.version.return_value = None
        assert async_sock.version() is None

    async def test_server_hostname(
        self, mock_schannel_socket: MagicMock
    ) -> None:
        async_sock = _make_async_socket(mock_schannel_socket)
        mock_schannel_socket.server_hostname = "test.example.com"
        assert async_sock.server_hostname == "test.example.com"

    async def test_underlying_socket(
        self, mock_schannel_socket: MagicMock
    ) -> None:
        async_sock = _make_async_socket(mock_schannel_socket)
        assert async_sock.underlying_socket is mock_schannel_socket


@pytest.mark.unit
class TestContextManager:
    """Test async context manager protocol."""

    async def test_aenter_returns_self(
        self, mock_schannel_socket: MagicMock
    ) -> None:
        async_sock = _make_async_socket(mock_schannel_socket)
        async with async_sock as sock:
            assert sock is async_sock

    async def test_aexit_calls_close(
        self, mock_schannel_socket: MagicMock
    ) -> None:
        async_sock = _make_async_socket(mock_schannel_socket)
        async with async_sock:
            pass
        mock_schannel_socket.close.assert_called_once()

    async def test_aexit_calls_close_on_exception(
        self, mock_schannel_socket: MagicMock
    ) -> None:
        async_sock = _make_async_socket(mock_schannel_socket)
        with pytest.raises(RuntimeError):
            async with async_sock:
                raise RuntimeError("test error")
        mock_schannel_socket.close.assert_called_once()
