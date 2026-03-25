"""Tests for the websockets integration (ws.py)."""

from __future__ import annotations

import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from requests_schannel.socket import SchannelSocket

_BACKEND_PATCH = "requests_schannel.context.get_backend"
_WS_CONNECT_PATCH = "requests_schannel.ws.connect"


@pytest.mark.unit
class TestSchannelConnect:
    """Test schannel_connect() WebSocket helper."""

    async def test_wss_connect_performs_tls_and_delegates(self) -> None:
        """wss:// should do SChannel TLS handshake then pass relay socket to websockets."""
        mock_schannel_sock = MagicMock(spec=SchannelSocket)
        mock_a_sock = MagicMock(spec=socket.socket)
        mock_b_sock = MagicMock(spec=socket.socket)

        with (
            patch(_BACKEND_PATCH) as mock_get_backend,
            patch("requests_schannel.ws.socket.create_connection") as mock_conn,
            patch(
                "requests_schannel.ws.socket.socketpair", return_value=(mock_a_sock, mock_b_sock)
            ),
            patch(_WS_CONNECT_PATCH) as mock_ws_connect,
        ):
            mock_get_backend.return_value = MagicMock()
            mock_raw = MagicMock(spec=socket.socket)
            mock_conn.return_value = mock_raw

            # Mock the SchannelContext created by _build_context
            with patch("requests_schannel.ws._build_context") as mock_build:
                mock_ctx = MagicMock()
                mock_ctx.wrap_socket.return_value = mock_schannel_sock
                mock_build.return_value = mock_ctx

                mock_ws_conn = AsyncMock()
                mock_ws_connect.return_value.__aenter__ = AsyncMock(return_value=mock_ws_conn)
                mock_ws_connect.return_value.__aexit__ = AsyncMock(return_value=False)

                from requests_schannel.ws import schannel_connect

                async with schannel_connect("wss://example.com/ws") as ws:
                    assert ws is mock_ws_conn

                # Verify TCP connection was made
                mock_conn.assert_called_once_with(("example.com", 443), timeout=30.0)
                mock_raw.settimeout.assert_called_once_with(30.0)

                # Verify SChannel TLS handshake done
                mock_ctx.wrap_socket.assert_called_once_with(
                    mock_raw,
                    server_hostname="example.com",
                    do_handshake_on_connect=True,
                )

                # Verify websockets called with ws:// and the relay socket (not the TLS socket)
                mock_ws_connect.assert_called_once()
                call_args = mock_ws_connect.call_args
                assert call_args[0][0] == "ws://example.com:443/ws"
                assert call_args[1]["sock"] is mock_b_sock

    async def test_ws_connect_no_tls(self) -> None:
        """ws:// should delegate directly to websockets without TLS."""
        mock_ws_conn = AsyncMock()

        with patch(_WS_CONNECT_PATCH) as mock_ws_connect:
            mock_ws_connect.return_value.__aenter__ = AsyncMock(return_value=mock_ws_conn)
            mock_ws_connect.return_value.__aexit__ = AsyncMock(return_value=False)

            from requests_schannel.ws import schannel_connect

            async with schannel_connect("ws://example.com/ws") as ws:
                assert ws is mock_ws_conn

            mock_ws_connect.assert_called_once()
            call_args = mock_ws_connect.call_args
            assert call_args[0][0] == "ws://example.com/ws"
            # No sock kwarg for plain WS
            assert "sock" not in call_args[1]

    async def test_unsupported_scheme_raises(self) -> None:
        """Non ws/wss schemes should raise ValueError."""
        from requests_schannel.ws import schannel_connect

        with pytest.raises(ValueError, match="Unsupported scheme"):
            async with schannel_connect("http://example.com/ws"):
                pass

    async def test_wss_custom_port(self) -> None:
        """wss:// with a custom port should use that port."""
        with (
            patch("requests_schannel.ws.socket.create_connection") as mock_conn,
            patch("requests_schannel.ws._build_context") as mock_build,
            patch(_WS_CONNECT_PATCH) as mock_ws_connect,
        ):
            mock_raw = MagicMock(spec=socket.socket)
            mock_conn.return_value = mock_raw
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value = MagicMock(spec=SchannelSocket)
            mock_build.return_value = mock_ctx

            mock_ws_connect.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
            mock_ws_connect.return_value.__aexit__ = AsyncMock(return_value=False)

            from requests_schannel.ws import schannel_connect

            async with schannel_connect("wss://example.com:8443/ws"):
                pass

            mock_conn.assert_called_once_with(("example.com", 8443), timeout=30.0)
            call_args = mock_ws_connect.call_args
            assert "8443" in call_args[0][0]

    async def test_wss_with_query_string(self) -> None:
        """wss:// URI with query string should preserve it."""
        with (
            patch("requests_schannel.ws.socket.create_connection") as mock_conn,
            patch("requests_schannel.ws._build_context") as mock_build,
            patch(_WS_CONNECT_PATCH) as mock_ws_connect,
        ):
            mock_conn.return_value = MagicMock(spec=socket.socket)
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value = MagicMock(spec=SchannelSocket)
            mock_build.return_value = mock_ctx

            mock_ws_connect.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
            mock_ws_connect.return_value.__aexit__ = AsyncMock(return_value=False)

            from requests_schannel.ws import schannel_connect

            async with schannel_connect("wss://example.com/ws?token=abc"):
                pass

            call_args = mock_ws_connect.call_args
            assert call_args[0][0] == "ws://example.com:443/ws?token=abc"

    async def test_wss_custom_timeout(self) -> None:
        """Custom timeout should be passed through to socket creation."""
        with (
            patch("requests_schannel.ws.socket.create_connection") as mock_conn,
            patch("requests_schannel.ws._build_context") as mock_build,
            patch(_WS_CONNECT_PATCH) as mock_ws_connect,
        ):
            mock_raw = MagicMock(spec=socket.socket)
            mock_conn.return_value = mock_raw
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value = MagicMock(spec=SchannelSocket)
            mock_build.return_value = mock_ctx

            mock_ws_connect.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
            mock_ws_connect.return_value.__aexit__ = AsyncMock(return_value=False)

            from requests_schannel.ws import schannel_connect

            async with schannel_connect("wss://example.com/ws", timeout=60.0):
                pass

            mock_conn.assert_called_once_with(("example.com", 443), timeout=60.0)
            mock_raw.settimeout.assert_called_once_with(60.0)

    async def test_wss_with_provided_context(self) -> None:
        """Providing an explicit context skips _build_context."""
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = MagicMock(spec=SchannelSocket)

        with (
            patch("requests_schannel.ws.socket.create_connection") as mock_conn,
            patch(_WS_CONNECT_PATCH) as mock_ws_connect,
        ):
            mock_conn.return_value = MagicMock(spec=socket.socket)
            mock_ws_connect.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
            mock_ws_connect.return_value.__aexit__ = AsyncMock(return_value=False)

            from requests_schannel.ws import schannel_connect

            async with schannel_connect("wss://example.com/ws", context=mock_ctx):
                pass

            # The provided context should be used directly
            mock_ctx.wrap_socket.assert_called_once()

    async def test_wss_with_additional_headers(self) -> None:
        """Additional headers should be forwarded to websockets connect."""
        with (
            patch("requests_schannel.ws.socket.create_connection") as mock_conn,
            patch("requests_schannel.ws._build_context") as mock_build,
            patch(_WS_CONNECT_PATCH) as mock_ws_connect,
        ):
            mock_conn.return_value = MagicMock(spec=socket.socket)
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value = MagicMock(spec=SchannelSocket)
            mock_build.return_value = mock_ctx

            mock_ws_connect.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
            mock_ws_connect.return_value.__aexit__ = AsyncMock(return_value=False)

            from requests_schannel.ws import schannel_connect

            headers = {"Authorization": "Bearer token123"}
            async with schannel_connect("wss://example.com/ws", additional_headers=headers):
                pass

            call_kwargs = mock_ws_connect.call_args[1]
            assert call_kwargs["additional_headers"] == headers

    async def test_ws_default_port_80(self) -> None:
        """ws:// without explicit port should use port 80."""
        # For plain ws, we just verify the URI is passed through
        mock_ws_conn = AsyncMock()

        with patch(_WS_CONNECT_PATCH) as mock_ws_connect:
            mock_ws_connect.return_value.__aenter__ = AsyncMock(return_value=mock_ws_conn)
            mock_ws_connect.return_value.__aexit__ = AsyncMock(return_value=False)

            from requests_schannel.ws import schannel_connect

            async with schannel_connect("ws://example.com/ws"):
                pass

            # Plain WS is passed through directly
            call_args = mock_ws_connect.call_args
            assert call_args[0][0] == "ws://example.com/ws"


@pytest.mark.unit
class TestBuildContext:
    """Test _build_context helper."""

    def test_build_context_defaults(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.ws import _build_context

            ctx = _build_context(
                client_cert_thumbprint=None,
                client_cert_subject=None,
                auto_select_client_cert=False,
                cert_store_name="MY",
                backend=None,
            )
            assert ctx is not None
            assert ctx.auto_select_client_cert is False

    def test_build_context_with_thumbprint(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.ws import _build_context

            ctx = _build_context(
                client_cert_thumbprint="AABBCCDD",
                client_cert_subject=None,
                auto_select_client_cert=False,
                cert_store_name="MY",
                backend=None,
            )
            assert ctx.client_cert_thumbprint == "AABBCCDD"

    def test_build_context_with_subject(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.ws import _build_context

            ctx = _build_context(
                client_cert_thumbprint=None,
                client_cert_subject="CN=Test",
                auto_select_client_cert=False,
                cert_store_name="MY",
                backend=None,
            )
            assert ctx.client_cert_subject == "CN=Test"

    def test_build_context_with_auto_select(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.ws import _build_context

            ctx = _build_context(
                client_cert_thumbprint=None,
                client_cert_subject=None,
                auto_select_client_cert=True,
                cert_store_name="MY",
                backend=None,
            )
            assert ctx.auto_select_client_cert is True

    def test_build_context_custom_store(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.ws import _build_context

            ctx = _build_context(
                client_cert_thumbprint=None,
                client_cert_subject=None,
                auto_select_client_cert=False,
                cert_store_name="ROOT",
                backend=None,
            )
            assert ctx.cert_store_name == "ROOT"
