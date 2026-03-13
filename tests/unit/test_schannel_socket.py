"""Tests for SchannelSocket wrapping and I/O operations."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock

import pytest

from requests_schannel._errors import SchannelError
from requests_schannel.backend import (
    CredentialHandle,
    HandshakeResult,
)
from requests_schannel.socket import SchannelSocket


@pytest.fixture
def raw_socket() -> MagicMock:
    """Mock raw TCP socket."""
    sock = MagicMock(spec=socket.socket)
    sock.recv.return_value = b""
    sock.fileno.return_value = 5
    return sock


@pytest.fixture
def schannel_socket(raw_socket: MagicMock, mock_backend: MagicMock) -> SchannelSocket:
    """Create a SchannelSocket with mock backend."""
    credential = CredentialHandle(handle="cred")
    return SchannelSocket(
        sock=raw_socket,
        backend=mock_backend,
        credential=credential,
        server_hostname="example.com",
        flags=0,
        alpn_protocols=["http/1.1"],
    )


@pytest.mark.unit
class TestHandshake:
    """Test TLS handshake flow."""

    def test_handshake_completes_immediately(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock
    ) -> None:
        """Backend returns complete=True on first step."""
        mock_backend.handshake_step.return_value = HandshakeResult(
            output_token=b"", complete=True
        )
        schannel_socket.do_handshake()
        assert mock_backend.create_context.called

    def test_handshake_multi_step(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """Simulate a 2-step handshake."""
        mock_backend.handshake_step.side_effect = [
            HandshakeResult(output_token=b"client_hello", complete=False),
            HandshakeResult(output_token=b"client_fin", complete=True, extra_data=b""),
        ]
        raw_socket.recv.return_value = b"server_hello"

        schannel_socket.do_handshake()
        assert mock_backend.handshake_step.call_count == 2
        assert raw_socket.sendall.call_count == 2

    def test_handshake_idempotent(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock
    ) -> None:
        """Calling do_handshake twice doesn't re-handshake."""
        mock_backend.handshake_step.return_value = HandshakeResult(
            output_token=b"", complete=True
        )
        schannel_socket.do_handshake()
        schannel_socket.do_handshake()
        assert mock_backend.create_context.call_count == 1

    def test_handshake_preserves_extra_data(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """Extra data from handshake is preserved in recv buffer."""
        mock_backend.handshake_step.side_effect = [
            HandshakeResult(output_token=b"hello", complete=False),
            HandshakeResult(output_token=b"", complete=True, extra_data=b"leftover"),
        ]
        raw_socket.recv.return_value = b"server_data"

        schannel_socket.do_handshake()
        # Extra data should be in the recv buffer
        assert schannel_socket._recv_buffer == b"leftover"


@pytest.mark.unit
class TestRecv:
    """Test receive/decrypt operations."""

    def test_recv_before_handshake_raises(self, schannel_socket: SchannelSocket) -> None:
        with pytest.raises(SchannelError, match="handshake"):
            schannel_socket.recv()

    def test_recv_returns_decrypted_data(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        mock_backend.handshake_step.return_value = HandshakeResult(
            output_token=b"", complete=True
        )
        schannel_socket.do_handshake()

        raw_socket.recv.return_value = b"encrypted_data"
        mock_backend.decrypt.return_value = (b"hello world", b"")

        result = schannel_socket.recv(4096)
        assert result == b"hello world"

    def test_recv_buffers_excess_data(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """When decrypt returns more than requested, excess is buffered."""
        mock_backend.handshake_step.return_value = HandshakeResult(
            output_token=b"", complete=True
        )
        schannel_socket.do_handshake()

        raw_socket.recv.return_value = b"encrypted"
        mock_backend.decrypt.return_value = (b"0123456789", b"")

        # Read only 5 bytes
        result = schannel_socket.recv(5)
        assert result == b"01234"

        # Next read should return buffered data
        result2 = schannel_socket.recv(5)
        assert result2 == b"56789"

    def test_recv_after_close_raises(self, schannel_socket: SchannelSocket) -> None:
        schannel_socket._closed = True
        with pytest.raises(SchannelError, match="closed"):
            schannel_socket.recv()

    def test_read_aliases_recv(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        mock_backend.handshake_step.return_value = HandshakeResult(
            output_token=b"", complete=True
        )
        schannel_socket.do_handshake()
        raw_socket.recv.return_value = b"enc"
        mock_backend.decrypt.return_value = (b"data", b"")

        assert schannel_socket.read(4096) == b"data"


@pytest.mark.unit
class TestSend:
    """Test send/encrypt operations."""

    def test_send_before_handshake_raises(self, schannel_socket: SchannelSocket) -> None:
        with pytest.raises(SchannelError, match="handshake"):
            schannel_socket.send(b"data")

    def test_send_encrypts_and_sends(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        mock_backend.handshake_step.return_value = HandshakeResult(
            output_token=b"", complete=True
        )
        schannel_socket.do_handshake()

        mock_backend.encrypt.side_effect = None
        mock_backend.encrypt.return_value = b"encrypted_payload"
        result = schannel_socket.send(b"hello")
        assert result == 5
        raw_socket.sendall.assert_called_with(b"encrypted_payload")

    def test_write_aliases_send(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        mock_backend.handshake_step.return_value = HandshakeResult(
            output_token=b"", complete=True
        )
        schannel_socket.do_handshake()
        mock_backend.encrypt.return_value = b"enc"

        assert schannel_socket.write(b"data") == 4

    def test_sendall(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        mock_backend.handshake_step.return_value = HandshakeResult(
            output_token=b"", complete=True
        )
        schannel_socket.do_handshake()
        mock_backend.encrypt.return_value = b"enc"

        schannel_socket.sendall(b"data")
        assert raw_socket.sendall.called


@pytest.mark.unit
class TestMetadata:
    """Test TLS metadata methods."""

    def _handshake(self, sock: SchannelSocket, backend: MagicMock) -> None:
        backend.handshake_step.return_value = HandshakeResult(
            output_token=b"", complete=True
        )
        sock.do_handshake()

    def test_selected_alpn_protocol(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock
    ) -> None:
        self._handshake(schannel_socket, mock_backend)
        mock_backend.get_negotiated_protocol.return_value = "http/1.1"
        assert schannel_socket.selected_alpn_protocol() == "http/1.1"

    def test_alpn_none_before_handshake(self, schannel_socket: SchannelSocket) -> None:
        assert schannel_socket.selected_alpn_protocol() is None

    def test_cipher(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock
    ) -> None:
        self._handshake(schannel_socket, mock_backend)
        result = schannel_socket.cipher()
        assert result is not None
        assert len(result) == 3
        assert result[1] == "TLSv1.2"
        assert result[2] == 256

    def test_version(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock
    ) -> None:
        self._handshake(schannel_socket, mock_backend)
        assert schannel_socket.version() == "TLSv1.2"

    def test_getpeercert_binary(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock
    ) -> None:
        self._handshake(schannel_socket, mock_backend)
        cert = schannel_socket.getpeercert(binary_form=True)
        assert isinstance(cert, bytes)

    def test_getpeercert_dict(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock
    ) -> None:
        self._handshake(schannel_socket, mock_backend)
        cert = schannel_socket.getpeercert(binary_form=False)
        assert isinstance(cert, dict)
        assert "sha256_digest" in cert

    def test_server_hostname(self, schannel_socket: SchannelSocket) -> None:
        assert schannel_socket.server_hostname == "example.com"

    def test_fileno(self, schannel_socket: SchannelSocket, raw_socket: MagicMock) -> None:
        assert schannel_socket.fileno() == 5


@pytest.mark.unit
class TestLifecycle:
    """Test socket lifecycle (close, unwrap, context manager)."""

    def test_close(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        mock_backend.handshake_step.return_value = HandshakeResult(
            output_token=b"", complete=True
        )
        schannel_socket.do_handshake()
        schannel_socket.close()
        assert schannel_socket._closed
        raw_socket.close.assert_called_once()

    def test_close_idempotent(
        self, schannel_socket: SchannelSocket, raw_socket: MagicMock
    ) -> None:
        schannel_socket.close()
        schannel_socket.close()
        # Should not raise

    def test_unwrap_returns_raw_socket(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        mock_backend.handshake_step.return_value = HandshakeResult(
            output_token=b"", complete=True
        )
        schannel_socket.do_handshake()
        result = schannel_socket.unwrap()
        assert result is raw_socket

    def test_context_manager(
        self, schannel_socket: SchannelSocket, raw_socket: MagicMock
    ) -> None:
        with schannel_socket:
            pass
        assert schannel_socket._closed

    def test_settimeout(self, schannel_socket: SchannelSocket, raw_socket: MagicMock) -> None:
        schannel_socket.settimeout(5.0)
        raw_socket.settimeout.assert_called_with(5.0)

    def test_setblocking(self, schannel_socket: SchannelSocket, raw_socket: MagicMock) -> None:
        schannel_socket.setblocking(False)
        raw_socket.setblocking.assert_called_with(False)


@pytest.mark.unit
class TestMakefile:
    """Test makefile() for http.client compatibility."""

    def test_makefile_binary_read(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        mock_backend.handshake_step.return_value = HandshakeResult(
            output_token=b"", complete=True
        )
        schannel_socket.do_handshake()

        raw_socket.recv.return_value = b"encrypted"
        mock_backend.decrypt.return_value = (b"hello", b"")

        f = schannel_socket.makefile("rb")
        assert hasattr(f, "read")
        f.close()

    def test_makefile_returns_buffered(
        self, schannel_socket: SchannelSocket, mock_backend: MagicMock
    ) -> None:
        mock_backend.handshake_step.return_value = HandshakeResult(
            output_token=b"", complete=True
        )
        schannel_socket.do_handshake()

        f = schannel_socket.makefile("rb")
        import io
        assert isinstance(f, io.BufferedReader)
        f.close()
