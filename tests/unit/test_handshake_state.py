"""Tests for the TLS handshake state machine."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from requests_schannel._constants import (
    ISC_REQ_TLS_CLIENT,
    ISC_REQ_TLS_CLIENT_MTLS,
)
from requests_schannel._errors import HandshakeError
from requests_schannel.backend import (
    CredentialHandle,
    HandshakeResult,
)
from requests_schannel.socket import SchannelSocket


@pytest.fixture
def raw_socket() -> MagicMock:
    import socket

    sock = MagicMock(spec=socket.socket)
    sock.recv.return_value = b"server_response"
    return sock


@pytest.mark.unit
class TestHandshakeStateMachine:
    """Test the SchannelSocket handshake state machine."""

    def test_initial_state(self, mock_backend: MagicMock, raw_socket: MagicMock) -> None:
        sock = SchannelSocket(
            sock=raw_socket,
            backend=mock_backend,
            credential=CredentialHandle(handle="cred"),
            server_hostname="host",
            flags=ISC_REQ_TLS_CLIENT,
        )
        assert not sock._connected
        assert sock._context is None

    def test_single_step_handshake(self, mock_backend: MagicMock, raw_socket: MagicMock) -> None:
        """Handshake completes in one step (unusual but valid)."""
        mock_backend.handshake_step.return_value = HandshakeResult(output_token=b"", complete=True)

        sock = SchannelSocket(
            sock=raw_socket,
            backend=mock_backend,
            credential=CredentialHandle(handle="cred"),
            server_hostname="host",
            flags=ISC_REQ_TLS_CLIENT,
        )
        sock.do_handshake()

        assert sock._connected
        assert sock._context is not None

    def test_two_step_handshake(self, mock_backend: MagicMock, raw_socket: MagicMock) -> None:
        """Normal 2-step handshake: ClientHello → ServerHello → Finish."""
        mock_backend.handshake_step.side_effect = [
            HandshakeResult(output_token=b"client_hello", complete=False),
            HandshakeResult(output_token=b"finished", complete=True),
        ]

        sock = SchannelSocket(
            sock=raw_socket,
            backend=mock_backend,
            credential=CredentialHandle(handle="cred"),
            server_hostname="host",
            flags=ISC_REQ_TLS_CLIENT,
        )
        sock.do_handshake()

        assert sock._connected
        assert mock_backend.handshake_step.call_count == 2

    def test_three_step_handshake(self, mock_backend: MagicMock, raw_socket: MagicMock) -> None:
        """3-step handshake with multiple continue rounds."""
        mock_backend.handshake_step.side_effect = [
            HandshakeResult(output_token=b"msg1", complete=False),
            HandshakeResult(output_token=b"msg2", complete=False),
            HandshakeResult(output_token=b"msg3", complete=True),
        ]

        sock = SchannelSocket(
            sock=raw_socket,
            backend=mock_backend,
            credential=CredentialHandle(handle="cred"),
            server_hostname="host",
            flags=ISC_REQ_TLS_CLIENT,
        )
        sock.do_handshake()

        assert sock._connected
        assert mock_backend.handshake_step.call_count == 3

    def test_handshake_sends_output_tokens(
        self, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """Verify output tokens are sent to the server."""
        mock_backend.handshake_step.side_effect = [
            HandshakeResult(output_token=b"client_hello", complete=False),
            HandshakeResult(output_token=b"client_fin", complete=True),
        ]

        sock = SchannelSocket(
            sock=raw_socket,
            backend=mock_backend,
            credential=CredentialHandle(handle="cred"),
            server_hostname="host",
            flags=ISC_REQ_TLS_CLIENT,
        )
        sock.do_handshake()

        calls = raw_socket.sendall.call_args_list
        assert calls[0].args[0] == b"client_hello"
        assert calls[1].args[0] == b"client_fin"

    def test_handshake_reads_server_tokens(
        self, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """Verify server data is read during handshake."""
        raw_socket.recv.return_value = b"server_token_data"
        mock_backend.handshake_step.side_effect = [
            HandshakeResult(output_token=b"hello", complete=False),
            HandshakeResult(output_token=b"", complete=True),
        ]

        sock = SchannelSocket(
            sock=raw_socket,
            backend=mock_backend,
            credential=CredentialHandle(handle="cred"),
            server_hostname="host",
            flags=ISC_REQ_TLS_CLIENT,
        )
        sock.do_handshake()

        # Server data was read
        assert raw_socket.recv.called

    def test_handshake_connection_closed_raises(
        self, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """Connection closed mid-handshake should raise HandshakeError."""
        raw_socket.recv.return_value = b""  # Connection closed
        mock_backend.handshake_step.side_effect = [
            HandshakeResult(output_token=b"hello", complete=False),
        ]

        sock = SchannelSocket(
            sock=raw_socket,
            backend=mock_backend,
            credential=CredentialHandle(handle="cred"),
            server_hostname="host",
            flags=ISC_REQ_TLS_CLIENT,
        )
        with pytest.raises(HandshakeError, match="[Cc]losed"):
            sock.do_handshake()

    def test_correct_flags_passed(self, mock_backend: MagicMock, raw_socket: MagicMock) -> None:
        """Verify ISC_REQ flags are passed to create_context."""
        mock_backend.handshake_step.return_value = HandshakeResult(output_token=b"", complete=True)

        sock = SchannelSocket(
            sock=raw_socket,
            backend=mock_backend,
            credential=CredentialHandle(handle="cred"),
            server_hostname="host",
            flags=ISC_REQ_TLS_CLIENT_MTLS,
            alpn_protocols=["http/1.1"],
        )
        sock.do_handshake()

        call_kwargs = mock_backend.create_context.call_args
        assert call_kwargs.kwargs["flags"] == ISC_REQ_TLS_CLIENT_MTLS
        assert call_kwargs.kwargs["alpn_protocols"] == ["http/1.1"]
        assert call_kwargs.kwargs["target_name"] == "host"

    def test_extra_data_preserved(self, mock_backend: MagicMock, raw_socket: MagicMock) -> None:
        """Extra data from handshake step is preserved for decryption."""
        mock_backend.handshake_step.side_effect = [
            HandshakeResult(output_token=b"hello", complete=False),
            HandshakeResult(output_token=b"", complete=True, extra_data=b"app_data"),
        ]

        sock = SchannelSocket(
            sock=raw_socket,
            backend=mock_backend,
            credential=CredentialHandle(handle="cred"),
            server_hostname="host",
            flags=ISC_REQ_TLS_CLIENT,
        )
        sock.do_handshake()

        assert sock._recv_buffer == b"app_data"

    def test_empty_output_token_not_sent(
        self, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """Empty output tokens should not be sent to the server."""
        mock_backend.handshake_step.return_value = HandshakeResult(output_token=b"", complete=True)

        sock = SchannelSocket(
            sock=raw_socket,
            backend=mock_backend,
            credential=CredentialHandle(handle="cred"),
            server_hostname="host",
            flags=ISC_REQ_TLS_CLIENT,
        )
        sock.do_handshake()

        raw_socket.sendall.assert_not_called()
