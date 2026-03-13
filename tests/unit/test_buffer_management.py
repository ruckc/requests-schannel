"""Tests for SecBuffer/SecBufferDesc construction and buffer management."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

from requests_schannel._constants import (
    SECBUFFER_DATA,
    SECBUFFER_EMPTY,
    SECBUFFER_EXTRA,
    SECBUFFER_STREAM_HEADER,
    SECBUFFER_STREAM_TRAILER,
    SECBUFFER_TOKEN,
)


@pytest.mark.unit
class TestBufferConstants:
    """Verify buffer type constants are correct."""

    def test_secbuffer_types_distinct(self) -> None:
        types = [
            SECBUFFER_EMPTY,
            SECBUFFER_DATA,
            SECBUFFER_TOKEN,
            SECBUFFER_EXTRA,
            SECBUFFER_STREAM_HEADER,
            SECBUFFER_STREAM_TRAILER,
        ]
        assert len(set(types)) == len(types), "Buffer types must be unique"


@pytest.mark.unit
@pytest.mark.skipif(sys.platform != "win32", reason="ctypes backend requires Windows")
class TestCtypesBufferConstruction:
    """Test ctypes buffer construction (Windows only)."""

    def test_import_ctypes_backend(self) -> None:
        """Verify ctypes backend can be imported on Windows."""
        from requests_schannel.backends.ctypes_backend import CtypesBackend

        backend = CtypesBackend()
        assert backend is not None


@pytest.mark.unit
class TestSchannelSocketBuffering:
    """Test SchannelSocket internal buffer management."""

    def test_recv_buffer_starts_empty(self) -> None:
        """New SchannelSocket should have empty receive buffer."""
        import socket

        from requests_schannel.backend import CredentialHandle
        from requests_schannel.socket import SchannelSocket

        sock = SchannelSocket(
            sock=MagicMock(spec=socket.socket),
            backend=MagicMock(),
            credential=CredentialHandle(handle="cred"),
            server_hostname="host",
            flags=0,
        )
        assert sock._recv_buffer == b""
        assert sock._plaintext_buffer == b""

    def test_plaintext_buffer_drains_correctly(self, mock_backend: MagicMock) -> None:
        """Plaintext buffer should drain in order when recv is called multiple times."""
        import socket

        from requests_schannel.backend import CredentialHandle, HandshakeResult
        from requests_schannel.socket import SchannelSocket

        raw = MagicMock(spec=socket.socket)
        sock = SchannelSocket(
            sock=raw,
            backend=mock_backend,
            credential=CredentialHandle(handle="cred"),
            server_hostname="host",
            flags=0,
        )
        # Simulate connected state
        mock_backend.handshake_step.return_value = HandshakeResult(
            output_token=b"", complete=True
        )
        sock.do_handshake()

        # Inject plaintext buffer directly
        sock._plaintext_buffer = b"ABCDEFGHIJ"

        # Read 3 bytes at a time
        assert sock.recv(3) == b"ABC"
        assert sock.recv(3) == b"DEF"
        assert sock.recv(3) == b"GHI"
        assert sock.recv(3) == b"J"

    def test_recv_into_works(self, mock_backend: MagicMock) -> None:
        """recv_into should write to provided buffer."""
        import socket

        from requests_schannel.backend import CredentialHandle, HandshakeResult
        from requests_schannel.socket import SchannelSocket

        raw = MagicMock(spec=socket.socket)
        sock = SchannelSocket(
            sock=raw,
            backend=mock_backend,
            credential=CredentialHandle(handle="cred"),
            server_hostname="host",
            flags=0,
        )
        mock_backend.handshake_step.return_value = HandshakeResult(
            output_token=b"", complete=True
        )
        sock.do_handshake()

        sock._plaintext_buffer = b"Hello"
        buf = bytearray(10)
        n = sock.recv_into(buf, 5)
        assert n == 5
        assert buf[:5] == b"Hello"
