"""Tests for large file handling: chunked sends, streaming receives, and memory bounds.

These tests verify that the SchannelSocket correctly:
- Splits large uploads into TLS-record-sized chunks (no bloat on send path)
- Streams large downloads without buffering all decrypted data in memory
- Works correctly with makefile()/io.BufferedReader for HTTP response streaming
"""

from __future__ import annotations

import io
import socket
from unittest.mock import MagicMock, call

import pytest

from requests_schannel.backend import CredentialHandle, HandshakeResult
from requests_schannel.socket import SchannelSocket

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def raw_socket() -> MagicMock:
    """Mock raw TCP socket."""
    sock = MagicMock(spec=socket.socket)
    sock.recv.return_value = b""
    sock.fileno.return_value = 5
    return sock


@pytest.fixture
def connected_socket(raw_socket: MagicMock, mock_backend: MagicMock) -> SchannelSocket:
    """SchannelSocket with a completed TLS handshake."""
    credential = CredentialHandle(handle="cred")
    sock = SchannelSocket(
        sock=raw_socket,
        backend=mock_backend,
        credential=credential,
        server_hostname="example.com",
        flags=0,
    )
    mock_backend.handshake_step.return_value = HandshakeResult(output_token=b"", complete=True)
    sock.do_handshake()
    return sock


# ---------------------------------------------------------------------------
# Large upload (send) tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLargeUploadChunking:
    """Verify large payloads are split into max_message-sized TLS records."""

    def test_send_splits_into_max_message_chunks(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """Sending N * max_message bytes should call encrypt exactly N times."""
        max_msg = 16384
        num_chunks = 10
        data = b"A" * (max_msg * num_chunks)

        mock_backend.encrypt.side_effect = None
        mock_backend.encrypt.return_value = b"\x00"  # minimal encrypted output

        bytes_sent = connected_socket.send(data)

        assert bytes_sent == len(data)
        assert mock_backend.encrypt.call_count == num_chunks
        # Each call should receive exactly max_msg bytes
        for encrypt_call in mock_backend.encrypt.call_args_list:
            chunk = encrypt_call[0][1]  # positional arg 1 is the plaintext
            assert len(chunk) == max_msg

    def test_send_final_chunk_smaller_than_max(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """The last chunk may be smaller than max_message (remainder bytes)."""
        max_msg = 16384
        remainder = 999
        data = b"B" * (max_msg * 3 + remainder)

        mock_backend.encrypt.side_effect = None
        mock_backend.encrypt.return_value = b"\x00"

        connected_socket.send(data)

        assert mock_backend.encrypt.call_count == 4
        last_chunk = mock_backend.encrypt.call_args_list[-1][0][1]
        assert len(last_chunk) == remainder

    def test_sendall_large_data_fully_delivered(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """sendall() with large data calls sendall on underlying socket for each chunk."""
        max_msg = 16384
        data = b"C" * (max_msg * 5)

        mock_backend.encrypt.side_effect = None
        mock_backend.encrypt.return_value = b"enc_record"

        connected_socket.sendall(data)

        # Each chunk must be sent via the raw socket's sendall
        assert raw_socket.sendall.call_count == 5
        assert all(c == call(b"enc_record") for c in raw_socket.sendall.call_args_list)

    def test_send_does_not_hold_entire_payload_as_single_encrypt_call(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock
    ) -> None:
        """Encrypt is never called with more bytes than max_message at once."""
        max_msg = 16384
        large_payload = b"D" * (max_msg * 20)  # 320 KB

        mock_backend.encrypt.side_effect = None
        mock_backend.encrypt.return_value = b"\x00"

        connected_socket.send(large_payload)

        for encrypt_call in mock_backend.encrypt.call_args_list:
            chunk = encrypt_call[0][1]
            assert len(chunk) <= max_msg, (
                f"encrypt() called with {len(chunk)} bytes, exceeding max_message={max_msg}"
            )

    def test_send_single_byte_still_encrypted(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """Sending a single byte still goes through encrypt+sendall."""
        mock_backend.encrypt.side_effect = None
        mock_backend.encrypt.return_value = b"\x00" * 5 + b"x" + b"\x00" * 36

        result = connected_socket.send(b"x")
        assert result == 1
        assert mock_backend.encrypt.call_count == 1
        raw_socket.sendall.assert_called_once()


# ---------------------------------------------------------------------------
# Large download (recv) tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLargeDownloadStreaming:
    """Verify large downloads stream through the socket without excessive buffering."""

    def test_recv_processes_records_one_at_a_time(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """Each recv() call decrypts at most one record; subsequent calls drain the buffer."""
        record_payload = b"Z" * 16384

        # First decrypt returns full record; second returns EOF
        mock_backend.decrypt.side_effect = [
            (record_payload, b""),
            (b"", b""),
        ]
        raw_socket.recv.return_value = b"enc"

        # First recv: requests 4096, gets 4096 from the 16384-byte record
        chunk1 = connected_socket.recv(4096)
        assert chunk1 == record_payload[:4096]

        # Remaining data sits in plaintext_buffer, not requiring another network read
        assert len(connected_socket._plaintext_buffer) == 16384 - 4096

        # Subsequent reads drain from plaintext_buffer without calling decrypt again
        decrypt_count_before = mock_backend.decrypt.call_count
        chunk2 = connected_socket.recv(4096)
        assert chunk2 == record_payload[4096:8192]
        assert mock_backend.decrypt.call_count == decrypt_count_before

    def test_plaintext_buffer_bounded_by_one_record(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """After a partial read, the plaintext buffer holds at most one record's worth of data."""
        record_size = 16384
        record_payload = b"E" * record_size

        mock_backend.decrypt.return_value = (record_payload, b"")
        raw_socket.recv.return_value = b"enc"

        connected_socket.recv(1)  # consume just 1 byte

        # Buffer holds the rest of the record — at most record_size - 1
        assert len(connected_socket._plaintext_buffer) == record_size - 1

    def test_recv_buffer_cleared_after_full_consume(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """recv_buffer (encrypted side) is empty after decrypt with no extra data."""
        mock_backend.decrypt.return_value = (b"payload", b"")
        raw_socket.recv.return_value = b"encrypted_data"

        connected_socket.recv(4096)

        assert connected_socket._recv_buffer == b""

    def test_extra_data_preserved_across_records(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """Extra data from one decrypt call is carried over to the next."""
        next_record = b"next_tls_record"
        mock_backend.decrypt.return_value = (b"data", next_record)
        raw_socket.recv.return_value = b"encrypted"

        connected_socket.recv(4096)

        assert connected_socket._recv_buffer == next_record

    def test_many_records_received_sequentially(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """Receiving many records in succession yields all data in order."""
        num_records = 50
        record_payload = b"F" * 4096

        decrypt_results = [(record_payload, b"")] * num_records + [(b"", b"")]
        mock_backend.decrypt.side_effect = decrypt_results
        raw_socket.recv.return_value = b"enc"

        received = []
        for _ in range(num_records):
            chunk = connected_socket.recv(4096)
            if not chunk:
                break
            received.append(chunk)

        assert len(received) == num_records
        assert all(c == record_payload for c in received)

    def test_recv_returns_eof_on_empty_network(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """If the network returns no data and decrypt buffer is empty, recv returns b''."""
        raw_socket.recv.return_value = b""
        mock_backend.decrypt.side_effect = Exception("should not be called")

        result = connected_socket.recv(4096)
        assert result == b""


# ---------------------------------------------------------------------------
# makefile() / io.BufferedReader streaming tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMakefileStreaming:
    """Verify makefile() creates a proper streaming interface for HTTP responses."""

    def test_makefile_returns_buffered_reader(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock
    ) -> None:
        """makefile('rb') must return an io.BufferedReader."""
        f = connected_socket.makefile("rb")
        assert isinstance(f, io.BufferedReader)
        f.close()

    def test_makefile_increments_io_refs(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock
    ) -> None:
        """Each makefile() call increments _io_refs to defer socket teardown."""
        assert connected_socket._io_refs == 0
        f1 = connected_socket.makefile("rb")
        assert connected_socket._io_refs == 1
        f2 = connected_socket.makefile("rb")
        assert connected_socket._io_refs == 2
        f1.close()
        f2.close()

    def test_makefile_close_decrements_io_refs(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock
    ) -> None:
        """Closing the file object returned by makefile() decrements _io_refs."""
        f = connected_socket.makefile("rb")
        assert connected_socket._io_refs == 1
        f.close()
        assert connected_socket._io_refs == 0

    def test_makefile_streams_multiple_chunks(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """Reading from makefile() in a loop yields all data in order."""
        chunks = [b"chunk1data", b"chunk2data", b"chunk3data"]
        decrypt_results = [(c, b"") for c in chunks] + [(b"", b"")]
        mock_backend.decrypt.side_effect = decrypt_results
        raw_socket.recv.return_value = b"enc"

        f = connected_socket.makefile("rb")
        received = []
        while True:
            piece = f.read(10)
            if not piece:
                break
            received.append(piece)
        f.close()

        # All chunk data must appear in the received stream
        full_data = b"".join(received)
        assert full_data == b"chunk1datachunk2datachunk3data"

    def test_makefile_iter_content_pattern(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """Simulate requests.iter_content(chunk_size) reading pattern."""
        chunk_size = 4096
        num_chunks = 20
        payload = b"G" * chunk_size

        decrypt_results = [(payload, b"")] * num_chunks + [(b"", b"")]
        mock_backend.decrypt.side_effect = decrypt_results
        raw_socket.recv.return_value = b"enc"

        f = connected_socket.makefile("rb")
        received_chunks = []
        while True:
            piece = f.read(chunk_size)
            if not piece:
                break
            received_chunks.append(piece)
        f.close()

        assert len(received_chunks) == num_chunks
        assert sum(len(c) for c in received_chunks) == chunk_size * num_chunks


# ---------------------------------------------------------------------------
# End-to-end streaming simulation
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestStreamingTransferSimulation:
    """Simulate large file transfers to verify streaming architecture."""

    def test_simulated_large_download_no_memory_bloat(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """Simulate a 1 MB download: decrypt is called once per record, not once for all data.

        Verifies the per-record decryption pattern that keeps memory bounded
        regardless of how many records the full transfer contains.
        """
        record_size = 16384
        simulated_records = 64  # 64 * 16 KB = 1 MB to keep the test fast

        decrypt_calls = [(b"H" * record_size, b"")] * simulated_records + [(b"", b"")]
        mock_backend.decrypt.side_effect = decrypt_calls
        raw_socket.recv.return_value = b"enc"

        total_bytes = 0
        while True:
            chunk = connected_socket.recv(record_size)
            if not chunk:
                break
            total_bytes += len(chunk)
            # Invariant: plaintext_buffer must never grow beyond one record
            assert len(connected_socket._plaintext_buffer) <= record_size

        assert total_bytes == record_size * simulated_records
        # decrypt was called exactly once per record (no bulk buffering)
        assert mock_backend.decrypt.call_count == simulated_records + 1

    def test_simulated_large_upload_chunking(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """Simulate a 10 MB upload: verify it is sent in max_message-sized TLS records."""
        max_msg = 16384
        upload_size = 10 * 1024 * 1024  # 10 MB
        expected_chunks = upload_size // max_msg  # exact multiple

        mock_backend.encrypt.side_effect = None
        mock_backend.encrypt.return_value = b"\x00"  # minimal encrypted output

        bytes_sent = connected_socket.send(b"I" * upload_size)

        assert bytes_sent == upload_size
        assert mock_backend.encrypt.call_count == expected_chunks
        # Underlying socket.sendall called once per encrypted chunk
        assert raw_socket.sendall.call_count == expected_chunks

    def test_streaming_download_via_raw_io(
        self, connected_socket: SchannelSocket, mock_backend: MagicMock, raw_socket: MagicMock
    ) -> None:
        """_SchannelSocketIO.read(n) returns incremental chunks, compatible with io.RawIOBase."""
        from requests_schannel.socket import _SchannelSocketIO

        record_payload = b"J" * 8192
        decrypt_results = [(record_payload, b"")] * 4 + [(b"", b"")]
        mock_backend.decrypt.side_effect = decrypt_results
        raw_socket.recv.return_value = b"enc"

        raw_io = _SchannelSocketIO(connected_socket, "rb")
        received = []
        while True:
            buf = bytearray(8192)
            n = raw_io.readinto(buf)
            if n == 0:
                break
            received.append(bytes(buf[:n]))
        raw_io.close()

        assert len(received) == 4
        assert all(c == record_payload for c in received)
