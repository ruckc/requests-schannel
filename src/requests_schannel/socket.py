"""SchannelSocket — TLS socket wrapper using Windows SChannel.

Provides an ssl.SSLSocket-compatible interface backed by SChannel SSPI.
NOT thread-safe: one socket per connection, used by one thread at a time.
"""

from __future__ import annotations

import io
import socket
from typing import Any

from ._constants import TLS_MAX_RECORD_SIZE
from ._errors import DecryptionError, HandshakeError, SchannelError
from .backend import (
    CredentialHandle,
    SchannelBackend,
    SecurityContext,
)


class SchannelSocket:
    """A TLS-wrapped socket using Windows SChannel.

    Compatible with the ssl.SSLSocket interface expected by urllib3.
    Each instance wraps a raw socket.socket and owns one SSPI SecurityContext.
    """

    def __init__(
        self,
        sock: socket.socket,
        backend: SchannelBackend,
        credential: CredentialHandle,
        server_hostname: str,
        flags: int,
        alpn_protocols: list[str] | None = None,
    ) -> None:
        self._sock = sock
        self._backend = backend
        self._credential = credential
        self._server_hostname = server_hostname
        self._context: SecurityContext | None = None
        self._flags = flags
        self._alpn_protocols = alpn_protocols
        self._closed = False
        self._connected = False
        # Decryption buffer: holds data received from network that hasn't been decrypted yet
        self._recv_buffer = b""
        # Plaintext buffer: holds decrypted data not yet consumed by the caller
        self._plaintext_buffer = b""
        self._peer_closing = False

    # --- ssl.SSLSocket-compatible interface ---

    def do_handshake(self) -> None:
        """Perform the TLS handshake."""
        if self._connected:
            return

        self._context = self._backend.create_context(
            credential=self._credential,
            target_name=self._server_hostname,
            flags=self._flags,
            alpn_protocols=self._alpn_protocols,
        )

        # Initial handshake step (no input token)
        result = self._backend.handshake_step(self._context)

        if result.output_token:
            self._sock.sendall(result.output_token)

        # Handshake loop
        while not result.complete:
            # Read data from server
            data = self._recv_raw(TLS_MAX_RECORD_SIZE + 1024)
            if not data:
                raise HandshakeError("Connection closed during TLS handshake")

            self._recv_buffer += data

            result = self._backend.handshake_step(self._context, self._recv_buffer)

            # Handle extra data (belongs to next record)
            if result.extra_data:
                self._recv_buffer = result.extra_data
            else:
                self._recv_buffer = b""

            if result.output_token:
                self._sock.sendall(result.output_token)

        self._connected = True

    def read(self, nbytes: int = 4096) -> bytes:
        """Read up to nbytes of decrypted data."""
        return self.recv(nbytes)

    def recv(self, bufsize: int = 4096) -> bytes:
        """Receive up to bufsize bytes of decrypted data."""
        if self._closed:
            raise SchannelError("Socket is closed")
        if not self._connected or self._context is None:
            raise SchannelError("TLS handshake not completed")

        # Return buffered plaintext first
        if self._plaintext_buffer:
            chunk = self._plaintext_buffer[:bufsize]
            self._plaintext_buffer = self._plaintext_buffer[bufsize:]
            return chunk

        if self._peer_closing:
            return b""

        # Need to decrypt more data
        while True:
            # Try to decrypt what we have
            if self._recv_buffer:
                try:
                    plaintext, extra = self._backend.decrypt(self._context, self._recv_buffer)
                except DecryptionError:
                    raise
                except SchannelError:
                    raise

                if plaintext:
                    self._recv_buffer = extra
                    if len(plaintext) > bufsize:
                        self._plaintext_buffer = plaintext[bufsize:]
                        return plaintext[:bufsize]
                    return plaintext

                if not plaintext and not extra:
                    # close_notify received
                    self._peer_closing = True
                    return b""

            # Need more data from network
            data = self._recv_raw(TLS_MAX_RECORD_SIZE + 1024)
            if not data:
                return b""
            self._recv_buffer += data

    def recv_into(self, buffer: bytearray | memoryview, nbytes: int = 0) -> int:
        """Receive into a pre-allocated buffer."""
        if nbytes == 0:
            nbytes = len(buffer)
        data = self.recv(nbytes)
        n = len(data)
        buffer[:n] = data
        return n

    def write(self, data: bytes) -> int:
        """Write data through the TLS connection."""
        return self.send(data)

    def send(self, data: bytes) -> int:
        """Send data through the TLS connection."""
        if self._closed:
            raise SchannelError("Socket is closed")
        if not self._connected or self._context is None:
            raise SchannelError("TLS handshake not completed")

        sizes = self._backend.get_stream_sizes(self._context)
        max_chunk = sizes.max_message

        sent = 0
        while sent < len(data):
            chunk = data[sent : sent + max_chunk]
            encrypted = self._backend.encrypt(self._context, chunk)
            self._sock.sendall(encrypted)
            sent += len(chunk)
        return sent

    def sendall(self, data: bytes) -> None:
        """Send all data through the TLS connection."""
        self.send(data)

    def getpeercert(self, binary_form: bool = False) -> Any:
        """Get the peer's certificate.

        Args:
            binary_form: If True, return DER-encoded bytes. If False, return
                        a dict (simplified — full parsing requires pyasn1).
        """
        if not self._connected or self._context is None:
            return None
        der = self._backend.get_peer_certificate(self._context)
        if binary_form:
            return der
        # Simplified: return thumbprint and raw DER
        import hashlib

        return {"sha256_digest": hashlib.sha256(der).hexdigest(), "der": der}

    def selected_alpn_protocol(self) -> str | None:
        """Get the ALPN-negotiated application protocol."""
        if not self._connected or self._context is None:
            return None
        return self._backend.get_negotiated_protocol(self._context)

    def cipher(self) -> tuple[str, str, int] | None:
        """Get current cipher info: (cipher_name, tls_version, key_bits)."""
        if not self._connected or self._context is None:
            return None
        info = self._backend.get_connection_info(self._context)
        cipher_name = f"0x{info.cipher_algorithm:04X}"
        return cipher_name, info.protocol_version, info.cipher_strength

    def version(self) -> str | None:
        """Get the TLS version string (e.g. 'TLSv1.2')."""
        if not self._connected or self._context is None:
            return None
        info = self._backend.get_connection_info(self._context)
        return info.protocol_version

    def unwrap(self) -> socket.socket:
        """Perform TLS shutdown and return the underlying raw socket."""
        if self._context is not None and self._connected:
            try:
                shutdown_token = self._backend.shutdown(self._context)
                if shutdown_token:
                    self._sock.sendall(shutdown_token)
            except OSError:
                pass
            self._backend.free_context(self._context)
            self._context = None
        self._connected = False
        return self._sock

    def close(self) -> None:
        """Close the TLS connection and underlying socket."""
        if self._closed:
            return
        self._closed = True
        try:
            self.unwrap()
        except Exception:
            pass
        try:
            self._sock.close()
        except OSError:
            pass

    def fileno(self) -> int:
        """Return the underlying socket's file descriptor."""
        return self._sock.fileno()

    def settimeout(self, timeout: float | None) -> None:
        self._sock.settimeout(timeout)

    def gettimeout(self) -> float | None:
        return self._sock.gettimeout()

    def setblocking(self, flag: bool) -> None:
        self._sock.setblocking(flag)

    @property
    def server_hostname(self) -> str:
        return self._server_hostname

    def getpeername(self) -> Any:
        return self._sock.getpeername()

    def getsockname(self) -> Any:
        return self._sock.getsockname()

    # --- makefile support for http.client compatibility ---

    def makefile(self, mode: str = "r", buffering: int = -1, **kwargs: Any) -> Any:
        """Create a file-like object for the socket.

        urllib3/http.client uses makefile("rb") to read HTTP responses.
        """
        if "b" in mode:
            raw = _SchannelSocketIO(self, mode)
            if buffering < 0:
                buffering = io.DEFAULT_BUFFER_SIZE
            if buffering == 0:
                return raw
            if "r" in mode:
                return io.BufferedReader(raw, buffering)
            return io.BufferedWriter(raw, buffering)
        # Text mode
        raw = _SchannelSocketIO(self, mode.replace("t", "") + "b")
        buf = io.BufferedReader(raw, io.DEFAULT_BUFFER_SIZE)
        encoding = kwargs.get("encoding", "utf-8")
        return io.TextIOWrapper(buf, encoding=encoding)

    # --- Internal helpers ---

    def _recv_raw(self, bufsize: int) -> bytes:
        """Receive raw (encrypted) bytes from the underlying socket."""
        try:
            return self._sock.recv(bufsize)
        except OSError:
            return b""

    def __enter__(self) -> SchannelSocket:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class _SchannelSocketIO(io.RawIOBase):
    """Raw I/O wrapper for SchannelSocket, implementing io.RawIOBase protocol."""

    def __init__(self, schannel_sock: SchannelSocket, mode: str) -> None:
        super().__init__()
        self._sock = schannel_sock
        self._mode = mode

    def readable(self) -> bool:
        return "r" in self._mode

    def writable(self) -> bool:
        return "w" in self._mode

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            # Read all available
            chunks = []
            while True:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        return self._sock.recv(size)

    def readinto(self, b: bytearray | memoryview) -> int:  # type: ignore[override]
        data = self._sock.recv(len(b))
        n = len(data)
        b[:n] = data
        return n

    def write(self, b: bytes) -> int:  # type: ignore[override]
        return self._sock.send(b)

    def seekable(self) -> bool:
        return False

    def fileno(self) -> int:
        return self._sock.fileno()
