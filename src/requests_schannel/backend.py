"""Abstract backend interface for SChannel operations and certificate store access."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from . import _constants as c


class TlsVersion(IntEnum):
    """TLS protocol versions supported by SChannel."""

    TLSv1_2 = c.SP_PROT_TLS1_2_CLIENT
    TLSv1_3 = c.SP_PROT_TLS1_3_CLIENT


@dataclass(frozen=True)
class CertInfo:
    """Metadata about a certificate in the Windows store."""

    thumbprint: str
    subject: str
    issuer: str
    friendly_name: str
    not_before: float  # timestamp
    not_after: float  # timestamp
    has_private_key: bool
    serial_number: str
    der_encoded: bytes


@dataclass(frozen=True)
class StreamSizes:
    """SChannel stream sizes returned by QueryContextAttributes(STREAM_SIZES)."""

    header: int
    trailer: int
    max_message: int
    buffers: int
    block_size: int


@dataclass(frozen=True)
class ConnectionInfo:
    """TLS connection information."""

    protocol_version: str
    cipher_algorithm: int
    cipher_strength: int
    hash_algorithm: int
    hash_strength: int
    exchange_algorithm: int
    exchange_strength: int


@dataclass
class CredentialConfig:
    """Configuration for acquiring SChannel credentials."""

    protocols: int = c.SP_PROT_TLS_CLIENT_DEFAULT
    cert_context: Any = None  # Platform-specific cert handle
    flags: int = c.SCH_CRED_AUTO_CRED_VALIDATION | c.SCH_CRED_REVOCATION_CHECK_CHAIN
    manual_validation: bool = False

    def __post_init__(self) -> None:
        if self.manual_validation:
            self.flags = (
                (self.flags & ~c.SCH_CRED_AUTO_CRED_VALIDATION)
                | c.SCH_CRED_MANUAL_CRED_VALIDATION
            )


@dataclass
class HandshakeResult:
    """Result of a single handshake step."""

    output_token: bytes
    complete: bool
    extra_data: bytes = b""


class CredentialHandle:
    """Opaque handle to SSPI credentials. Thread-safe — can be shared across connections."""

    __slots__ = ("_handle", "_backend_data")

    def __init__(self, handle: Any, backend_data: Any = None) -> None:
        self._handle = handle
        self._backend_data = backend_data

    @property
    def raw(self) -> Any:
        return self._handle

    @property
    def backend_data(self) -> Any:
        return self._backend_data


class SecurityContext:
    """Opaque handle to an SSPI security context. NOT thread-safe — one per connection."""

    __slots__ = ("_handle", "_backend_data", "_stream_sizes")

    def __init__(self, handle: Any = None, backend_data: Any = None) -> None:
        self._handle = handle
        self._backend_data = backend_data
        self._stream_sizes: StreamSizes | None = None

    @property
    def raw(self) -> Any:
        return self._handle

    @raw.setter
    def raw(self, value: Any) -> None:
        self._handle = value

    @property
    def backend_data(self) -> Any:
        return self._backend_data

    @backend_data.setter
    def backend_data(self, value: Any) -> None:
        self._backend_data = value

    @property
    def stream_sizes(self) -> StreamSizes | None:
        return self._stream_sizes

    @stream_sizes.setter
    def stream_sizes(self, value: StreamSizes) -> None:
        self._stream_sizes = value


class SchannelBackend(ABC):
    """Abstract interface for SChannel TLS operations.

    Backends implement this to provide TLS via either sspilib or raw ctypes.
    CredentialHandles are thread-safe and shareable; SecurityContexts are not.
    """

    @abstractmethod
    def acquire_credentials(self, config: CredentialConfig) -> CredentialHandle:
        """Acquire SChannel credentials, optionally with a client certificate.

        Returns a CredentialHandle that can be shared across threads/connections.
        """

    @abstractmethod
    def create_context(
        self,
        credential: CredentialHandle,
        target_name: str,
        flags: int = c.ISC_REQ_TLS_CLIENT,
        alpn_protocols: list[str] | None = None,
    ) -> SecurityContext:
        """Create a new security context for a single TLS connection.

        Returns a SecurityContext that is NOT thread-safe.
        """

    @abstractmethod
    def handshake_step(
        self, context: SecurityContext, in_token: bytes | None = None
    ) -> HandshakeResult:
        """Perform one step of the TLS handshake.

        Call repeatedly until HandshakeResult.complete is True.
        """

    @abstractmethod
    def encrypt(self, context: SecurityContext, plaintext: bytes) -> bytes:
        """Encrypt plaintext data for sending over the TLS connection."""

    @abstractmethod
    def decrypt(self, context: SecurityContext, ciphertext: bytes) -> tuple[bytes, bytes]:
        """Decrypt received TLS data.

        Returns (plaintext, extra_data). extra_data contains any bytes belonging
        to the next TLS record and must be prepended to the next recv buffer.
        """

    @abstractmethod
    def shutdown(self, context: SecurityContext) -> bytes:
        """Generate a TLS close_notify shutdown token.

        Returns the shutdown token bytes that should be sent to the peer.
        """

    @abstractmethod
    def get_peer_certificate(self, context: SecurityContext) -> bytes:
        """Get the peer's certificate in DER-encoded format."""

    @abstractmethod
    def get_connection_info(self, context: SecurityContext) -> ConnectionInfo:
        """Get TLS connection information (cipher, version, etc.)."""

    @abstractmethod
    def get_stream_sizes(self, context: SecurityContext) -> StreamSizes:
        """Get the TLS stream sizes (header, trailer, max message)."""

    @abstractmethod
    def get_negotiated_protocol(self, context: SecurityContext) -> str | None:
        """Get the ALPN-negotiated application protocol, or None."""

    @abstractmethod
    def free_credentials(self, credential: CredentialHandle) -> None:
        """Release SSPI credential handle resources."""

    @abstractmethod
    def free_context(self, context: SecurityContext) -> None:
        """Release SSPI security context resources."""


class CertStore(ABC):
    """Abstract interface for Windows Certificate Store operations."""

    @abstractmethod
    def open(self, store_name: str = "MY", machine: bool = False) -> Any:
        """Open a certificate store.

        Args:
            store_name: Store name (e.g. "MY", "Root", "CA").
            machine: If True, open LocalMachine store; otherwise CurrentUser.

        Returns an opaque store handle.
        """

    @abstractmethod
    def close(self, store_handle: Any) -> None:
        """Close a certificate store handle."""

    @abstractmethod
    def find_by_thumbprint(self, store_handle: Any, thumbprint: str) -> Any:
        """Find a certificate by SHA-1 thumbprint.

        Returns a platform-specific cert context, or raises CertificateNotFoundError.
        """

    @abstractmethod
    def find_by_subject(self, store_handle: Any, subject: str) -> Any:
        """Find a certificate by subject name substring.

        Returns the first matching cert context, or raises CertificateNotFoundError.
        """

    @abstractmethod
    def enumerate(self, store_handle: Any) -> list[CertInfo]:
        """Enumerate all certificates in the store."""

    @abstractmethod
    def get_cert_info(self, cert_context: Any) -> CertInfo:
        """Extract CertInfo metadata from a certificate context."""

    @abstractmethod
    def free_certificate(self, cert_context: Any) -> None:
        """Release a certificate context handle."""
