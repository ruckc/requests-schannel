"""SchannelContext — ssl.SSLContext-compatible duck type backed by Windows SChannel.

Thread-safe: holds one shared CredentialHandle, creates a new SecurityContext
per wrap_socket() call. Safe to share across a requests.Session connection pool.
"""

from __future__ import annotations

import socket
import ssl
from typing import Any

from ._constants import (
    ISC_REQ_TLS_CLIENT,
    ISC_REQ_TLS_CLIENT_MTLS,
    SCH_CRED_AUTO_CRED_VALIDATION,
    SCH_CRED_MANUAL_CRED_VALIDATION,
    SCH_CRED_REVOCATION_CHECK_CHAIN,
    SP_PROT_TLS1_2_CLIENT,
    SP_PROT_TLS1_3_CLIENT,
    SP_PROT_TLS_CLIENT_DEFAULT,
)
from ._errors import SchannelError
from .backend import (
    CredentialConfig,
    CredentialHandle,
    SchannelBackend,
    TlsVersion,
)
from .backends import get_backend, get_cert_store
from .socket import SchannelSocket


class SchannelContext:
    """ssl.SSLContext-compatible object backed by Windows SChannel.

    Configures TLS parameters and creates SchannelSocket instances via
    wrap_socket(). Thread-safe: the credential handle is acquired once and
    shared; each wrap_socket() creates a new per-connection security context.

    Usage::

        ctx = SchannelContext()
        ctx.client_cert_thumbprint = "AB12CD..."  # optional: mTLS
        ctx.set_alpn_protocols(["http/1.1"])

        # Use with urllib3/requests:
        sock = ctx.wrap_socket(raw_sock, server_hostname="example.com")
    """

    def __init__(
        self,
        backend: str | SchannelBackend | None = None,
    ) -> None:
        if isinstance(backend, SchannelBackend):
            self._backend = backend
        else:
            self._backend = get_backend(backend)

        # Configuration (set before first connection)
        self._client_cert_thumbprint: str | None = None
        self._client_cert_subject: str | None = None
        self._auto_select_client_cert: bool = False
        self._cert_store_name: str = "MY"
        self._cert_store_machine: bool = False
        self._alpn_protocols: list[str] | None = None
        self._protocols: int = SP_PROT_TLS_CLIENT_DEFAULT
        self._verify_mode: ssl.VerifyMode = ssl.CERT_REQUIRED
        self._check_hostname: bool = True
        self._hwnd: int | None = None

        # Credential handle (lazy-initialized, thread-safe once created)
        self._credential: CredentialHandle | None = None
        self._cert_context: Any = None

    # --- Certificate selection ---

    @property
    def client_cert_thumbprint(self) -> str | None:
        """SHA-1 thumbprint of the client certificate for mTLS."""
        return self._client_cert_thumbprint

    @client_cert_thumbprint.setter
    def client_cert_thumbprint(self, value: str | None) -> None:
        self._client_cert_thumbprint = value
        self._credential = None  # Force re-acquisition

    @property
    def client_cert_subject(self) -> str | None:
        """Subject name substring to find the client certificate."""
        return self._client_cert_subject

    @client_cert_subject.setter
    def client_cert_subject(self, value: str | None) -> None:
        self._client_cert_subject = value
        self._credential = None

    @property
    def auto_select_client_cert(self) -> bool:
        """If True, let Windows auto-select a client cert (may show dialog)."""
        return self._auto_select_client_cert

    @auto_select_client_cert.setter
    def auto_select_client_cert(self, value: bool) -> None:
        self._auto_select_client_cert = value
        self._credential = None

    @property
    def cert_store_name(self) -> str:
        """Windows certificate store name (default 'MY')."""
        return self._cert_store_name

    @cert_store_name.setter
    def cert_store_name(self, value: str) -> None:
        self._cert_store_name = value
        self._credential = None

    @property
    def hwnd(self) -> int | None:
        """Optional parent window handle (HWND) for Windows Security dialogs.

        When set, Windows certificate-selection and smartcard PIN prompts will
        use this window as their parent so that they appear on top of the
        application window rather than behind it.  Pass the integer value of an
        HWND (e.g. ``int(win32gui.GetForegroundWindow())``).
        """
        return self._hwnd

    @hwnd.setter
    def hwnd(self, value: int | None) -> None:
        self._hwnd = value
        self._credential = None

    # --- TLS configuration ---

    @property
    def minimum_version(self) -> TlsVersion:
        """Minimum TLS version. Only TLS 1.2+ supported."""
        if self._protocols & SP_PROT_TLS1_2_CLIENT:
            return TlsVersion.TLSv1_2
        return TlsVersion.TLSv1_3

    @minimum_version.setter
    def minimum_version(self, value: TlsVersion) -> None:
        if value == TlsVersion.TLSv1_2:
            self._protocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT
        elif value == TlsVersion.TLSv1_3:
            self._protocols = SP_PROT_TLS1_3_CLIENT
        self._credential = None

    @property
    def maximum_version(self) -> TlsVersion:
        """Maximum TLS version."""
        if self._protocols & SP_PROT_TLS1_3_CLIENT:
            return TlsVersion.TLSv1_3
        return TlsVersion.TLSv1_2

    @maximum_version.setter
    def maximum_version(self, value: TlsVersion) -> None:
        if value == TlsVersion.TLSv1_2:
            self._protocols = SP_PROT_TLS1_2_CLIENT
        elif value == TlsVersion.TLSv1_3:
            self._protocols |= SP_PROT_TLS1_3_CLIENT
        self._credential = None

    @property
    def verify_mode(self) -> ssl.VerifyMode:
        return self._verify_mode

    @verify_mode.setter
    def verify_mode(self, value: ssl.VerifyMode) -> None:
        self._verify_mode = value
        self._credential = None

    @property
    def check_hostname(self) -> bool:
        return self._check_hostname

    @check_hostname.setter
    def check_hostname(self, value: bool) -> None:
        self._check_hostname = value

    def set_alpn_protocols(self, protocols: list[str]) -> None:
        """Set ALPN protocol list (e.g. ["h2", "http/1.1"])."""
        self._alpn_protocols = list(protocols)

    # --- ssl.SSLContext compatibility stubs ---

    def load_cert_chain(
        self, certfile: str | None = None, keyfile: str | None = None, password: str | None = None
    ) -> None:
        """No-op: certificates come from the Windows certificate store.

        Use client_cert_thumbprint or client_cert_subject instead.
        """

    def load_verify_locations(
        self,
        cafile: str | None = None,
        capath: str | None = None,
        cadata: bytes | None = None,
    ) -> None:
        """No-op: server verification uses the Windows trust store."""

    def load_default_certs(self, purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH) -> None:
        """No-op: Windows trust store is always used."""

    def set_ciphers(self, ciphers: str) -> None:
        """No-op: SChannel manages cipher suite selection.

        Windows policy controls which cipher suites are available.
        """

    def set_default_verify_paths(self) -> None:
        """No-op: Windows trust store is used by default."""

    # --- Core: socket wrapping ---

    def wrap_socket(
        self,
        sock: socket.socket,
        server_side: bool = False,
        do_handshake_on_connect: bool = True,
        suppress_ragged_eofs: bool = True,
        server_hostname: str | None = None,
        session: Any = None,
    ) -> SchannelSocket:
        """Wrap a socket with SChannel TLS, performing the handshake.

        This is the primary interface used by urllib3/requests.
        """
        if server_side:
            raise SchannelError("Server-side TLS is not supported (client-only library)")

        if server_hostname is None:
            raise SchannelError("server_hostname is required for TLS")

        credential = self._get_or_create_credential()

        # Determine ISC_REQ flags
        has_client_cert = (
            self._client_cert_thumbprint is not None
            or self._client_cert_subject is not None
            or self._auto_select_client_cert
        )
        flags = ISC_REQ_TLS_CLIENT_MTLS if has_client_cert else ISC_REQ_TLS_CLIENT

        # If manual validation is enabled, add the flag
        if self._verify_mode == ssl.CERT_NONE:
            from ._constants import ISC_REQ_MANUAL_CRED_VALIDATION

            flags |= ISC_REQ_MANUAL_CRED_VALIDATION

        schannel_sock = SchannelSocket(
            sock=sock,
            backend=self._backend,
            credential=credential,
            server_hostname=server_hostname,
            flags=flags,
            alpn_protocols=self._alpn_protocols,
        )

        if do_handshake_on_connect:
            schannel_sock.do_handshake()

        return schannel_sock

    # --- Internal ---

    def _get_or_create_credential(self) -> CredentialHandle:
        """Lazily acquire SSPI credential handle. Thread-safe after creation."""
        if self._credential is not None:
            return self._credential

        cert_context = self._resolve_client_cert()

        # Build credential flags
        flags = SCH_CRED_REVOCATION_CHECK_CHAIN
        if self._verify_mode == ssl.CERT_NONE:
            flags = SCH_CRED_MANUAL_CRED_VALIDATION
        else:
            flags |= SCH_CRED_AUTO_CRED_VALIDATION

        config = CredentialConfig(
            protocols=self._protocols,
            cert_context=cert_context,
            flags=flags,
            manual_validation=(self._verify_mode == ssl.CERT_NONE),
            hwnd=self._hwnd,
        )

        self._credential = self._backend.acquire_credentials(config)
        return self._credential

    def _resolve_client_cert(self) -> Any:
        """Find client certificate in Windows store if configured."""
        if not (
            self._client_cert_thumbprint
            or self._client_cert_subject
            or self._auto_select_client_cert
        ):
            return None

        cert_store = get_cert_store()
        store = cert_store.open(self._cert_store_name, self._cert_store_machine)
        try:
            if self._client_cert_thumbprint:
                cert = cert_store.find_by_thumbprint(store, self._client_cert_thumbprint)
            elif self._client_cert_subject:
                cert = cert_store.find_by_subject(store, self._client_cert_subject)
            else:
                # Auto-select: return None and let SChannel/Windows choose
                return None
            self._cert_context = cert
            return cert
        finally:
            # Don't close store — cert context references it
            pass

    @property
    def backend(self) -> SchannelBackend:
        """The underlying SChannel backend instance."""
        return self._backend

    def __del__(self) -> None:
        if self._credential is not None:
            try:
                self._backend.free_credentials(self._credential)
            except Exception:
                pass
