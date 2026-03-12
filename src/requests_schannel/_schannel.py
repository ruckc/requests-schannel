"""
SChannel socket wrapper.

Wraps a raw :class:`socket.socket` with TLS using the Windows SChannel API
via ctypes.  Private-key operations are delegated to the Windows CSP / KSP
associated with the certificate, so smart-card certificates work
transparently without exporting any key material.

Handshake flow (SSPI / SChannel client side)
--------------------------------------------
1. ``AcquireCredentialsHandle`` – obtain a credentials handle that
   references the client certificate (if any) held in the Windows store.
2. ``InitializeSecurityContext`` loop – exchange TLS handshake tokens with
   the server.  The first call passes ``NULL`` as the input buffer; each
   subsequent call feeds the server's response tokens back in until
   ``SEC_E_OK`` is returned.
3. ``QueryContextAttributes(SECPKG_ATTR_STREAM_SIZES)`` – learn the
   per-record header/trailer sizes required for ``EncryptMessage``.
4. ``EncryptMessage`` / ``DecryptMessage`` – protect / unprotect
   application-layer data.
5. ``DeleteSecurityContext`` / ``FreeCredentialsHandle`` – tear down.
"""
from __future__ import annotations

import ctypes
import socket
import sys
from typing import Optional

from .exceptions import SchannelCertValidationError, SchannelError, SchannelHandshakeError

if sys.platform == "win32":  # pragma: no cover
    import ctypes.wintypes as wintypes

    from ._windows_types import (
        SCH_CREDENTIALS,
        SCH_CREDENTIALS_VERSION,
        SEC_E_INCOMPLETE_MESSAGE,
        SEC_E_OK,
        SEC_I_CONTINUE_NEEDED,
        SEC_I_INCOMPLETE_CREDENTIALS,
        SECBUFFER_ALERT,
        SECBUFFER_DATA,
        SECBUFFER_EMPTY,
        SECBUFFER_EXTRA,
        SECBUFFER_STREAM_HEADER,
        SECBUFFER_STREAM_TRAILER,
        SECBUFFER_TOKEN,
        SECBUFFER_VERSION,
        SECPKG_ATTR_STREAM_SIZES,
        SECPKG_ATTR_REMOTE_CERT_CONTEXT,
        SECPKG_CRED_OUTBOUND,
        ISC_REQ_CONFIDENTIALITY,
        ISC_REQ_EXTENDED_ERROR,
        ISC_REQ_MANUAL_CRED_VALIDATION,
        ISC_REQ_REPLAY_DETECT,
        ISC_REQ_SEQUENCE_DETECT,
        ISC_REQ_STREAM,
        SCH_CRED_MANUAL_CRED_VALIDATION,
        SCH_CRED_NO_DEFAULT_CREDS,
        SECURITY_NATIVE_DREP,
        UNISP_NAME,
        AUTHTYPE_SERVER,
        CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL,
        CERT_CHAIN_ENGINE_CONFIG,
        CERT_CHAIN_PARA,
        CERT_CHAIN_POLICY_SSL,
        CERT_CHAIN_POLICY_PARA,
        CERT_CHAIN_POLICY_STATUS,
        SSL_EXTRA_CERT_CHAIN_POLICY_PARA,
        CredHandle,
        CtxtHandle,
        SecBuffer,
        SecBufferDesc,
        SecPkgContext_StreamSizes,
        TimeStamp,
        _load_secur32,
        _load_crypt32,
    )

    _secur32 = _load_secur32()
    _crypt32 = _load_crypt32()

# Maximum TLS record size (RFC 5246 §6.2.1)
_TLS_MAX_RECORD = 16384
# Read chunk size when accumulating handshake data
_RECV_CHUNK = 16384


def _make_sec_buffer_array(count: int) -> "ctypes.Array[SecBuffer]":
    """Return a zero-initialised array of *count* SecBuffer structures."""
    arr_type = SecBuffer * count
    return arr_type()


def _make_sec_buffer_desc(buffers: "ctypes.Array") -> SecBufferDesc:
    """Wrap a SecBuffer array in a SecBufferDesc."""
    desc = SecBufferDesc()
    desc.ulVersion = SECBUFFER_VERSION
    desc.cBuffers = len(buffers)
    desc.pBuffers = buffers
    return desc


class SchannelSocket:
    """
    A TLS socket that uses Windows SChannel for all cryptographic operations.

    Parameters
    ----------
    raw_sock:
        An already-connected plain TCP :class:`socket.socket`.
    server_name:
        The target hostname used for SNI and (optionally) server certificate
        name validation.
    cert_context_handle:
        Optional ``PCCERT_CONTEXT`` value (as a Python ``int``) for client
        certificate authentication.  The private key is **never exported**;
        SChannel calls the associated CSP / KSP directly.
    verify:
        Whether to validate the server certificate.
    ca_store_handle:
        Optional ``HCERTSTORE`` that supplements the default root-CA store
        used by SChannel for server certificate validation.
    timeout:
        Socket timeout in seconds.
    """

    def __init__(
        self,
        raw_sock: socket.socket,
        *,
        server_name: str,
        cert_context_handle: Optional[int] = None,
        verify: bool = True,
        ca_store_handle: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> None:
        if sys.platform != "win32":  # pragma: no cover
            raise NotImplementedError("SchannelSocket is only available on Windows")

        self._sock = raw_sock
        self._server_name = server_name
        self._cert_context_handle = cert_context_handle
        self._verify = verify
        self._ca_store_handle = ca_store_handle

        if timeout is not None:
            self._sock.settimeout(timeout)

        self._cred = CredHandle()
        self._ctx = CtxtHandle()
        self._stream_sizes: Optional[SecPkgContext_StreamSizes] = None
        self._recv_buf: bytes = b""
        self._plaintext_buf: bytes = b""
        self._handshake_done: bool = False

        self._acquire_credentials()
        self._do_handshake()
        if self._verify:
            self._verify_server_cert()

    # ------------------------------------------------------------------
    # Credentials acquisition
    # ------------------------------------------------------------------

    def _acquire_credentials(self) -> None:  # pragma: no cover
        """Call ``AcquireCredentialsHandle`` to initialise the credential.

        Uses the ``SCH_CREDENTIALS`` structure (version 5) which supports
        TLS 1.3.  The older ``SCHANNEL_CRED`` (version 4) returns
        ``SEC_E_UNKNOWN_CREDENTIALS`` when TLS 1.3 is requested.
        """
        scred = SCH_CREDENTIALS()
        scred.dwVersion = SCH_CREDENTIALS_VERSION
        scred.dwSessionLifespan = 0

        if self._cert_context_handle:
            # Pass the certificate context without copying key material
            pa_cred = (ctypes.c_void_p * 1)(self._cert_context_handle)
            scred.cCreds = 1
            scred.paCred = pa_cred
        else:
            scred.cCreds = 0

        # Always use manual credential validation.  SCH_CRED_AUTO_CRED_VALIDATION
        # causes Windows to make blocking network calls (CTL auto-update,
        # OCSP/CRL retrieval) inside InitializeSecurityContext, which cannot
        # be bounded by our socket timeout and hangs indefinitely in CI
        # environments without unrestricted internet access.  When verify=True,
        # we perform equivalent chain validation ourselves in _verify_server_cert()
        # using offline-only CertGetCertificateChain flags.
        scred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS

        # Leave cTlsParameters=0 / pTlsParameters=NULL to let SChannel
        # negotiate the best available protocol (TLS 1.2 or 1.3).

        ts = TimeStamp()
        status = int(_secur32.AcquireCredentialsHandleW(
            None,
            UNISP_NAME,
            SECPKG_CRED_OUTBOUND,
            None,
            ctypes.byref(scred),
            None,
            None,
            ctypes.byref(self._cred),
            ctypes.byref(ts),
        ))
        if status != SEC_E_OK:
            raise SchannelError("AcquireCredentialsHandle failed", status)

    # ------------------------------------------------------------------
    # TLS handshake
    # ------------------------------------------------------------------

    def _do_handshake(self) -> None:  # pragma: no cover
        """
        Perform the full TLS handshake via ``InitializeSecurityContext``.

        The loop follows the pattern documented in MSDN
        "Creating a Secure Connection Using Schannel":
        https://docs.microsoft.com/en-us/windows/win32/secauthn/creating-a-secure-connection-using-schannel
        """
        first_call = True
        in_data: bytes = b""

        isc_flags = (
            ISC_REQ_SEQUENCE_DETECT
            | ISC_REQ_REPLAY_DETECT
            | ISC_REQ_CONFIDENTIALITY
            | ISC_REQ_EXTENDED_ERROR
            | ISC_REQ_STREAM
            # Required to activate SCH_CRED_MANUAL_CRED_VALIDATION set in the
            # credential (see _acquire_credentials).  Without this flag SChannel
            # ignores the manual-validation credential flag and performs its own
            # automatic validation, which may block on network calls.
            | ISC_REQ_MANUAL_CRED_VALIDATION
        )

        while True:
            # --- Output buffers -----------------------------------------
            out_bufs = _make_sec_buffer_array(2)
            out_bufs[0].cbBuffer = 0
            out_bufs[0].BufferType = SECBUFFER_TOKEN
            out_bufs[0].pvBuffer = None
            out_bufs[1].cbBuffer = 0
            out_bufs[1].BufferType = SECBUFFER_ALERT
            out_bufs[1].pvBuffer = None
            out_desc = _make_sec_buffer_desc(out_bufs)

            # --- Input buffers ------------------------------------------
            if not first_call and in_data:
                in_raw = ctypes.create_string_buffer(in_data)
                in_bufs = _make_sec_buffer_array(2)
                in_bufs[0].cbBuffer = len(in_data)
                in_bufs[0].BufferType = SECBUFFER_TOKEN
                in_bufs[0].pvBuffer = ctypes.cast(in_raw, ctypes.c_void_p)
                in_bufs[1].cbBuffer = 0
                in_bufs[1].BufferType = SECBUFFER_EMPTY
                in_bufs[1].pvBuffer = None
                in_desc = _make_sec_buffer_desc(in_bufs)
                p_in_desc = ctypes.byref(in_desc)
            else:
                in_bufs = None
                p_in_desc = None

            ctx_attrs = wintypes.ULONG(0)
            ts = TimeStamp()

            status = int(_secur32.InitializeSecurityContextW(
                ctypes.byref(self._cred),
                None if first_call else ctypes.byref(self._ctx),
                self._server_name,
                isc_flags,
                0,
                SECURITY_NATIVE_DREP,
                p_in_desc,
                0,
                ctypes.byref(self._ctx),
                ctypes.byref(out_desc),
                ctypes.byref(ctx_attrs),
                ctypes.byref(ts),
            ))
            first_call = False

            # Send any output tokens produced by SChannel
            if out_bufs[0].cbBuffer > 0 and out_bufs[0].pvBuffer:
                token = ctypes.string_at(out_bufs[0].pvBuffer, out_bufs[0].cbBuffer)
                _secur32.FreeContextBuffer(out_bufs[0].pvBuffer)
                out_bufs[0].pvBuffer = None
                self._sock.sendall(token)

            # Handle extra data carried along with the last handshake message
            if in_bufs is not None and in_bufs[1].BufferType == SECBUFFER_EXTRA and in_bufs[1].cbBuffer > 0:
                extra = in_data[len(in_data) - in_bufs[1].cbBuffer:]
            else:
                extra = b""

            if status == SEC_E_OK:
                # Handshake complete; stash any application data that arrived
                # in the EXTRA buffer
                self._recv_buf = extra
                break
            elif status == SEC_I_CONTINUE_NEEDED:
                # Need server tokens; read from the socket
                chunk = self._sock.recv(_RECV_CHUNK)
                if not chunk:
                    raise SchannelHandshakeError(
                        "Server closed connection during TLS handshake"
                    )
                in_data = extra + chunk
            elif status == SEC_E_INCOMPLETE_MESSAGE:
                # Need more data to complete the current handshake record
                chunk = self._sock.recv(_RECV_CHUNK)
                if not chunk:
                    raise SchannelHandshakeError(
                        "Server closed connection during TLS handshake (incomplete message)"
                    )
                in_data = in_data + chunk
            elif status == SEC_I_INCOMPLETE_CREDENTIALS:
                # Server requested a client certificate but we have none
                raise SchannelHandshakeError(
                    "Server requires client certificate but none was provided",
                    status,
                )
            else:
                _validate_handshake_status(status)

        self._query_stream_sizes()
        self._handshake_done = True

    def _query_stream_sizes(self) -> None:  # pragma: no cover
        sizes = SecPkgContext_StreamSizes()
        status = int(_secur32.QueryContextAttributesW(
            ctypes.byref(self._ctx),
            SECPKG_ATTR_STREAM_SIZES,
            ctypes.byref(sizes),
        ))
        if status != SEC_E_OK:
            raise SchannelError("QueryContextAttributes(STREAM_SIZES) failed", status)
        self._stream_sizes = sizes

    def _verify_server_cert(self) -> None:  # pragma: no cover
        """
        Manually validate the server certificate chain against the Windows
        certificate store.

        Called after a successful handshake when ``verify=True``.  By doing
        this ourselves (rather than relying on ``SCH_CRED_AUTO_CRED_VALIDATION``)
        we avoid the Windows CTL auto-update mechanism, which makes blocking
        network requests to ``ctldl.windowsupdate.com`` and cannot be bounded
        by our socket timeout, causing indefinite hangs in CI environments.

        The chain is built with ``CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL`` so that
        no network I/O is performed; chain building succeeds entirely from the
        local certificate stores (ROOT, CA, etc.).

        When ``ca_store_handle`` is set a custom chain engine is created with
        ``hExclusiveRoot`` pointing at that store.  This makes the engine treat
        the certificates in that store as the *only* trusted roots, allowing
        tests (and callers) to supply a custom CA cert via an in-memory
        ``HCERTSTORE`` without modifying any system store (which would trigger
        Windows's CTL auto-update and hang in restricted network environments).
        """
        # Step 1 – Retrieve the server's PCCERT_CONTEXT from the SChannel context.
        remote_cert = ctypes.c_void_p(0)
        status = int(_secur32.QueryContextAttributesW(
            ctypes.byref(self._ctx),
            SECPKG_ATTR_REMOTE_CERT_CONTEXT,
            ctypes.byref(remote_cert),
        ))
        if status != SEC_E_OK or not remote_cert.value:
            raise SchannelCertValidationError(
                "QueryContextAttributes(REMOTE_CERT_CONTEXT) failed", status
            )

        try:
            # Step 2 – Build the certificate chain using only local/cached data.
            #
            # When the caller provided a custom CA store (ca_store_handle), we
            # create a chain engine whose hExclusiveRoot is that store.  This
            # makes CertGetCertificateChain trust only the certificates in that
            # store as roots, without touching the system ROOT store (and
            # therefore without triggering any CTL auto-update network calls).
            #
            # For normal production use (ca_store_handle=None) we pass NULL as
            # the engine to use the default system chain engine.
            chain_engine = ctypes.c_void_p(0)
            if self._ca_store_handle:
                engine_config = CERT_CHAIN_ENGINE_CONFIG()
                engine_config.cbSize = ctypes.sizeof(CERT_CHAIN_ENGINE_CONFIG)
                engine_config.hExclusiveRoot = ctypes.c_void_p(self._ca_store_handle)
                ok = _crypt32.CertCreateCertificateChainEngine(
                    ctypes.byref(engine_config),
                    ctypes.byref(chain_engine),
                )
                if not ok or not chain_engine.value:
                    raise SchannelCertValidationError(
                        "CertCreateCertificateChainEngine failed",
                        ctypes.GetLastError(),
                    )

            try:
                chain_para = CERT_CHAIN_PARA()
                chain_para.cbSize = ctypes.sizeof(CERT_CHAIN_PARA)

                chain_ctx = ctypes.c_void_p(0)
                ok = _crypt32.CertGetCertificateChain(
                    chain_engine,                        # custom engine or NULL (default)
                    remote_cert,                         # pCertContext
                    None,                                # pTime: NULL = current time
                    ctypes.c_void_p(0),                  # hAdditionalStore: NULL
                    ctypes.byref(chain_para),            # pChainPara (required)
                    CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, # no network I/O
                    None,                                # pvReserved: NULL
                    ctypes.byref(chain_ctx),
                )
                if not ok or not chain_ctx.value:
                    raise SchannelCertValidationError(
                        "CertGetCertificateChain failed",
                        ctypes.GetLastError(),
                    )

                try:
                    # Step 3 – Validate the chain using the SSL chain policy, which
                    # checks both the trust chain and the server hostname (SAN/CN).
                    ssl_para = SSL_EXTRA_CERT_CHAIN_POLICY_PARA()
                    ssl_para.cbSize = ctypes.sizeof(ssl_para)
                    ssl_para.dwAuthType = AUTHTYPE_SERVER
                    ssl_para.fdwChecks = 0
                    ssl_para.pwszServerName = self._server_name

                    policy_para = CERT_CHAIN_POLICY_PARA()
                    policy_para.cbSize = ctypes.sizeof(policy_para)
                    policy_para.dwFlags = 0
                    policy_para.pvExtraPolicyPara = ctypes.cast(
                        ctypes.byref(ssl_para), ctypes.c_void_p
                    )

                    policy_status = CERT_CHAIN_POLICY_STATUS()
                    policy_status.cbSize = ctypes.sizeof(policy_status)

                    ok = _crypt32.CertVerifyCertificateChainPolicy(
                        ctypes.c_void_p(CERT_CHAIN_POLICY_SSL),
                        chain_ctx,
                        ctypes.byref(policy_para),
                        ctypes.byref(policy_status),
                    )
                    if not ok:
                        raise SchannelCertValidationError(
                            "CertVerifyCertificateChainPolicy call failed",
                            ctypes.GetLastError(),
                        )
                    if policy_status.dwError:
                        raise SchannelCertValidationError(
                            f"Server certificate validation failed for {self._server_name!r}",
                            policy_status.dwError,
                        )
                finally:
                    _crypt32.CertFreeCertificateChain(chain_ctx)
            finally:
                if chain_engine.value:
                    _crypt32.CertFreeCertificateChainEngine(chain_engine)
        finally:
            _crypt32.CertFreeCertificateContext(remote_cert)

    # ------------------------------------------------------------------
    # send / recv
    # ------------------------------------------------------------------

    def send(self, data: bytes) -> int:  # pragma: no cover
        """Encrypt *data* with SChannel and send it over the socket."""
        if not self._handshake_done or self._stream_sizes is None:
            raise SchannelError("TLS handshake not completed")

        sizes = self._stream_sizes
        # We may need to split data into chunks of at most cbMaximumMessage bytes
        total_sent = 0
        while total_sent < len(data):
            chunk = data[total_sent : total_sent + sizes.cbMaximumMessage]
            total_sent += self._send_chunk(chunk)
        return total_sent

    def sendall(self, data: bytes) -> None:  # pragma: no cover
        """Send all *data*, encrypting with SChannel.  Mirrors socket.sendall()."""
        sent = 0
        while sent < len(data):
            sent += self.send(data[sent:])

    def _send_chunk(self, chunk: bytes) -> int:  # pragma: no cover
        sizes = self._stream_sizes
        header_buf = ctypes.create_string_buffer(sizes.cbHeader)
        data_buf = ctypes.create_string_buffer(chunk)
        trailer_buf = ctypes.create_string_buffer(sizes.cbTrailer)

        enc_bufs = _make_sec_buffer_array(4)
        enc_bufs[0].cbBuffer = sizes.cbHeader
        enc_bufs[0].BufferType = SECBUFFER_STREAM_HEADER
        enc_bufs[0].pvBuffer = ctypes.cast(header_buf, ctypes.c_void_p)

        enc_bufs[1].cbBuffer = len(chunk)
        enc_bufs[1].BufferType = SECBUFFER_DATA
        enc_bufs[1].pvBuffer = ctypes.cast(data_buf, ctypes.c_void_p)

        enc_bufs[2].cbBuffer = sizes.cbTrailer
        enc_bufs[2].BufferType = SECBUFFER_STREAM_TRAILER
        enc_bufs[2].pvBuffer = ctypes.cast(trailer_buf, ctypes.c_void_p)

        enc_bufs[3].cbBuffer = 0
        enc_bufs[3].BufferType = SECBUFFER_EMPTY
        enc_bufs[3].pvBuffer = None

        enc_desc = _make_sec_buffer_desc(enc_bufs)
        status = int(_secur32.EncryptMessage(
            ctypes.byref(self._ctx), 0, ctypes.byref(enc_desc), 0
        ))
        if status != SEC_E_OK:
            raise SchannelError("EncryptMessage failed", status)

        # The three buffers are now contiguous encrypted data; send them
        wire = (
            ctypes.string_at(enc_bufs[0].pvBuffer, enc_bufs[0].cbBuffer)
            + ctypes.string_at(enc_bufs[1].pvBuffer, enc_bufs[1].cbBuffer)
            + ctypes.string_at(enc_bufs[2].pvBuffer, enc_bufs[2].cbBuffer)
        )
        self._sock.sendall(wire)
        return len(chunk)

    def recv(self, size: int) -> bytes:  # pragma: no cover
        """Return up to *size* bytes of decrypted application data."""
        while not self._plaintext_buf:
            prev_len = len(self._recv_buf) + len(self._plaintext_buf)
            self._decrypt_one_record()
            # If we made no progress (EOF on underlying socket), stop.
            if not self._plaintext_buf and len(self._recv_buf) == prev_len:
                return b""
        result = self._plaintext_buf[:size]
        self._plaintext_buf = self._plaintext_buf[size:]
        return result

    def _decrypt_one_record(self) -> None:  # pragma: no cover
        """Read raw bytes from the socket until one TLS record is decrypted."""
        while True:
            if self._recv_buf:
                raw = ctypes.create_string_buffer(self._recv_buf)
                dec_bufs = _make_sec_buffer_array(4)
                dec_bufs[0].cbBuffer = len(self._recv_buf)
                dec_bufs[0].BufferType = SECBUFFER_DATA
                dec_bufs[0].pvBuffer = ctypes.cast(raw, ctypes.c_void_p)
                for i in range(1, 4):
                    dec_bufs[i].cbBuffer = 0
                    dec_bufs[i].BufferType = SECBUFFER_EMPTY
                    dec_bufs[i].pvBuffer = None
                dec_desc = _make_sec_buffer_desc(dec_bufs)
                qop = wintypes.ULONG(0)
                status = int(_secur32.DecryptMessage(
                    ctypes.byref(self._ctx), ctypes.byref(dec_desc), 0, ctypes.byref(qop)
                ))
                if status == SEC_E_OK:
                    # Collect plaintext from DATA buffer(s)
                    for i in range(4):
                        if dec_bufs[i].BufferType == SECBUFFER_DATA and dec_bufs[i].cbBuffer:
                            self._plaintext_buf += ctypes.string_at(
                                dec_bufs[i].pvBuffer, dec_bufs[i].cbBuffer
                            )
                        elif dec_bufs[i].BufferType == SECBUFFER_EXTRA and dec_bufs[i].cbBuffer:
                            # Leftover data for next record
                            self._recv_buf = ctypes.string_at(
                                dec_bufs[i].pvBuffer, dec_bufs[i].cbBuffer
                            )
                            return
                    self._recv_buf = b""
                    return
                elif status == SEC_E_INCOMPLETE_MESSAGE:
                    pass  # fall through to read more data
                else:
                    raise SchannelError("DecryptMessage failed", status)

            chunk = self._sock.recv(_RECV_CHUNK)
            if not chunk:
                return  # EOF
            self._recv_buf += chunk

    # ------------------------------------------------------------------
    # makefile / fileno helpers required by http.client
    # ------------------------------------------------------------------

    def makefile(self, mode: str = "rb", bufsize: int = -1) -> "_SchannelFile":  # pragma: no cover
        return _SchannelFile(self, mode)

    def fileno(self) -> int:  # pragma: no cover
        return self._sock.fileno()

    def settimeout(self, timeout: Optional[float]) -> None:  # pragma: no cover
        self._sock.settimeout(timeout)

    def getpeername(self):  # pragma: no cover
        return self._sock.getpeername()

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:  # pragma: no cover
        if self._handshake_done:
            try:
                _secur32.DeleteSecurityContext(ctypes.byref(self._ctx))
            except Exception:
                pass
        try:
            _secur32.FreeCredentialsHandle(ctypes.byref(self._cred))
        except Exception:
            pass
        self._sock.close()
        self._handshake_done = False

    def __enter__(self) -> "SchannelSocket":  # pragma: no cover
        return self

    def __exit__(self, *_: object) -> None:  # pragma: no cover
        self.close()


# ---------------------------------------------------------------------------
# File-like wrapper for http.client compatibility
# ---------------------------------------------------------------------------


class _SchannelFile:  # pragma: no cover
    """
    File-like object backed by a :class:`SchannelSocket`.

    ``http.client.HTTPResponse`` expects a ``BufferedIOBase``-like interface
    when reading responses: ``read``, ``readline``, ``readinto``, ``read1``,
    ``peek``, ``fileno``, and ``flush`` are all called in various code paths.
    """

    def __init__(self, sock: SchannelSocket, mode: str) -> None:
        self._sock = sock
        self._mode = mode
        self._closed = False
        self._peek_buf: bytes = b""

    def read(self, size: int = -1) -> bytes:
        if size < 0 or size is None:
            chunks = []
            if self._peek_buf:
                chunks.append(self._peek_buf)
                self._peek_buf = b""
            while True:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        if self._peek_buf:
            if len(self._peek_buf) >= size:
                result = self._peek_buf[:size]
                self._peek_buf = self._peek_buf[size:]
                return result
            result = self._peek_buf
            self._peek_buf = b""
            remaining = size - len(result)
            data = self._sock.recv(remaining)
            return result + data
        return self._sock.recv(size)

    def read1(self, size: int = -1) -> bytes:
        """Read up to *size* bytes with at most one call to the underlying socket."""
        return self.read(size)

    def readinto(self, b: bytearray) -> int:
        """Read up to len(b) bytes into *b* and return number of bytes read."""
        data = self.read(len(b))
        n = len(data)
        b[:n] = data
        return n

    def readline(self, limit: int = -1) -> bytes:
        line = b""
        # Drain peek buffer first
        if self._peek_buf:
            idx = self._peek_buf.find(b"\n")
            if idx >= 0:
                idx += 1  # include the newline
                if limit < 0 or idx <= limit:
                    line = self._peek_buf[:idx]
                    self._peek_buf = self._peek_buf[idx:]
                    return line
            # No newline in peek buffer; use it all
            line = self._peek_buf
            self._peek_buf = b""
        while limit < 0 or len(line) < limit:
            c = self._sock.recv(1)
            if not c:
                break
            line += c
            if c == b"\n":
                break
        return line

    def peek(self, size: int = -1) -> bytes:
        """Return buffered data without advancing the read position."""
        if not self._peek_buf:
            self._peek_buf = self._sock.recv(size if size > 0 else 4096)
        return self._peek_buf

    def write(self, data: bytes) -> int:
        return self._sock.send(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed

    def fileno(self) -> int:
        return self._sock.fileno()

    def readable(self) -> bool:
        return "r" in self._mode

    def writable(self) -> bool:
        return "w" in self._mode


# ---------------------------------------------------------------------------
# Status validation helpers
# ---------------------------------------------------------------------------


def _validate_handshake_status(status: int) -> None:  # pragma: no cover
    """Raise an appropriate exception for a failed ISC status code."""
    from ._windows_types import (
        SEC_E_CERT_EXPIRED,
        SEC_E_UNTRUSTED_ROOT,
        SEC_E_WRONG_PRINCIPAL,
    )

    if status in (SEC_E_UNTRUSTED_ROOT,):
        raise SchannelCertValidationError(
            "Server certificate is not trusted (untrusted root)", status
        )
    if status == SEC_E_CERT_EXPIRED:
        raise SchannelCertValidationError(
            "Server certificate has expired", status
        )
    if status == SEC_E_WRONG_PRINCIPAL:
        raise SchannelCertValidationError(
            "Server certificate does not match the target hostname", status
        )
    raise SchannelHandshakeError(
        "TLS handshake failed", status
    )
