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
        SCHANNEL_CRED,
        SCHANNEL_CRED_VERSION,
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
        SECPKG_CRED_OUTBOUND,
        SP_PROT_TLS1_2_CLIENT,
        SP_PROT_TLS1_3_CLIENT,
        ISC_REQ_CONFIDENTIALITY,
        ISC_REQ_EXTENDED_ERROR,
        ISC_REQ_MANUAL_CRED_VALIDATION,
        ISC_REQ_REPLAY_DETECT,
        ISC_REQ_SEQUENCE_DETECT,
        ISC_REQ_STREAM,
        SCH_CRED_AUTO_CRED_VALIDATION,
        SCH_CRED_MANUAL_CRED_VALIDATION,
        SCH_CRED_NO_DEFAULT_CREDS,
        SECURITY_NATIVE_DREP,
        UNISP_NAME,
        CredHandle,
        CtxtHandle,
        SecBuffer,
        SecBufferDesc,
        SecPkgContext_StreamSizes,
        TimeStamp,
        _load_secur32,
    )

    _secur32 = _load_secur32()

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

    # ------------------------------------------------------------------
    # Credentials acquisition
    # ------------------------------------------------------------------

    def _acquire_credentials(self) -> None:  # pragma: no cover
        """Call ``AcquireCredentialsHandle`` to initialise the credential."""
        scred = SCHANNEL_CRED()
        scred.dwVersion = SCHANNEL_CRED_VERSION
        scred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT
        scred.dwMinimumCipherStrength = 0
        scred.dwMaximumCipherStrength = 0
        scred.dwSessionLifespan = 0

        if self._cert_context_handle:
            # Pass the certificate context without copying key material
            pa_cred = (ctypes.c_void_p * 1)(self._cert_context_handle)
            scred.cCreds = 1
            scred.paCred = pa_cred
        else:
            scred.cCreds = 0

        if self._verify:
            scred.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION
            if self._ca_store_handle:
                scred.hRootStore = self._ca_store_handle
        else:
            scred.dwFlags = (
                SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS
            )

        ts = TimeStamp()
        status = _secur32.AcquireCredentialsHandleW(
            None,
            UNISP_NAME,
            SECPKG_CRED_OUTBOUND,
            None,
            ctypes.byref(scred),
            None,
            None,
            ctypes.byref(self._cred),
            ctypes.byref(ts),
        )
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

            status = _secur32.InitializeSecurityContextW(
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
            )
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
        status = _secur32.QueryContextAttributesW(
            ctypes.byref(self._ctx),
            SECPKG_ATTR_STREAM_SIZES,
            ctypes.byref(sizes),
        )
        if status != SEC_E_OK:
            raise SchannelError("QueryContextAttributes(STREAM_SIZES) failed", status)
        self._stream_sizes = sizes

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
        status = _secur32.EncryptMessage(
            ctypes.byref(self._ctx), 0, ctypes.byref(enc_desc), 0
        )
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
            self._decrypt_one_record()
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
                status = _secur32.DecryptMessage(
                    ctypes.byref(self._ctx), ctypes.byref(dec_desc), 0, ctypes.byref(qop)
                )
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
    """Minimal file-like object backed by a :class:`SchannelSocket`."""

    def __init__(self, sock: SchannelSocket, mode: str) -> None:
        self._sock = sock
        self._mode = mode
        self._closed = False

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            chunks = []
            while True:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        return self._sock.recv(size)

    def readline(self) -> bytes:
        line = b""
        while True:
            c = self._sock.recv(1)
            if not c:
                break
            line += c
            if c == b"\n":
                break
        return line

    def write(self, data: bytes) -> int:
        return self._sock.send(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed

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
