"""SChannel backend using raw ctypes to call Windows SSPI/CryptoAPI."""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
from typing import Any

from .._constants import (
    CERT_FIND_HASH,
    CERT_FIND_SUBJECT_STR,
    CERT_NCRYPT_KEY_SPEC,
    CERT_STORE_PROV_SYSTEM,
    CERT_SYSTEM_STORE_CURRENT_USER,
    CERT_SYSTEM_STORE_LOCAL_MACHINE,
    CRYPT_ACQUIRE_CACHE_FLAG,
    CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG,
    CRYPT_ACQUIRE_SILENT_FLAG,
    CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG,
    ENCODING_DEFAULT,
    ISC_REQ_TLS_CLIENT,
    NCRYPT_WINDOW_HANDLE_PROPERTY,
    PP_CLIENT_HWND,
    SCHANNEL_CRED_VERSION,
    SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT_ALPN,
    SEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS_SUCCESS,
    SEC_E_INCOMPLETE_MESSAGE,
    SEC_E_OK,
    SEC_I_COMPLETE_AND_CONTINUE,
    SEC_I_COMPLETE_NEEDED,
    SEC_I_CONTEXT_EXPIRED,
    SEC_I_RENEGOTIATE,
    SECBUFFER_APPLICATION_PROTOCOLS,
    SECBUFFER_DATA,
    SECBUFFER_EMPTY,
    SECBUFFER_EXTRA,
    SECBUFFER_STREAM_HEADER,
    SECBUFFER_STREAM_TRAILER,
    SECBUFFER_TOKEN,
    SECBUFFER_VERSION,
    SECPKG_ATTR_APPLICATION_PROTOCOL,
    SECPKG_ATTR_CONNECTION_INFO,
    SECPKG_ATTR_REMOTE_CERT_CONTEXT,
    SECPKG_ATTR_STREAM_SIZES,
    SECPKG_CRED_OUTBOUND,
    UNISP_NAME,
)
from .._errors import (
    CertificateNotFoundError,
    DecryptionError,
    EncryptionError,
    RenegotiationError,
    SchannelError,
    sspi_error,
)
from ..backend import (
    CertInfo,
    CertStore,
    ConnectionInfo,
    CredentialConfig,
    CredentialHandle,
    HandshakeResult,
    SchannelBackend,
    SecurityContext,
    StreamSizes,
)

# --- Win32 DLLs ---
_secur32 = ctypes.windll.secur32
_crypt32 = ctypes.windll.crypt32
_ncrypt = ctypes.windll.ncrypt

# --- ctypes Structures ---

ULONG = ctypes.c_ulong
PULONG = ctypes.POINTER(ULONG)
PVOID = ctypes.c_void_p
ULONG_PTR = ctypes.c_size_t  # Pointer-sized unsigned int (ULONG_PTR)


class _SecHandle(ctypes.Structure):
    _fields_ = [
        ("dwLower", ULONG_PTR),
        ("dwUpper", ULONG_PTR),
    ]


class _TimeStamp(ctypes.Structure):
    _fields_ = [
        ("LowPart", wt.DWORD),
        ("HighPart", wt.LONG),
    ]


class _SecBuffer(ctypes.Structure):
    _fields_ = [
        ("cbBuffer", ULONG),
        ("BufferType", ULONG),
        ("pvBuffer", PVOID),
    ]


class _SecBufferDesc(ctypes.Structure):
    _fields_ = [
        ("ulVersion", ULONG),
        ("cBuffers", ULONG),
        ("pBuffers", ctypes.POINTER(_SecBuffer)),
    ]


class _SCHANNEL_CRED(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wt.DWORD),
        ("cCreds", wt.DWORD),
        ("paCred", PVOID),  # PCCERT_CONTEXT*
        ("hRootStore", PVOID),
        ("cMappers", wt.DWORD),
        ("aphMappers", PVOID),
        ("cSupportedAlgs", wt.DWORD),
        ("palgSupportedAlgs", PVOID),
        ("grbitEnabledProtocols", wt.DWORD),
        ("dwMinimumCipherStrength", wt.DWORD),
        ("dwMaximumCipherStrength", wt.DWORD),
        ("dwSessionLifespan", wt.DWORD),
        ("dwFlags", wt.DWORD),
        ("dwCredFormat", wt.DWORD),
    ]


class _SecPkgContext_StreamSizes(ctypes.Structure):
    _fields_ = [
        ("cbHeader", ULONG),
        ("cbTrailer", ULONG),
        ("cbMaximumMessage", ULONG),
        ("cBuffers", ULONG),
        ("cbBlockSize", ULONG),
    ]


class _SecPkgContext_ConnectionInfo(ctypes.Structure):
    _fields_ = [
        ("dwProtocol", wt.DWORD),
        ("aiCipher", wt.DWORD),
        ("dwCipherStrength", wt.DWORD),
        ("aiHash", wt.DWORD),
        ("dwHashStrength", wt.DWORD),
        ("aiExch", wt.DWORD),
        ("dwExchStrength", wt.DWORD),
    ]


class _SecPkgContext_ApplicationProtocol(ctypes.Structure):
    _fields_ = [
        ("ProtoNegoStatus", ULONG),
        ("ProtoNegoExt", ULONG),
        ("ProtocolIdSize", ctypes.c_ubyte),
        ("ProtocolId", ctypes.c_ubyte * 255),
    ]


class _CRYPT_DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wt.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


class _CERT_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("dwCertEncodingType", wt.DWORD),
        ("pbCertEncoded", ctypes.POINTER(ctypes.c_byte)),
        ("cbCertEncoded", wt.DWORD),
        ("pCertInfo", PVOID),
        ("hCertStore", PVOID),
    ]


PCERT_CONTEXT = ctypes.POINTER(_CERT_CONTEXT)

# --- Win32 function prototypes ---
# secur32.dll
_secur32.AcquireCredentialsHandleW.restype = ctypes.c_long
_secur32.InitializeSecurityContextW.restype = ctypes.c_long
_secur32.QueryContextAttributesW.restype = ctypes.c_long
_secur32.EncryptMessage.restype = ctypes.c_long
_secur32.DecryptMessage.restype = ctypes.c_long
_secur32.ApplyControlToken.restype = ctypes.c_long
_secur32.CompleteAuthToken.restype = ctypes.c_long
_secur32.FreeContextBuffer.restype = ctypes.c_long
_secur32.FreeContextBuffer.argtypes = [PVOID]
_secur32.FreeCredentialsHandle.restype = ctypes.c_long
_secur32.DeleteSecurityContext.restype = ctypes.c_long

# crypt32.dll
_crypt32.CertOpenStore.restype = PVOID  # HCERTSTORE
_crypt32.CertOpenStore.argtypes = [
    PVOID,  # lpszStoreProvider (LPCSTR, but often a small integer constant)
    wt.DWORD,  # dwEncodingType
    PVOID,  # hCryptProv
    wt.DWORD,  # dwFlags
    ctypes.c_wchar_p,  # pvPara
]
_crypt32.CertCloseStore.restype = wt.BOOL
_crypt32.CertCloseStore.argtypes = [PVOID, wt.DWORD]
_crypt32.CertFindCertificateInStore.restype = PVOID  # PCCERT_CONTEXT
_crypt32.CertFindCertificateInStore.argtypes = [
    PVOID,  # hCertStore
    wt.DWORD,  # dwCertEncodingType
    wt.DWORD,  # dwFindFlags
    wt.DWORD,  # dwFindType
    PVOID,  # pvFindPara
    PVOID,  # pPrevCertContext
]
_crypt32.CertEnumCertificatesInStore.restype = PVOID
_crypt32.CertEnumCertificatesInStore.argtypes = [PVOID, PVOID]
_crypt32.CertFreeCertificateContext.restype = wt.BOOL
_crypt32.CertFreeCertificateContext.argtypes = [PVOID]
_crypt32.CertGetNameStringW.restype = wt.DWORD
_crypt32.CryptHashCertificate.restype = wt.BOOL

# PFX / cert manipulation
_crypt32.PFXImportCertStore.restype = PVOID  # HCERTSTORE
_crypt32.PFXImportCertStore.argtypes = [PVOID, ctypes.c_wchar_p, wt.DWORD]
_crypt32.CertAddCertificateContextToStore.restype = wt.BOOL
_crypt32.CertAddCertificateContextToStore.argtypes = [
    PVOID,  # hCertStore
    PVOID,  # pCertContext
    wt.DWORD,  # dwAddDisposition
    ctypes.POINTER(PVOID),  # ppStoreContext (optional out)
]
_crypt32.CertDeleteCertificateFromStore.restype = wt.BOOL
_crypt32.CertDeleteCertificateFromStore.argtypes = [PVOID]  # pCertContext
_crypt32.CertDuplicateCertificateContext.restype = PVOID  # PCCERT_CONTEXT
_crypt32.CertDuplicateCertificateContext.argtypes = [PVOID]
_crypt32.CertCreateCertificateContext.restype = PVOID  # PCCERT_CONTEXT
_crypt32.CertCreateCertificateContext.argtypes = [wt.DWORD, ctypes.c_char_p, wt.DWORD]


def _check_sspi(status: int, context: str = "") -> None:
    """Raise on SSPI error codes (negative values are errors)."""
    # SSPI uses HRESULT-like: negative = error, positive/zero = success/info
    if status < 0:
        # Convert to unsigned for lookup
        unsigned = status & 0xFFFFFFFF
        raise sspi_error(unsigned, context)


def _make_sec_handle() -> _SecHandle:
    """Create a zeroed SecHandle."""
    h = _SecHandle()
    ctypes.memset(ctypes.byref(h), 0, ctypes.sizeof(h))
    return h


def _set_cert_key_hwnd(cert_context: Any, hwnd: int) -> None:
    """Pre-acquire and cache the private key for *cert_context* with the
    parent-window handle *hwnd* set, so that Windows Security dialogs
    (certificate-selection pickers and smartcard PIN prompts) appear on top
    of the application window rather than behind it.

    For CAPI keys the HWND is registered via ``CryptSetProvParam(PP_CLIENT_HWND)``.
    For CNG keys it is registered via ``NCryptSetProperty(NCRYPT_WINDOW_HANDLE_PROPERTY)``.
    The key handle is cached inside *cert_context* (``CRYPT_ACQUIRE_CACHE_FLAG``)
    so that SChannel reuses it during the TLS handshake.

    Errors are silently ignored — the HWND hint is best-effort; the TLS
    connection still proceeds if the key cannot be pre-acquired.
    """
    hwnd_val = wt.HWND(hwnd)
    _hprov = ctypes.c_void_p(0)
    _keyspec = wt.DWORD(0)
    _caller_free = wt.BOOL(0)

    acq_flags = (
        CRYPT_ACQUIRE_CACHE_FLAG
        | CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG
        | CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG
    )

    ok = _crypt32.CryptAcquireCertificatePrivateKey(
        cert_context,
        acq_flags,
        ctypes.byref(hwnd_val),  # pvParameters = &hwnd (parent window)
        ctypes.byref(_hprov),
        ctypes.byref(_keyspec),
        ctypes.byref(_caller_free),
    )
    if not ok or not _hprov.value:
        return

    try:
        if _keyspec.value == CERT_NCRYPT_KEY_SPEC:
            # CNG key: set NCRYPT_WINDOW_HANDLE_PROPERTY so the provider
            # uses the correct parent window for PIN dialogs.
            try:
                _ncrypt.NCryptSetProperty(
                    _hprov,
                    ctypes.c_wchar_p(NCRYPT_WINDOW_HANDLE_PROPERTY),
                    ctypes.byref(hwnd_val),
                    ctypes.sizeof(hwnd_val),
                    0,  # dwFlags
                )
            except Exception:
                pass
        else:
            # Legacy CAPI key: set PP_CLIENT_HWND so the CSP uses the correct
            # parent window for PIN dialogs.
            try:
                ctypes.windll.advapi32.CryptSetProvParam(
                    _hprov,
                    PP_CLIENT_HWND,
                    ctypes.byref(hwnd_val),
                    0,
                )
            except Exception:
                pass
    finally:
        # Only release the handle when the caller is responsible AND the key
        # was not cached inside the cert context.  When CRYPT_ACQUIRE_CACHE_FLAG
        # is honoured the handle is owned by the cert context, so _caller_free
        # is FALSE and we must not free it.
        if _caller_free.value and _hprov.value:
            if _keyspec.value == CERT_NCRYPT_KEY_SPEC:
                try:
                    _ncrypt.NCryptFreeObject(_hprov)
                except Exception:
                    pass
            else:
                try:
                    ctypes.windll.advapi32.CryptReleaseContext(_hprov, 0)
                except Exception:
                    pass


def _build_alpn_buffer(protocols: list[str]) -> bytes:
    """Build the SecApplicationProtocols buffer for ALPN negotiation.

    Wire format: DWORD ProtocolListsSize, then for each list:
      DWORD ProtoNegoExt (1=TLS), WORD ProtocolListSize, then length-prefixed strings.
    """
    # Build the protocol list: each entry is 1-byte length + ASCII bytes
    proto_entries = b""
    for proto in protocols:
        encoded = proto.encode("ascii")
        proto_entries += struct.pack("B", len(encoded)) + encoded

    # Protocol list struct: ProtoNegoExt (DWORD) + ProtocolListSize (WORD) + entries
    inner = (
        struct.pack(
            "<IH",
            SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT_ALPN,
            len(proto_entries),
        )
        + proto_entries
    )

    # Outer: ProtocolListsSize (DWORD) + inner
    return struct.pack("<I", len(inner)) + inner


class CtypesCertStore(CertStore):
    """Certificate store access via raw crypt32.dll ctypes calls."""

    def open(self, store_name: str = "MY", machine: bool = False) -> Any:
        flags = CERT_SYSTEM_STORE_LOCAL_MACHINE if machine else CERT_SYSTEM_STORE_CURRENT_USER
        store = _crypt32.CertOpenStore(
            CERT_STORE_PROV_SYSTEM,
            0,
            None,
            flags,
            ctypes.c_wchar_p(store_name),
        )
        if not store:
            raise SchannelError(f"Failed to open certificate store '{store_name}'")
        # Wrap in c_void_p to preserve pointer identity for subsequent calls
        return ctypes.c_void_p(store)

    def close(self, store_handle: Any) -> None:
        _crypt32.CertCloseStore(store_handle, 0)

    def find_by_thumbprint(self, store_handle: Any, thumbprint: str) -> Any:
        # Convert hex thumbprint to binary hash
        hash_bytes = bytes.fromhex(thumbprint.replace(" ", "").replace(":", ""))
        hash_blob = _CRYPT_DATA_BLOB()
        hash_blob.cbData = len(hash_bytes)
        hash_blob.pbData = (ctypes.c_byte * len(hash_bytes))(*hash_bytes)

        cert = _crypt32.CertFindCertificateInStore(
            store_handle,
            ENCODING_DEFAULT,
            0,
            CERT_FIND_HASH,
            ctypes.byref(hash_blob),
            None,
        )
        if not cert:
            raise CertificateNotFoundError(f"Certificate with thumbprint '{thumbprint}' not found")
        return ctypes.cast(cert, PCERT_CONTEXT)

    def find_by_subject(self, store_handle: Any, subject: str) -> Any:
        cert = _crypt32.CertFindCertificateInStore(
            store_handle,
            ENCODING_DEFAULT,
            0,
            CERT_FIND_SUBJECT_STR,
            ctypes.c_wchar_p(subject),
            None,
        )
        if not cert:
            raise CertificateNotFoundError(
                f"Certificate with subject containing '{subject}' not found"
            )
        return ctypes.cast(cert, PCERT_CONTEXT)

    def enumerate(self, store_handle: Any) -> list[CertInfo]:
        results: list[CertInfo] = []
        cert = None
        while True:
            cert = _crypt32.CertEnumCertificatesInStore(store_handle, cert)
            if not cert:
                break
            cert_ptr = ctypes.cast(cert, PCERT_CONTEXT)
            try:
                results.append(self.get_cert_info(cert_ptr))
            except Exception:
                continue
        return results

    def get_cert_info(self, cert_context: Any) -> CertInfo:
        ctx = cert_context
        if not ctx:
            raise CertificateNotFoundError("Null certificate context")

        cert_ctx = ctx.contents

        # Get DER-encoded certificate
        der_size = cert_ctx.cbCertEncoded
        der_bytes = bytes(
            ctypes.cast(cert_ctx.pbCertEncoded, ctypes.POINTER(ctypes.c_byte * der_size)).contents
        )

        # Get subject name
        subject_size = _crypt32.CertGetNameStringW(
            cert_context,
            1,
            0,
            None,
            None,
            0,  # CERT_NAME_SIMPLE_DISPLAY_TYPE
        )
        subject_buf = ctypes.create_unicode_buffer(subject_size)
        _crypt32.CertGetNameStringW(cert_context, 1, 0, None, subject_buf, subject_size)

        # Get issuer name
        issuer_size = _crypt32.CertGetNameStringW(
            cert_context,
            1,
            1,
            None,
            None,
            0,  # flags=1 = CERT_NAME_ISSUER_FLAG
        )
        issuer_buf = ctypes.create_unicode_buffer(issuer_size)
        _crypt32.CertGetNameStringW(cert_context, 1, 1, None, issuer_buf, issuer_size)

        # Compute SHA-1 thumbprint
        hash_size = wt.DWORD(20)
        hash_buf = (ctypes.c_byte * 20)()
        _crypt32.CryptHashCertificate(
            0,
            0x00008003,
            0,  # CALG_SHA1
            cert_ctx.pbCertEncoded,
            cert_ctx.cbCertEncoded,
            hash_buf,
            ctypes.byref(hash_size),
        )
        thumbprint = bytes(hash_buf).hex().upper()

        # Check for private key availability
        _hprov = ctypes.c_void_p(0)
        _keyspec = wt.DWORD(0)
        _caller_free = wt.BOOL(0)
        has_key = bool(
            _crypt32.CryptAcquireCertificatePrivateKey(
                cert_context,
                CRYPT_ACQUIRE_SILENT_FLAG,
                None,
                ctypes.byref(_hprov),
                ctypes.byref(_keyspec),
                ctypes.byref(_caller_free),
            )
        )
        if has_key and _caller_free.value and _hprov.value:
            # Release the handle if the caller is responsible
            try:
                ctypes.windll.advapi32.CryptReleaseContext(_hprov, 0)
            except Exception:
                pass

        return CertInfo(
            thumbprint=thumbprint,
            subject=subject_buf.value,
            issuer=issuer_buf.value,
            friendly_name="",  # Requires property lookup; simplified
            not_before=0.0,
            not_after=0.0,
            has_private_key=has_key,
            serial_number="",
            der_encoded=der_bytes,
        )

    def free_certificate(self, cert_context: Any) -> None:
        if cert_context:
            _crypt32.CertFreeCertificateContext(cert_context)


class CtypesBackend(SchannelBackend):
    """SChannel backend using raw ctypes calls to secur32.dll and crypt32.dll."""

    def __init__(self) -> None:
        self._cert_store = CtypesCertStore()

    @property
    def cert_store(self) -> CtypesCertStore:
        return self._cert_store

    def acquire_credentials(self, config: CredentialConfig) -> CredentialHandle:
        cred = _SCHANNEL_CRED()
        ctypes.memset(ctypes.byref(cred), 0, ctypes.sizeof(cred))
        cred.dwVersion = SCHANNEL_CRED_VERSION
        cred.grbitEnabledProtocols = config.protocols
        cred.dwFlags = config.flags

        # If a client certificate is provided, set it
        cert_array = None
        if config.cert_context is not None:
            cert_array = (PCERT_CONTEXT * 1)(config.cert_context)
            cred.cCreds = 1
            cred.paCred = ctypes.cast(cert_array, PVOID)

            # If a parent window handle is provided, pre-acquire and cache the
            # private key with the HWND set so that Windows Security dialogs
            # (certificate selection, smartcard PIN prompts) appear on top of
            # the application window rather than behind it.
            if config.hwnd is not None:
                _set_cert_key_hwnd(config.cert_context, config.hwnd)

        cred_handle = _make_sec_handle()
        expiry = _TimeStamp()

        status = _secur32.AcquireCredentialsHandleW(
            None,  # principal
            ctypes.c_wchar_p(UNISP_NAME),
            SECPKG_CRED_OUTBOUND,
            None,  # logon ID
            ctypes.byref(cred),
            None,  # get key fn
            None,  # get key arg
            ctypes.byref(cred_handle),
            ctypes.byref(expiry),
        )
        _check_sspi(status, "AcquireCredentialsHandle")
        return CredentialHandle(cred_handle, backend_data=cert_array)

    def create_context(
        self,
        credential: CredentialHandle,
        target_name: str,
        flags: int = ISC_REQ_TLS_CLIENT,
        alpn_protocols: list[str] | None = None,
    ) -> SecurityContext:
        ctx = SecurityContext()
        ctx.backend_data = {
            "credential": credential,
            "target_name": target_name,
            "flags": flags,
            "alpn_protocols": alpn_protocols,
            "handle": None,  # Will be set during first handshake step
            "initialized": False,
        }
        return ctx

    def handshake_step(
        self, context: SecurityContext, in_token: bytes | None = None
    ) -> HandshakeResult:
        data = context.backend_data
        credential = data["credential"]
        target_name = data["target_name"]
        flags = data["flags"]
        is_first = not data["initialized"]

        # Output buffer
        out_buf = _SecBuffer()
        out_buf.cbBuffer = 0
        out_buf.BufferType = SECBUFFER_TOKEN
        out_buf.pvBuffer = None

        out_buf_desc = _SecBufferDesc()
        out_buf_desc.ulVersion = SECBUFFER_VERSION
        out_buf_desc.cBuffers = 1
        out_buf_desc.pBuffers = ctypes.pointer(out_buf)

        # Input buffer(s)
        in_buf_desc_ptr = None
        in_bufs = None
        in_buf_data = None
        alpn_buf_data = None

        if in_token is not None or (is_first and data.get("alpn_protocols")):
            buf_list = []

            if in_token is not None:
                in_buf_data = ctypes.create_string_buffer(in_token, len(in_token))
                token_buf = _SecBuffer()
                token_buf.cbBuffer = len(in_token)
                token_buf.BufferType = SECBUFFER_TOKEN
                token_buf.pvBuffer = ctypes.cast(in_buf_data, PVOID)
                buf_list.append(token_buf)

                empty_buf = _SecBuffer()
                empty_buf.cbBuffer = 0
                empty_buf.BufferType = SECBUFFER_EMPTY
                empty_buf.pvBuffer = None
                buf_list.append(empty_buf)

            if data.get("alpn_protocols") and is_first:
                alpn_bytes = _build_alpn_buffer(data["alpn_protocols"])
                alpn_buf_data = ctypes.create_string_buffer(alpn_bytes, len(alpn_bytes))
                alpn_buf = _SecBuffer()
                alpn_buf.cbBuffer = len(alpn_bytes)
                alpn_buf.BufferType = SECBUFFER_APPLICATION_PROTOCOLS
                alpn_buf.pvBuffer = ctypes.cast(alpn_buf_data, PVOID)
                buf_list.append(alpn_buf)

            in_bufs = (_SecBuffer * len(buf_list))(*buf_list)
            in_buf_desc = _SecBufferDesc()
            in_buf_desc.ulVersion = SECBUFFER_VERSION
            in_buf_desc.cBuffers = len(buf_list)
            in_buf_desc.pBuffers = ctypes.cast(in_bufs, ctypes.POINTER(_SecBuffer))
            in_buf_desc_ptr = ctypes.byref(in_buf_desc)

        ctx_handle = data.get("handle")
        new_ctx_handle = _make_sec_handle()
        attrs = ULONG(0)
        expiry = _TimeStamp()

        status = _secur32.InitializeSecurityContextW(
            ctypes.byref(credential.raw),
            ctypes.byref(ctx_handle) if ctx_handle is not None else None,
            ctypes.c_wchar_p(target_name),
            flags,
            0,  # reserved
            0,  # target data rep
            in_buf_desc_ptr,
            0,  # reserved
            ctypes.byref(new_ctx_handle),
            ctypes.byref(out_buf_desc),
            ctypes.byref(attrs),
            ctypes.byref(expiry),
        )

        # Update context handle
        if ctx_handle is None or status >= 0:
            data["handle"] = new_ctx_handle
            context.raw = new_ctx_handle
            data["initialized"] = True

        # Process status
        unsigned_status = status & 0xFFFFFFFF

        if unsigned_status == SEC_E_INCOMPLETE_MESSAGE:
            return HandshakeResult(output_token=b"", complete=False, extra_data=in_token or b"")

        if status < 0:
            raise sspi_error(unsigned_status, "InitializeSecurityContext")

        # Extract output token
        out_token = b""
        if out_buf.cbBuffer > 0 and out_buf.pvBuffer:
            out_token = bytes(
                ctypes.cast(
                    out_buf.pvBuffer, ctypes.POINTER(ctypes.c_byte * out_buf.cbBuffer)
                ).contents
            )
            _secur32.FreeContextBuffer(ctypes.c_void_p(out_buf.pvBuffer))

        # Check for extra data in input buffers
        extra_data = b""
        if in_bufs is not None:
            for i in range(len(in_bufs)):
                if in_bufs[i].BufferType == SECBUFFER_EXTRA and in_bufs[i].cbBuffer > 0:
                    # Extra data is the tail of the original input
                    if in_token is not None:
                        extra_data = in_token[-in_bufs[i].cbBuffer :]
                    break

        complete = unsigned_status == SEC_E_OK

        # Handle SEC_I_COMPLETE_NEEDED / SEC_I_COMPLETE_AND_CONTINUE
        if unsigned_status in (SEC_I_COMPLETE_NEEDED, SEC_I_COMPLETE_AND_CONTINUE):
            _secur32.CompleteAuthToken(ctypes.byref(context.raw), ctypes.byref(out_buf_desc))
            complete = unsigned_status == SEC_I_COMPLETE_NEEDED

        return HandshakeResult(output_token=out_token, complete=complete, extra_data=extra_data)

    def encrypt(self, context: SecurityContext, plaintext: bytes) -> bytes:
        sizes = self.get_stream_sizes(context)

        # SChannel stream encryption: [header][data][trailer]
        header_buf = ctypes.create_string_buffer(sizes.header)
        data_buf = ctypes.create_string_buffer(plaintext, len(plaintext))
        trailer_buf = ctypes.create_string_buffer(sizes.trailer)

        bufs = (_SecBuffer * 4)()
        bufs[0].cbBuffer = sizes.header
        bufs[0].BufferType = SECBUFFER_STREAM_HEADER
        bufs[0].pvBuffer = ctypes.cast(header_buf, PVOID)

        bufs[1].cbBuffer = len(plaintext)
        bufs[1].BufferType = SECBUFFER_DATA
        bufs[1].pvBuffer = ctypes.cast(data_buf, PVOID)

        bufs[2].cbBuffer = sizes.trailer
        bufs[2].BufferType = SECBUFFER_STREAM_TRAILER
        bufs[2].pvBuffer = ctypes.cast(trailer_buf, PVOID)

        bufs[3].cbBuffer = 0
        bufs[3].BufferType = SECBUFFER_EMPTY
        bufs[3].pvBuffer = None

        buf_desc = _SecBufferDesc()
        buf_desc.ulVersion = SECBUFFER_VERSION
        buf_desc.cBuffers = 4
        buf_desc.pBuffers = ctypes.cast(bufs, ctypes.POINTER(_SecBuffer))

        status = _secur32.EncryptMessage(ctypes.byref(context.raw), 0, ctypes.byref(buf_desc), 0)
        if status != 0:
            raise EncryptionError(f"EncryptMessage failed: 0x{status & 0xFFFFFFFF:08X}")

        return (
            bytes(
                ctypes.cast(
                    bufs[0].pvBuffer, ctypes.POINTER(ctypes.c_byte * bufs[0].cbBuffer)
                ).contents
            )
            + bytes(
                ctypes.cast(
                    bufs[1].pvBuffer, ctypes.POINTER(ctypes.c_byte * bufs[1].cbBuffer)
                ).contents
            )
            + bytes(
                ctypes.cast(
                    bufs[2].pvBuffer, ctypes.POINTER(ctypes.c_byte * bufs[2].cbBuffer)
                ).contents
            )
        )

    def decrypt(self, context: SecurityContext, ciphertext: bytes) -> tuple[bytes, bytes]:
        data_buf = ctypes.create_string_buffer(ciphertext, len(ciphertext))

        bufs = (_SecBuffer * 4)()
        bufs[0].cbBuffer = len(ciphertext)
        bufs[0].BufferType = SECBUFFER_DATA
        bufs[0].pvBuffer = ctypes.cast(data_buf, PVOID)

        for i in range(1, 4):
            bufs[i].cbBuffer = 0
            bufs[i].BufferType = SECBUFFER_EMPTY
            bufs[i].pvBuffer = None

        buf_desc = _SecBufferDesc()
        buf_desc.ulVersion = SECBUFFER_VERSION
        buf_desc.cBuffers = 4
        buf_desc.pBuffers = ctypes.cast(bufs, ctypes.POINTER(_SecBuffer))

        status = _secur32.DecryptMessage(ctypes.byref(context.raw), ctypes.byref(buf_desc), 0, None)

        unsigned = status & 0xFFFFFFFF

        if unsigned == SEC_E_INCOMPLETE_MESSAGE:
            # Need more data — return empty plaintext and all data as extra
            return b"", ciphertext

        if unsigned == SEC_I_CONTEXT_EXPIRED:
            # Peer sent close_notify
            return b"", b""

        if unsigned == SEC_I_RENEGOTIATE:
            raise RenegotiationError("Server requested TLS renegotiation")

        if status < 0:
            raise DecryptionError(f"DecryptMessage failed: 0x{unsigned:08X}")

        # Find plaintext and extra data in output buffers
        plaintext = b""
        extra = b""
        for i in range(4):
            if bufs[i].BufferType == SECBUFFER_DATA and bufs[i].cbBuffer > 0:
                plaintext = bytes(
                    ctypes.cast(
                        bufs[i].pvBuffer, ctypes.POINTER(ctypes.c_byte * bufs[i].cbBuffer)
                    ).contents
                )
            elif bufs[i].BufferType == SECBUFFER_EXTRA and bufs[i].cbBuffer > 0:
                extra = ciphertext[-bufs[i].cbBuffer :]

        return plaintext, extra

    def shutdown(self, context: SecurityContext) -> bytes:
        # Send a close_notify by applying SCHANNEL_SHUTDOWN
        shutdown_token = struct.pack("<I", 1)  # SCHANNEL_SHUTDOWN
        token_buf_data = ctypes.create_string_buffer(shutdown_token, len(shutdown_token))

        buf = _SecBuffer()
        buf.cbBuffer = len(shutdown_token)
        buf.BufferType = SECBUFFER_TOKEN
        buf.pvBuffer = ctypes.cast(token_buf_data, PVOID)

        buf_desc = _SecBufferDesc()
        buf_desc.ulVersion = SECBUFFER_VERSION
        buf_desc.cBuffers = 1
        buf_desc.pBuffers = ctypes.pointer(buf)

        status = _secur32.ApplyControlToken(ctypes.byref(context.raw), ctypes.byref(buf_desc))
        if status < 0:
            return b""

        # Now call InitializeSecurityContext to get the shutdown token
        data = context.backend_data
        out_buf = _SecBuffer()
        out_buf.cbBuffer = 0
        out_buf.BufferType = SECBUFFER_TOKEN
        out_buf.pvBuffer = None

        out_desc = _SecBufferDesc()
        out_desc.ulVersion = SECBUFFER_VERSION
        out_desc.cBuffers = 1
        out_desc.pBuffers = ctypes.pointer(out_buf)

        attrs = ULONG(0)
        expiry = _TimeStamp()

        _secur32.InitializeSecurityContextW(
            ctypes.byref(data["credential"].raw),
            ctypes.byref(context.raw),
            ctypes.c_wchar_p(data["target_name"]),
            data["flags"],
            0,
            0,
            None,
            0,
            None,
            ctypes.byref(out_desc),
            ctypes.byref(attrs),
            ctypes.byref(expiry),
        )

        result = b""
        if out_buf.cbBuffer > 0 and out_buf.pvBuffer:
            result = bytes(
                ctypes.cast(
                    out_buf.pvBuffer, ctypes.POINTER(ctypes.c_byte * out_buf.cbBuffer)
                ).contents
            )
            _secur32.FreeContextBuffer(ctypes.c_void_p(out_buf.pvBuffer))
        return result

    def get_peer_certificate(self, context: SecurityContext) -> bytes:
        cert_ptr = PVOID()
        status = _secur32.QueryContextAttributesW(
            ctypes.byref(context.raw), SECPKG_ATTR_REMOTE_CERT_CONTEXT, ctypes.byref(cert_ptr)
        )
        if status != 0 or not cert_ptr:
            raise SchannelError("Failed to get peer certificate")

        cert_context = ctypes.cast(cert_ptr, PCERT_CONTEXT).contents
        der = bytes(
            ctypes.cast(
                cert_context.pbCertEncoded,
                ctypes.POINTER(ctypes.c_byte * cert_context.cbCertEncoded),
            ).contents
        )
        _crypt32.CertFreeCertificateContext(cert_ptr)
        return der

    def get_connection_info(self, context: SecurityContext) -> ConnectionInfo:
        info = _SecPkgContext_ConnectionInfo()
        status = _secur32.QueryContextAttributesW(
            ctypes.byref(context.raw), SECPKG_ATTR_CONNECTION_INFO, ctypes.byref(info)
        )
        if status != 0:
            raise SchannelError("Failed to query connection info")

        protocol_map = {
            0x00000800: "TLSv1.2",
            0x00002000: "TLSv1.3",
        }
        return ConnectionInfo(
            protocol_version=protocol_map.get(info.dwProtocol, f"0x{info.dwProtocol:X}"),
            cipher_algorithm=info.aiCipher,
            cipher_strength=info.dwCipherStrength,
            hash_algorithm=info.aiHash,
            hash_strength=info.dwHashStrength,
            exchange_algorithm=info.aiExch,
            exchange_strength=info.dwExchStrength,
        )

    def get_stream_sizes(self, context: SecurityContext) -> StreamSizes:
        if context.stream_sizes is not None:
            return context.stream_sizes

        sizes = _SecPkgContext_StreamSizes()
        status = _secur32.QueryContextAttributesW(
            ctypes.byref(context.raw), SECPKG_ATTR_STREAM_SIZES, ctypes.byref(sizes)
        )
        if status != 0:
            raise SchannelError("Failed to query stream sizes")

        result = StreamSizes(
            header=sizes.cbHeader,
            trailer=sizes.cbTrailer,
            max_message=sizes.cbMaximumMessage,
            buffers=sizes.cBuffers,
            block_size=sizes.cbBlockSize,
        )
        context.stream_sizes = result
        return result

    def get_negotiated_protocol(self, context: SecurityContext) -> str | None:
        proto = _SecPkgContext_ApplicationProtocol()
        status = _secur32.QueryContextAttributesW(
            ctypes.byref(context.raw), SECPKG_ATTR_APPLICATION_PROTOCOL, ctypes.byref(proto)
        )
        if status != 0:
            return None
        if proto.ProtoNegoStatus != SEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS_SUCCESS:
            return None
        if proto.ProtocolIdSize == 0:
            return None
        return bytes(proto.ProtocolId[: proto.ProtocolIdSize]).decode("ascii")

    def free_credentials(self, credential: CredentialHandle) -> None:
        try:
            _secur32.FreeCredentialsHandle(ctypes.byref(credential.raw))
        except OSError:
            pass

    def free_context(self, context: SecurityContext) -> None:
        if context.raw is not None:
            try:
                _secur32.DeleteSecurityContext(ctypes.byref(context.raw))
            except OSError:
                pass
