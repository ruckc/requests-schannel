"""
Windows API type definitions (ctypes) for SChannel and CryptoAPI.

All structures, constants, and DLL bindings required by _cert_store.py and
_schannel.py live here so that they can be imported in a single place and
tested/mocked independently.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

ULONG = ctypes.c_ulong
ULONG_PTR = ctypes.c_size_t  # pointer-sized unsigned int (32 or 64 bit)
SECURITY_STATUS = ctypes.c_long  # signed 32-bit HRESULT-style


# ---------------------------------------------------------------------------
# SSPI / SChannel status codes (SECURITY_STATUS / HRESULT)
# ---------------------------------------------------------------------------

SEC_E_OK: int = 0x00000000
SEC_I_CONTINUE_NEEDED: int = 0x00090312
SEC_I_COMPLETE_NEEDED: int = 0x00090313
SEC_I_COMPLETE_AND_CONTINUE: int = 0x00090314
SEC_I_INCOMPLETE_CREDENTIALS: int = 0x00090320
SEC_E_INCOMPLETE_MESSAGE: int = 0x80090318
SEC_E_INVALID_HANDLE: int = 0x80100003
SEC_E_INVALID_TOKEN: int = 0x80090308
SEC_E_TARGET_NAME: int = 0x80090303
SEC_E_UNTRUSTED_ROOT: int = 0x80090325
SEC_E_CERT_EXPIRED: int = 0x80090328
SEC_E_WRONG_PRINCIPAL: int = 0x80090322
SEC_E_UNSUPPORTED_FUNCTION: int = 0x80090302
SEC_E_INSUFFICIENT_MEMORY: int = 0x80090300
SEC_E_INTERNAL_ERROR: int = 0x80090304
SEC_E_NO_CREDENTIALS: int = 0x8009030E
SEC_E_NOT_OWNER: int = 0x80090306

# ---------------------------------------------------------------------------
# SecBuffer / SecBufferDesc constants
# ---------------------------------------------------------------------------

SECBUFFER_VERSION: int = 0
SECBUFFER_EMPTY: int = 0
SECBUFFER_DATA: int = 1
SECBUFFER_TOKEN: int = 2
SECBUFFER_PKG_PARAMS: int = 3
SECBUFFER_MISSING: int = 4
SECBUFFER_EXTRA: int = 5
SECBUFFER_STREAM_TRAILER: int = 6
SECBUFFER_STREAM_HEADER: int = 7
SECBUFFER_STREAM: int = 10
SECBUFFER_ALERT: int = 17

# ---------------------------------------------------------------------------
# InitializeSecurityContext request / context attribute flags
# ---------------------------------------------------------------------------

ISC_REQ_SEQUENCE_DETECT: int = 0x00000008
ISC_REQ_REPLAY_DETECT: int = 0x00000004
ISC_REQ_CONFIDENTIALITY: int = 0x00000010
ISC_REQ_USE_SUPPLIED_CREDS: int = 0x00000080
ISC_REQ_ALLOCATE_MEMORY: int = 0x00000100
ISC_REQ_EXTENDED_ERROR: int = 0x00004000
ISC_REQ_STREAM: int = 0x00008000
ISC_REQ_MANUAL_CRED_VALIDATION: int = 0x00080000

SECURITY_NATIVE_DREP: int = 0x00000010
SECPKG_CRED_OUTBOUND: int = 0x00000002

# ---------------------------------------------------------------------------
# SChannel credential / protocol constants
# ---------------------------------------------------------------------------

UNISP_NAME: str = "Microsoft Unified Security Protocol Provider"
SCHANNEL_CRED_VERSION: int = 4

# grbitEnabledProtocols – allow TLS 1.2 and TLS 1.3 only
SP_PROT_TLS1_2_CLIENT: int = 0x00000200
SP_PROT_TLS1_3_CLIENT: int = 0x00002000

# dwFlags for SCHANNEL_CRED
SCH_CRED_NO_DEFAULT_CREDS: int = 0x00000010
SCH_CRED_AUTO_CRED_VALIDATION: int = 0x00000020
SCH_CRED_MANUAL_CRED_VALIDATION: int = 0x00000008
SCH_CRED_NO_SERVERNAME_CHECK: int = 0x00000004
SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT: int = 0x00000400

# ---------------------------------------------------------------------------
# QueryContextAttributes attribute identifiers
# ---------------------------------------------------------------------------

SECPKG_ATTR_STREAM_SIZES: int = 4
SECPKG_ATTR_REMOTE_CERT_CONTEXT: int = 83
SECPKG_ATTR_CONNECTION_INFO: int = 90

# ---------------------------------------------------------------------------
# CryptoAPI / Crypt32 constants
# ---------------------------------------------------------------------------

X509_ASN_ENCODING: int = 0x00000001
PKCS_7_ASN_ENCODING: int = 0x00010000
CERT_ENCODING_TYPE: int = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING

CERT_STORE_PROV_SYSTEM: int = 10
CERT_SYSTEM_STORE_CURRENT_USER: int = 0x00010000
CERT_SYSTEM_STORE_LOCAL_MACHINE: int = 0x00020000

CERT_CLOSE_STORE_FORCE_FLAG: int = 0x00000001

# CertFindCertificateInStore dwFindType
CERT_FIND_SHA1_HASH: int = 0x00010000
CERT_FIND_SUBJECT_STR_W: int = 0x00080007
CERT_FIND_ISSUER_STR_W: int = 0x00040004
CERT_FIND_ANY: int = 0x00000000

# CertGetCertificateContextProperty property ID
CERT_SHA1_HASH_PROP_ID: int = 3
CERT_FRIENDLY_NAME_PROP_ID: int = 11
CERT_KEY_PROV_INFO_PROP_ID: int = 2

# PFX import flags
CRYPT_EXPORTABLE: int = 0x00000001
CRYPT_USER_PROTECTED: int = 0x00000002
CRYPT_MACHINE_KEYSET: int = 0x00000020
CRYPT_USER_KEYSET: int = 0x00001000

# CertAddCertificateContextToStore disposition
CERT_STORE_ADD_NEW: int = 1
CERT_STORE_ADD_REPLACE_EXISTING: int = 3
CERT_STORE_ADD_USE_EXISTING: int = 2

# ---------------------------------------------------------------------------
# Structures
# ---------------------------------------------------------------------------


class SecHandle(ctypes.Structure):
    """Maps to the Windows SecHandle / CredHandle / CtxtHandle union."""

    _fields_ = [
        ("dwLower", ULONG_PTR),
        ("dwUpper", ULONG_PTR),
    ]


CredHandle = SecHandle
CtxtHandle = SecHandle


class TimeStamp(ctypes.Structure):
    """Maps to LARGE_INTEGER / TimeStamp used by SSPI."""

    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG),
    ]


class SecBuffer(ctypes.Structure):
    """Maps to the Windows SecBuffer structure."""

    _fields_ = [
        ("cbBuffer", wintypes.ULONG),
        ("BufferType", wintypes.ULONG),
        ("pvBuffer", ctypes.c_void_p),
    ]


class SecBufferDesc(ctypes.Structure):
    """Maps to the Windows SecBufferDesc structure."""

    _fields_ = [
        ("ulVersion", wintypes.ULONG),
        ("cBuffers", wintypes.ULONG),
        ("pBuffers", ctypes.POINTER(SecBuffer)),
    ]


class SCHANNEL_CRED(ctypes.Structure):
    """Maps to the Windows SCHANNEL_CRED structure (dwVersion == 4)."""

    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("cCreds", wintypes.DWORD),
        # Array of PCCERT_CONTEXT pointers (we keep it as void* array)
        ("paCred", ctypes.POINTER(ctypes.c_void_p)),
        ("hRootStore", wintypes.HANDLE),
        ("cMappers", wintypes.DWORD),
        ("aphMappers", ctypes.c_void_p),
        ("cSupportedAlgs", wintypes.DWORD),
        ("palgSupportedAlgs", ctypes.c_void_p),
        ("grbitEnabledProtocols", wintypes.DWORD),
        ("dwMinimumCipherStrength", wintypes.DWORD),
        ("dwMaximumCipherStrength", wintypes.DWORD),
        ("dwSessionLifespan", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("dwCredFormat", wintypes.DWORD),
    ]


class SecPkgContext_StreamSizes(ctypes.Structure):
    """Maps to SecPkgContext_StreamSizes – returned by QueryContextAttributes."""

    _fields_ = [
        ("cbHeader", wintypes.ULONG),
        ("cbTrailer", wintypes.ULONG),
        ("cbMaximumMessage", wintypes.ULONG),
        ("cBuffers", wintypes.ULONG),
        ("cbBlockSize", wintypes.ULONG),
    ]


class CRYPTOAPI_BLOB(ctypes.Structure):
    """Maps to CRYPT_DATA_BLOB / CRYPT_HASH_BLOB etc."""

    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


# ---------------------------------------------------------------------------
# DLL bindings  (loaded lazily – only when first accessed)
# ---------------------------------------------------------------------------


def _load_secur32() -> ctypes.WinDLL:  # type: ignore[name-defined]
    lib = ctypes.WinDLL("secur32", use_last_error=True)  # type: ignore[attr-defined]

    # AcquireCredentialsHandleW
    lib.AcquireCredentialsHandleW.restype = SECURITY_STATUS
    lib.AcquireCredentialsHandleW.argtypes = [
        ctypes.c_wchar_p,             # pszPrincipal
        ctypes.c_wchar_p,             # pszPackage
        wintypes.ULONG,               # fCredentialUse
        ctypes.c_void_p,              # pvLogonID
        ctypes.c_void_p,              # pAuthData (SCHANNEL_CRED*)
        ctypes.c_void_p,              # pGetKeyFn
        ctypes.c_void_p,              # pvGetKeyArgument
        ctypes.POINTER(CredHandle),   # phCredential (out)
        ctypes.POINTER(TimeStamp),    # ptsExpiry (out)
    ]

    # InitializeSecurityContextW
    lib.InitializeSecurityContextW.restype = SECURITY_STATUS
    lib.InitializeSecurityContextW.argtypes = [
        ctypes.POINTER(CredHandle),   # phCredential
        ctypes.POINTER(CtxtHandle),   # phContext (NULL on first call)
        ctypes.c_wchar_p,             # pszTargetName
        wintypes.ULONG,               # fContextReq
        wintypes.ULONG,               # Reserved1
        wintypes.ULONG,               # TargetDataRep
        ctypes.POINTER(SecBufferDesc),# pInput (NULL on first call)
        wintypes.ULONG,               # Reserved2
        ctypes.POINTER(CtxtHandle),   # phNewContext (out)
        ctypes.POINTER(SecBufferDesc),# pOutput (out)
        ctypes.POINTER(wintypes.ULONG),# pfContextAttr (out)
        ctypes.POINTER(TimeStamp),    # ptsExpiry (out)
    ]

    # DeleteSecurityContext
    lib.DeleteSecurityContext.restype = SECURITY_STATUS
    lib.DeleteSecurityContext.argtypes = [ctypes.POINTER(CtxtHandle)]

    # FreeCredentialsHandle
    lib.FreeCredentialsHandle.restype = SECURITY_STATUS
    lib.FreeCredentialsHandle.argtypes = [ctypes.POINTER(CredHandle)]

    # FreeContextBuffer
    lib.FreeContextBuffer.restype = SECURITY_STATUS
    lib.FreeContextBuffer.argtypes = [ctypes.c_void_p]

    # EncryptMessage
    lib.EncryptMessage.restype = SECURITY_STATUS
    lib.EncryptMessage.argtypes = [
        ctypes.POINTER(CtxtHandle),    # phContext
        wintypes.ULONG,                # fQOP
        ctypes.POINTER(SecBufferDesc), # pMessage
        wintypes.ULONG,                # MessageSeqNo
    ]

    # DecryptMessage
    lib.DecryptMessage.restype = SECURITY_STATUS
    lib.DecryptMessage.argtypes = [
        ctypes.POINTER(CtxtHandle),    # phContext
        ctypes.POINTER(SecBufferDesc), # pMessage
        wintypes.ULONG,                # MessageSeqNo
        ctypes.POINTER(wintypes.ULONG),# pfQOP (out)
    ]

    # QueryContextAttributesW
    lib.QueryContextAttributesW.restype = SECURITY_STATUS
    lib.QueryContextAttributesW.argtypes = [
        ctypes.POINTER(CtxtHandle),    # phContext
        wintypes.ULONG,                # ulAttribute
        ctypes.c_void_p,               # pBuffer (out)
    ]

    return lib


def _load_crypt32() -> ctypes.WinDLL:  # type: ignore[name-defined]
    lib = ctypes.WinDLL("crypt32", use_last_error=True)  # type: ignore[attr-defined]

    # CertCreateCertificateContext
    lib.CertCreateCertificateContext.restype = ctypes.c_void_p  # PCCERT_CONTEXT
    lib.CertCreateCertificateContext.argtypes = [
        wintypes.DWORD,    # dwCertEncodingType
        ctypes.c_void_p,   # pbCertEncoded
        wintypes.DWORD,    # cbCertEncoded
    ]

    # CertOpenStore
    lib.CertOpenStore.restype = wintypes.HANDLE
    lib.CertOpenStore.argtypes = [
        ctypes.c_void_p,   # lpszStoreProvider (CERT_STORE_PROV_SYSTEM → int cast)
        wintypes.DWORD,    # dwEncodingType
        wintypes.HANDLE,   # hCryptProv
        wintypes.DWORD,    # dwFlags
        ctypes.c_void_p,   # pvPara (store name as wide string)
    ]

    # CertCloseStore
    lib.CertCloseStore.restype = wintypes.BOOL
    lib.CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]

    # CertFindCertificateInStore
    lib.CertFindCertificateInStore.restype = ctypes.c_void_p  # PCCERT_CONTEXT
    lib.CertFindCertificateInStore.argtypes = [
        wintypes.HANDLE,    # hCertStore
        wintypes.DWORD,     # dwCertEncodingType
        wintypes.DWORD,     # dwFindFlags
        wintypes.DWORD,     # dwFindType
        ctypes.c_void_p,    # pvFindPara
        ctypes.c_void_p,    # pPrevCertContext (PCCERT_CONTEXT)
    ]

    # CertFreeCertificateContext
    lib.CertFreeCertificateContext.restype = wintypes.BOOL
    lib.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]  # PCCERT_CONTEXT

    # CertDuplicateCertificateContext
    lib.CertDuplicateCertificateContext.restype = ctypes.c_void_p
    lib.CertDuplicateCertificateContext.argtypes = [ctypes.c_void_p]

    # CertGetCertificateContextProperty
    lib.CertGetCertificateContextProperty.restype = wintypes.BOOL
    lib.CertGetCertificateContextProperty.argtypes = [
        ctypes.c_void_p,               # pCertContext
        wintypes.DWORD,                # dwPropId
        ctypes.c_void_p,               # pvData (out, can be NULL for size query)
        ctypes.POINTER(wintypes.DWORD),# pcbData (in/out)
    ]

    # PFXImportCertStore – used in test setup to install generated soft certs
    lib.PFXImportCertStore.restype = wintypes.HANDLE
    lib.PFXImportCertStore.argtypes = [
        ctypes.POINTER(CRYPTOAPI_BLOB),  # pPFX
        ctypes.c_wchar_p,                # szPassword
        wintypes.DWORD,                  # dwFlags
    ]

    # CertAddCertificateContextToStore
    lib.CertAddCertificateContextToStore.restype = wintypes.BOOL
    lib.CertAddCertificateContextToStore.argtypes = [
        wintypes.HANDLE,          # hCertStore
        ctypes.c_void_p,          # pCertContext (PCCERT_CONTEXT)
        wintypes.DWORD,           # dwAddDisposition
        ctypes.POINTER(ctypes.c_void_p),  # ppStoreContext (out, optional)
    ]

    return lib
