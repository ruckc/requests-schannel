"""Exception hierarchy for requests-schannel."""

from __future__ import annotations

from . import _constants as c


class SchannelError(Exception):
    """Base exception for all SChannel errors."""


class HandshakeError(SchannelError):
    """TLS handshake failed."""


class CertificateError(SchannelError):
    """Certificate-related error."""


class CertificateNotFoundError(CertificateError):
    """Requested certificate was not found in the Windows certificate store."""


class CertificateExpiredError(CertificateError):
    """Server or client certificate has expired."""


class CertificateUntrustedError(CertificateError):
    """Certificate chain is not trusted (untrusted root)."""


class CertificateVerificationError(CertificateError):
    """Server certificate verification failed."""


class CredentialError(SchannelError):
    """Failed to acquire SSPI credentials."""


class DecryptionError(SchannelError):
    """Failed to decrypt incoming TLS data."""


class EncryptionError(SchannelError):
    """Failed to encrypt outgoing TLS data."""


class BackendError(SchannelError):
    """Backend (sspilib or ctypes) is unavailable or misconfigured."""


class ContextExpiredError(SchannelError):
    """The security context has expired (session timed out)."""


class RenegotiationError(SchannelError):
    """TLS renegotiation was requested but failed."""


# Map SSPI status codes to exception classes
_SSPI_ERROR_MAP: dict[int, type[SchannelError]] = {
    c.SEC_E_CERT_EXPIRED: CertificateExpiredError,
    c.SEC_E_UNTRUSTED_ROOT: CertificateUntrustedError,
    c.SEC_E_CERT_UNKNOWN: CertificateVerificationError,
    c.SEC_E_NO_CREDENTIALS: CredentialError,
    c.SEC_E_LOGON_DENIED: HandshakeError,
    c.SEC_E_INVALID_TOKEN: HandshakeError,
    c.SEC_E_ALGORITHM_MISMATCH: HandshakeError,
    c.SEC_E_TARGET_UNKNOWN: HandshakeError,
    c.SEC_E_WRONG_PRINCIPAL: CertificateVerificationError,
    c.CRYPT_E_REVOCATION_OFFLINE: CertificateVerificationError,
    c.SEC_E_INTERNAL_ERROR: SchannelError,
    c.SEC_E_INVALID_HANDLE: SchannelError,
    c.SEC_E_INSUFFICIENT_MEMORY: SchannelError,
}

# Friendly messages for common SSPI errors
_SSPI_ERROR_MESSAGES: dict[int, str] = {
    c.SEC_E_INVALID_HANDLE: "The security handle is invalid",
    c.SEC_E_INSUFFICIENT_MEMORY: "Insufficient memory to complete the operation",
    c.SEC_E_CERT_EXPIRED: "The certificate has expired",
    c.SEC_E_UNTRUSTED_ROOT: "The certificate chain is not trusted (untrusted root CA)",
    c.SEC_E_CERT_UNKNOWN: "The certificate is unknown or invalid",
    c.SEC_E_NO_CREDENTIALS: "No credentials are available (certificate not found or inaccessible)",
    c.SEC_E_LOGON_DENIED: "Logon denied — server rejected authentication",
    c.SEC_E_INVALID_TOKEN: "The TLS token is invalid (protocol mismatch or corrupt data)",
    c.SEC_E_ALGORITHM_MISMATCH: "No common TLS algorithm — cipher suite negotiation failed",
    c.SEC_E_TARGET_UNKNOWN: "The target server name is unknown",
    c.SEC_E_WRONG_PRINCIPAL: "The server certificate does not match the expected hostname",
    c.CRYPT_E_REVOCATION_OFFLINE: (
        "Certificate revocation check failed — the revocation server is offline"
    ),
    c.SEC_E_INTERNAL_ERROR: "An internal SChannel error occurred",
    c.SEC_E_INCOMPLETE_MESSAGE: "Incomplete TLS message — need more data from the network",
}


def sspi_error(status_code: int, context: str = "") -> SchannelError:
    """Create an appropriate exception from an SSPI status code."""
    exc_class = _SSPI_ERROR_MAP.get(status_code, SchannelError)
    message = _SSPI_ERROR_MESSAGES.get(status_code, f"SSPI error 0x{status_code:08X}")
    if context:
        message = f"{context}: {message}"
    return exc_class(message)
