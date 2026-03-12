"""Custom exceptions for requests-schannel."""


class SchannelError(OSError):
    """Base exception for SChannel errors."""

    def __init__(self, message: str, error_code: int = 0) -> None:
        self.error_code = error_code
        super().__init__(message)

    def __str__(self) -> str:
        msg = super().__str__()
        if self.error_code:
            return f"{msg} (0x{self.error_code:08X})"
        return msg

    def __repr__(self) -> str:
        if self.error_code:
            return f"{type(self).__name__}({super().__str__()!r}, error_code=0x{self.error_code:08X})"
        return f"{type(self).__name__}({super().__str__()!r})"


class SchannelHandshakeError(SchannelError):
    """Raised when the TLS handshake fails."""


class SchannelCertValidationError(SchannelError):
    """Raised when server certificate validation fails."""


class CertStoreError(OSError):
    """Raised when a Windows certificate store operation fails."""

    def __init__(self, message: str, error_code: int = 0) -> None:
        self.error_code = error_code
        super().__init__(message)

    def __str__(self) -> str:
        msg = super().__str__()
        if self.error_code:
            return f"{msg} (Win32 error {self.error_code})"
        return msg


class CertNotFoundError(CertStoreError):
    """Raised when a requested certificate cannot be found in the store."""
