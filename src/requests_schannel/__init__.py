"""
requests-schannel – Windows SChannel transport adapter for requests.
"""
from .adapter import SchannelAdapter
from ._cert_store import CertContext, CertStore
from .exceptions import (
    CertNotFoundError,
    CertStoreError,
    SchannelCertValidationError,
    SchannelError,
    SchannelHandshakeError,
)

__all__ = [
    "SchannelAdapter",
    "CertContext",
    "CertStore",
    "SchannelError",
    "SchannelHandshakeError",
    "SchannelCertValidationError",
    "CertStoreError",
    "CertNotFoundError",
]
