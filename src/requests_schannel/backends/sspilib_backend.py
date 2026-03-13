"""SChannel backend using sspilib for SSPI operations.

sspilib's high-level ClientSecurityContext.step() API does not include a
SECBUFFER_EMPTY in the input SecBufferDesc, so SSPI has no place to report
unconsumed (SECBUFFER_EXTRA) data during the TLS handshake.  Additionally,
sspilib.raw.SecBuffer caches Python objects and does not reflect in-place
modifications made by the native SSPI implementation.  This makes sspilib
unsuitable for SChannel's multi-record buffer management model.

Until sspilib gains SChannel-aware buffer handling, this backend delegates
all SSPI operations to CtypesBackend.  The sspilib package is still
imported so that ``get_backend("sspilib")`` raises a clear ImportError when
the package is absent.
"""

from __future__ import annotations

try:
    import sspilib  # noqa: F401  — validate availability
except ImportError as e:
    raise ImportError(
        "sspilib is required for the sspilib backend. "
        "Install with: pip install requests-schannel[sspilib]"
    ) from e

from .ctypes_backend import CtypesBackend


class SSPILibBackend(CtypesBackend):
    """SChannel backend that requires sspilib but delegates to ctypes.

    sspilib's buffer model does not support SChannel's SECBUFFER_EXTRA
    mechanism, so all SSPI operations are handled by the ctypes backend.
    """
