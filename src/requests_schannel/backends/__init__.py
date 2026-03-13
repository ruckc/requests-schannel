"""Backend auto-selection: prefer sspilib, fall back to ctypes."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from .._errors import BackendError

if TYPE_CHECKING:
    from ..backend import CertStore, SchannelBackend


def get_backend(name: str | None = None) -> SchannelBackend:
    """Get a SChannel backend instance.

    Args:
        name: Explicit backend name ("sspilib" or "ctypes"). If None, auto-selects:
              sspilib if available, otherwise ctypes.

    Raises:
        BackendError: If the requested backend is unavailable.
    """
    if sys.platform != "win32":
        raise BackendError("requests-schannel requires Windows (SChannel is a Windows API)")

    if name == "ctypes":
        return _get_ctypes_backend()
    elif name == "sspilib":
        return _get_sspilib_backend()
    elif name is not None:
        raise BackendError(f"Unknown backend: {name!r}. Use 'sspilib' or 'ctypes'.")

    # Auto-select: try sspilib first
    try:
        return _get_sspilib_backend()
    except BackendError:
        return _get_ctypes_backend()


def get_cert_store(name: str | None = None) -> CertStore:
    """Get a CertStore instance.

    Both backends use the same ctypes-based cert store implementation.
    """
    if sys.platform != "win32":
        raise BackendError("Certificate store access requires Windows")

    from .ctypes_backend import CtypesCertStore

    return CtypesCertStore()


def _get_sspilib_backend() -> SchannelBackend:
    try:
        from .sspilib_backend import SSPILibBackend

        return SSPILibBackend()
    except ImportError as e:
        raise BackendError(
            "sspilib backend unavailable. Install with: pip install requests-schannel[sspilib]"
        ) from e


def _get_ctypes_backend() -> SchannelBackend:
    try:
        from .ctypes_backend import CtypesBackend

        return CtypesBackend()
    except Exception as e:
        raise BackendError(f"ctypes backend unavailable: {e}") from e
