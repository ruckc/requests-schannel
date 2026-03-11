"""
Windows Certificate Store integration.

Certificates are located by thumbprint or subject without ever exporting the
private key.  The returned :class:`CertContext` wraps an opaque Windows
``PCCERT_CONTEXT`` handle that can be passed directly to SChannel so that all
private-key operations (including those delegated to a smart card CSP/KSP)
happen inside the Windows security subsystem.
"""
from __future__ import annotations

import ctypes
import sys
from typing import Iterator, Optional

from .exceptions import CertNotFoundError, CertStoreError

if sys.platform == "win32":  # pragma: no cover
    import ctypes.wintypes as wintypes

    from ._windows_types import (
        CERT_CLOSE_STORE_FORCE_FLAG,
        CERT_ENCODING_TYPE,
        CERT_FIND_ANY,
        CERT_FIND_SHA1_HASH,
        CERT_FIND_SUBJECT_STR_W,
        CERT_SHA1_HASH_PROP_ID,
        CERT_STORE_PROV_SYSTEM,
        CERT_SYSTEM_STORE_CURRENT_USER,
        CERT_SYSTEM_STORE_LOCAL_MACHINE,
        CRYPTOAPI_BLOB,
        _load_crypt32,
    )

    _crypt32 = _load_crypt32()


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def _parse_thumbprint(thumbprint: str) -> bytes:
    """Convert a colon- or space-separated hex thumbprint to raw bytes."""
    clean = thumbprint.replace(":", "").replace(" ", "").upper()
    if len(clean) != 40:
        raise ValueError(
            f"Invalid SHA-1 thumbprint '{thumbprint}': "
            "expected 40 hex digits (with or without ':' separators)"
        )
    return bytes.fromhex(clean)


# ---------------------------------------------------------------------------
# CertContext
# ---------------------------------------------------------------------------


class CertContext:
    """
    Thin wrapper around a Windows ``PCCERT_CONTEXT`` (an opaque pointer).

    The context is reference-counted by crypt32; :meth:`close` calls
    ``CertFreeCertificateContext``.  The raw pointer value is exposed via
    :attr:`handle` so it can be passed to SChannel without copying any key
    material.

    This class deliberately provides **no method to access or export the
    private key**.  All cryptographic operations must be performed by passing
    the handle to a Windows API (SChannel / CNG / CAPI) that contacts the
    appropriate CSP or KSP internally.
    """

    __slots__ = ("_handle", "_closed")

    def __init__(self, handle: int) -> None:
        if not handle:
            raise CertStoreError("NULL CERT_CONTEXT handle")
        self._handle: int = handle
        self._closed: bool = False

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def handle(self) -> int:
        """The raw ``PCCERT_CONTEXT`` pointer value."""
        if self._closed:
            raise CertStoreError("CertContext has been closed")
        return self._handle

    @property
    def thumbprint(self) -> bytes:
        """SHA-1 thumbprint (20 bytes) of the certificate."""
        if sys.platform != "win32":  # pragma: no cover
            raise NotImplementedError("Windows only")
        size = wintypes.DWORD(0)
        # First call: query the required buffer size
        ok = _crypt32.CertGetCertificateContextProperty(
            ctypes.c_void_p(self.handle),
            CERT_SHA1_HASH_PROP_ID,
            None,
            ctypes.byref(size),
        )
        if not ok:
            raise CertStoreError(
                "CertGetCertificateContextProperty (size query) failed",
                ctypes.GetLastError(),
            )
        buf = (ctypes.c_ubyte * size.value)()
        ok = _crypt32.CertGetCertificateContextProperty(
            ctypes.c_void_p(self.handle),
            CERT_SHA1_HASH_PROP_ID,
            buf,
            ctypes.byref(size),
        )
        if not ok:
            raise CertStoreError(
                "CertGetCertificateContextProperty failed",
                ctypes.GetLastError(),
            )
        return bytes(buf)

    @property
    def thumbprint_hex(self) -> str:
        """SHA-1 thumbprint as an upper-case colon-separated hex string."""
        return ":".join(f"{b:02X}" for b in self.thumbprint)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Release the underlying CERT_CONTEXT reference."""
        if not self._closed and self._handle:
            if sys.platform == "win32":  # pragma: no cover
                _crypt32.CertFreeCertificateContext(ctypes.c_void_p(self._handle))
            self._handle = 0
            self._closed = True

    def __enter__(self) -> "CertContext":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        try:
            tp = self.thumbprint_hex
        except Exception:
            tp = "<unknown>"
        return f"CertContext(thumbprint={tp!r})"


# ---------------------------------------------------------------------------
# CertStore
# ---------------------------------------------------------------------------


class CertStore:
    """
    Manages a reference to a Windows certificate store.

    Parameters
    ----------
    store_name:
        The name of the certificate store, e.g. ``"MY"`` (Personal),
        ``"ROOT"`` (Trusted Root CAs), ``"CA"`` (Intermediate CAs).
    location:
        ``"user"`` for ``CERT_SYSTEM_STORE_CURRENT_USER`` (the default) or
        ``"machine"`` for ``CERT_SYSTEM_STORE_LOCAL_MACHINE``.
    """

    def __init__(self, store_name: str = "MY", location: str = "user") -> None:
        if sys.platform != "win32":  # pragma: no cover
            raise NotImplementedError("CertStore is only available on Windows")
        self._store_name = store_name
        self._location = location
        self._handle: int = self._open()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _open(self) -> int:  # pragma: no cover
        flags = (
            CERT_SYSTEM_STORE_CURRENT_USER
            if self._location == "user"
            else CERT_SYSTEM_STORE_LOCAL_MACHINE
        )
        handle = _crypt32.CertOpenStore(
            ctypes.c_void_p(CERT_STORE_PROV_SYSTEM),
            0,
            None,
            flags,
            ctypes.c_wchar_p(self._store_name),
        )
        if not handle:
            raise CertStoreError(
                f"CertOpenStore('{self._store_name}') failed",
                ctypes.GetLastError(),
            )
        return handle

    # ------------------------------------------------------------------
    # Certificate lookup (no export)
    # ------------------------------------------------------------------

    def find_by_thumbprint(self, thumbprint: str | bytes) -> CertContext:
        """
        Find a certificate by its SHA-1 thumbprint.

        Parameters
        ----------
        thumbprint:
            Either raw bytes (20 bytes) or a hex string such as
            ``"AA:BB:CC:..."`` or ``"AABBCC..."``.

        Returns
        -------
        CertContext
            A wrapper around the Windows CERT_CONTEXT.  The private key is
            **never exported**.

        Raises
        ------
        CertNotFoundError
            If no matching certificate is found.
        """
        if sys.platform != "win32":  # pragma: no cover
            raise NotImplementedError("Windows only")

        raw: bytes = (
            _parse_thumbprint(thumbprint)
            if isinstance(thumbprint, str)
            else thumbprint
        )
        blob_data = (ctypes.c_ubyte * len(raw))(*raw)
        blob = CRYPTOAPI_BLOB()
        blob.cbData = len(raw)
        blob.pbData = blob_data

        ctx_ptr = _crypt32.CertFindCertificateInStore(
            ctypes.c_void_p(self._handle),
            CERT_ENCODING_TYPE,
            0,
            CERT_FIND_SHA1_HASH,
            ctypes.byref(blob),
            None,
        )
        if not ctx_ptr:
            tp_str = (
                thumbprint
                if isinstance(thumbprint, str)
                else thumbprint.hex().upper()
            )
            raise CertNotFoundError(
                f"Certificate with thumbprint {tp_str!r} not found in "
                f"'{self._store_name}' store"
            )
        return CertContext(ctx_ptr)

    def find_by_subject(self, subject: str) -> CertContext:
        """
        Find the first certificate whose Subject contains *subject* as a
        substring (case-insensitive, Windows API behaviour).

        Parameters
        ----------
        subject:
            Substring to search for, e.g. ``"CN=My Server"`` or just
            ``"My Server"``.

        Raises
        ------
        CertNotFoundError
            If no matching certificate is found.
        """
        if sys.platform != "win32":  # pragma: no cover
            raise NotImplementedError("Windows only")

        ctx_ptr = _crypt32.CertFindCertificateInStore(
            ctypes.c_void_p(self._handle),
            CERT_ENCODING_TYPE,
            0,
            CERT_FIND_SUBJECT_STR_W,
            ctypes.c_wchar_p(subject),
            None,
        )
        if not ctx_ptr:
            raise CertNotFoundError(
                f"Certificate with subject containing {subject!r} not found "
                f"in '{self._store_name}' store"
            )
        return CertContext(ctx_ptr)

    def iter_certs(self) -> Iterator[CertContext]:
        """Iterate over **all** certificates in the store."""
        if sys.platform != "win32":  # pragma: no cover
            raise NotImplementedError("Windows only")

        prev: Optional[int] = None
        while True:
            ctx_ptr = _crypt32.CertFindCertificateInStore(
                ctypes.c_void_p(self._handle),
                CERT_ENCODING_TYPE,
                0,
                CERT_FIND_ANY,
                None,
                ctypes.c_void_p(prev) if prev else None,
            )
            if not ctx_ptr:
                break
            # CertFindCertificateInStore with CERT_FIND_ANY consumes the
            # previous context; we must NOT free it separately.
            prev = ctx_ptr
            yield CertContext(
                _crypt32.CertDuplicateCertificateContext(ctypes.c_void_p(ctx_ptr))
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def handle(self) -> int:
        """The raw HCERTSTORE handle."""
        return self._handle

    def close(self) -> None:
        """Close the certificate store handle."""
        if self._handle:
            if sys.platform == "win32":  # pragma: no cover
                _crypt32.CertCloseStore(
                    ctypes.c_void_p(self._handle), CERT_CLOSE_STORE_FORCE_FLAG
                )
            self._handle = 0

    def __enter__(self) -> "CertStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return f"CertStore(store_name={self._store_name!r}, location={self._location!r})"
