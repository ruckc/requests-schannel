"""requests-schannel — Windows SChannel TLS for requests and websockets.

This package replaces OpenSSL with Windows SChannel for TLS connections,
enabling smartcard/PKI mutual authentication using the Windows certificate store.
"""

from __future__ import annotations

from .backend import CertInfo, ConnectionInfo, StreamSizes, TlsVersion
from .context import SchannelContext
from .socket import SchannelSocket

__all__ = [
    # Core
    "SchannelContext",
    "SchannelSocket",
    # Data classes
    "CertInfo",
    "ConnectionInfo",
    "StreamSizes",
    "TlsVersion",
    # Lazy imports below (adapters, async, ws)
]


def __getattr__(name: str) -> object:
    """Lazy-load optional integration modules to avoid import errors
    when requests or websockets are not installed."""
    if name == "SchannelAdapter":
        from .adapters import SchannelAdapter

        return SchannelAdapter

    if name == "create_session":
        from .adapters import create_session

        return create_session

    if name == "AsyncSchannelSocket":
        from .async_socket import AsyncSchannelSocket

        return AsyncSchannelSocket

    if name == "schannel_connect":
        from .ws import schannel_connect

        return schannel_connect

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
