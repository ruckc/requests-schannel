"""requests-schannel — Windows SChannel TLS for requests and websockets.

This package replaces OpenSSL with Windows SChannel for TLS connections,
enabling smartcard/PKI mutual authentication using the Windows certificate store.

Top-level convenience imports::

    from requests_schannel import SchannelAdapter, create_session
    from requests_schannel import SchannelContext
    from requests_schannel import SchannelSocket
    from requests_schannel import AsyncSchannelSocket
    from requests_schannel import schannel_connect
    from requests_schannel import TlsVersion, CertInfo, ConnectionInfo, StreamSizes
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__all__ = [
    "AsyncSchannelSocket",
    "CertInfo",
    "ConnectionInfo",
    "SchannelAdapter",
    "SchannelContext",
    "SchannelSocket",
    "StreamSizes",
    "TlsVersion",
    "create_session",
    "schannel_connect",
]

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "SchannelAdapter": (".adapters", "SchannelAdapter"),
    "create_session": (".adapters", "create_session"),
    "SchannelContext": (".context", "SchannelContext"),
    "SchannelSocket": (".socket", "SchannelSocket"),
    "AsyncSchannelSocket": (".async_socket", "AsyncSchannelSocket"),
    "schannel_connect": (".ws", "schannel_connect"),
    "TlsVersion": (".backend", "TlsVersion"),
    "CertInfo": (".backend", "CertInfo"),
    "ConnectionInfo": (".backend", "ConnectionInfo"),
    "StreamSizes": (".backend", "StreamSizes"),
}

if TYPE_CHECKING:
    from .adapters import SchannelAdapter, create_session
    from .async_socket import AsyncSchannelSocket
    from .backend import CertInfo, ConnectionInfo, StreamSizes, TlsVersion
    from .context import SchannelContext
    from .socket import SchannelSocket
    from .ws import schannel_connect


def __getattr__(name: str) -> Any:
    if name in _LAZY_IMPORTS:
        module_path, attr = _LAZY_IMPORTS[name]
        import importlib

        module = importlib.import_module(module_path, package=__name__)
        return getattr(module, attr)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

