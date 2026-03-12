"""
requests transport adapter that uses Windows SChannel for TLS.

Usage
-----
.. code-block:: python

    import requests
    from requests_schannel import SchannelAdapter

    session = requests.Session()
    session.mount("https://", SchannelAdapter())
    resp = session.get("https://example.com/")

Client certificate (mTLS) – thumbprint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: python

    adapter = SchannelAdapter(
        client_cert="AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
    )

Client certificate (mTLS) – subject search
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: python

    adapter = SchannelAdapter(
        client_cert="subject:CN=My Client",
    )

The private key is **never exported**.  SChannel delegates all private-key
operations to the Windows CSP / KSP associated with the certificate, which
handles smart-card signing transparently inside the security subsystem.
"""
from __future__ import annotations

import socket
import sys
from typing import Any, Optional, Union
from urllib.parse import urlparse

import urllib3
import urllib3.connection
import urllib3.connectionpool
from requests.adapters import HTTPAdapter
from urllib3._collections import HTTPHeaderDict

from ._cert_store import CertContext, CertStore, _parse_thumbprint
from .exceptions import CertNotFoundError, SchannelError


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_client_cert(
    client_cert: Optional[Union[str, int]],
    cert_store: str,
) -> Optional[CertContext]:
    """
    Resolve *client_cert* to a :class:`CertContext`.

    *client_cert* may be:

    * ``None`` – no client certificate
    * A thumbprint string such as ``"AA:BB:..."`` or ``"AABBCC..."``
    * A subject search string prefixed with ``"subject:"``
    * An ``int`` that is already a ``PCCERT_CONTEXT`` handle

    Returns ``None`` if no client certificate was requested.
    """
    if client_cert is None:
        return None

    if isinstance(client_cert, int):
        # Caller owns the lifetime; wrap without taking an extra reference
        return CertContext(client_cert)

    assert isinstance(client_cert, str)

    with CertStore(store_name=cert_store, location="user") as store:
        if client_cert.startswith("subject:"):
            subject = client_cert[len("subject:"):]
            return store.find_by_subject(subject)

        # Treat as a thumbprint (hex, possibly colon-separated)
        return store.find_by_thumbprint(client_cert)


# ---------------------------------------------------------------------------
# urllib3 connection / pool subclasses
# ---------------------------------------------------------------------------


class _SchannelHTTPSConnection(urllib3.connection.HTTPSConnection):
    """
    urllib3 HTTPS connection that uses SChannel instead of OpenSSL/ssl.
    """

    def __init__(
        self,
        *args: Any,
        client_cert_context: Optional[CertContext] = None,
        schannel_verify: bool = True,
        ca_store_handle: Optional[int] = None,
        **kwargs: Any,
    ) -> None:
        # Strip ssl_context / cert_file / key_file so urllib3 doesn't try to
        # use OpenSSL for TLS.
        kwargs.pop("ssl_context", None)
        kwargs.pop("cert_file", None)
        kwargs.pop("key_file", None)
        super().__init__(*args, **kwargs)
        self._client_cert_context = client_cert_context
        self._schannel_verify = schannel_verify
        self._ca_store_handle = ca_store_handle

    def connect(self) -> None:  # pragma: no cover
        if sys.platform != "win32":
            raise SchannelError(
                "SchannelAdapter is only supported on Windows; "
                "use a standard requests adapter on other platforms."
            )

        from ._schannel import SchannelSocket

        # Create the raw TCP socket (respects proxy / source address settings)
        raw = self._new_conn()
        # self.timeout may be a urllib3 Timeout object rather than a plain float;
        # extract a numeric value or fall back to None (blocking).
        _sock_timeout: Optional[float] = None
        if isinstance(self.timeout, (int, float)):
            _sock_timeout = float(self.timeout)
        elif hasattr(self.timeout, "read_timeout"):
            rt = self.timeout.read_timeout  # type: ignore[union-attr]
            if isinstance(rt, (int, float)):
                _sock_timeout = float(rt)
        raw.settimeout(_sock_timeout)

        # Determine client cert handle (if any)
        cert_handle: Optional[int] = None
        if self._client_cert_context is not None:
            cert_handle = self._client_cert_context.handle

        self.sock = SchannelSocket(
            raw,
            server_name=self._tunnel_host or self.host,
            cert_context_handle=cert_handle,
            verify=self._schannel_verify,
            ca_store_handle=self._ca_store_handle,
            timeout=_sock_timeout,
        )
        self.is_verified = self._schannel_verify


class _SchannelHTTPSConnectionPool(urllib3.HTTPSConnectionPool):
    """HTTPSConnectionPool that instantiates :class:`_SchannelHTTPSConnection`."""

    ConnectionCls = _SchannelHTTPSConnection

    def __init__(
        self,
        *args: Any,
        client_cert_spec: Optional[Union[str, int]] = None,
        cert_store_name: str = "MY",
        schannel_verify: bool = True,
        ca_store_handle: Optional[int] = None,
        **kwargs: Any,
    ) -> None:
        # Remove SSL-related kwargs that urllib3 would forward to SSLContext
        for key in ("ssl_context", "ssl_version", "assert_hostname",
                    "assert_fingerprint"):
            kwargs.pop(key, None)
        super().__init__(*args, **kwargs)
        self._client_cert_spec = client_cert_spec
        self._cert_store_name = cert_store_name
        self._schannel_verify = schannel_verify
        self._ca_store_handle = ca_store_handle
        self._resolved_cert_context: Optional[CertContext] = None

    def _get_cert_context(self) -> Optional[CertContext]:
        """Resolve the cert spec to a CertContext lazily (at first connection)."""
        if self._resolved_cert_context is None and self._client_cert_spec is not None:
            self._resolved_cert_context = _resolve_client_cert(
                self._client_cert_spec, self._cert_store_name
            )
        return self._resolved_cert_context

    def _new_conn(self) -> _SchannelHTTPSConnection:  # pragma: no cover
        conn = _SchannelHTTPSConnection(
            host=getattr(self, "_proxy_host", None) or self.host,
            port=self.port,
            timeout=self.timeout.connect_timeout
            if hasattr(self.timeout, "connect_timeout")
            else self.timeout,
            client_cert_context=self._get_cert_context(),
            schannel_verify=self._schannel_verify,
            ca_store_handle=self._ca_store_handle,
        )
        return conn


class _SchannelPoolManager(urllib3.PoolManager):
    """PoolManager that creates :class:`_SchannelHTTPSConnectionPool` for HTTPS."""

    def __init__(
        self,
        *args: Any,
        client_cert_spec: Optional[Union[str, int]] = None,
        cert_store_name: str = "MY",
        schannel_verify: bool = True,
        ca_store_handle: Optional[int] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._client_cert_spec = client_cert_spec
        self._cert_store_name = cert_store_name
        self._schannel_verify = schannel_verify
        self._ca_store_handle = ca_store_handle
        self.pool_classes_by_scheme = {
            "http": urllib3.HTTPConnectionPool,
            "https": _SchannelHTTPSConnectionPool,
        }

    def _new_pool(
        self,
        scheme: str,
        host: str,
        port: int,
        request_context: Optional[dict] = None,
    ) -> urllib3.connectionpool.HTTPConnectionPool:
        if scheme == "https":
            ctx = dict(request_context or {})
            # Remove OpenSSL-specific keys so urllib3 doesn't complain,
            # and remove host/port since they are passed as positional args.
            for key in ("ssl_context", "ssl_version", "assert_hostname",
                        "assert_fingerprint", "cert_reqs", "host", "port"):
                ctx.pop(key, None)
            return _SchannelHTTPSConnectionPool(
                host,
                port,
                client_cert_spec=self._client_cert_spec,
                cert_store_name=self._cert_store_name,
                schannel_verify=self._schannel_verify,
                ca_store_handle=self._ca_store_handle,
                **ctx,
            )
        return super()._new_pool(scheme, host, port, request_context)


# ---------------------------------------------------------------------------
# Public adapter
# ---------------------------------------------------------------------------


class SchannelAdapter(HTTPAdapter):
    """
    A ``requests`` transport adapter that uses **Windows SChannel** for TLS.

    Parameters
    ----------
    client_cert:
        Identifies the client certificate to use for mutual TLS.  Accepted
        formats:

        * ``None`` (default) – no client certificate
        * ``"AABBCCDD..."`` – SHA-1 thumbprint (with or without ``:``)
        * ``"subject:CN=My Cert"`` – subject substring search
        * An ``int`` that is already a ``PCCERT_CONTEXT`` handle

        The private key is **never exported**; SChannel delegates all
        private-key operations to the Windows CSP / KSP (transparent for
        smart cards).
    cert_store:
        Name of the Windows certificate store to search when *client_cert*
        is a string.  Defaults to ``"MY"`` (Personal).
    verify:
        ``True`` (default) – validate the server certificate against the
        Windows trusted-root store.
        ``False`` – skip server certificate validation (not recommended for
        production).
    ca_store_handle:
        Optional Windows ``HCERTSTORE`` handle whose certificates are treated
        as the **exclusive** trusted roots for server certificate validation.
        When set, the system ROOT store is not consulted during chain building
        and no CTL auto-update network calls are made.  Intended for testing
        with a custom CA cert held in an in-memory store; leave ``None`` for
        normal production use (system ROOT store).
    """

    def __init__(
        self,
        client_cert: Optional[Union[str, int]] = None,
        cert_store: str = "MY",
        verify: bool = True,
        ca_store_handle: Optional[int] = None,
        **kwargs: Any,
    ) -> None:
        self._client_cert_spec = client_cert
        self._cert_store_name = cert_store
        self._schannel_verify = verify
        self._ca_store_handle = ca_store_handle
        self._client_cert_context: Optional[CertContext] = None

        super().__init__(**kwargs)

    # ------------------------------------------------------------------
    # Lazy certificate resolution (used by close() to free the context)
    # ------------------------------------------------------------------

    def _get_cert_context(self) -> Optional[CertContext]:
        """
        Resolve the client certificate specification to a :class:`CertContext`
        on first use.  We defer resolution so that the adapter can be
        constructed on any platform without touching the Windows certificate
        store.
        """
        if self._client_cert_context is None and self._client_cert_spec is not None:
            if sys.platform != "win32":  # pragma: no cover
                raise SchannelError(
                    "Client certificate resolution requires Windows"
                )
            self._client_cert_context = _resolve_client_cert(
                self._client_cert_spec, self._cert_store_name
            )
        return self._client_cert_context

    # ------------------------------------------------------------------
    # HTTPAdapter overrides
    # ------------------------------------------------------------------

    def init_poolmanager(
        self,
        num_pools: int,
        maxsize: int,
        block: bool = False,
        **connection_kw: Any,
    ) -> None:
        # Remove ssl_context so our pool manager isn't confused by it
        connection_kw.pop("ssl_context", None)
        self.poolmanager = _SchannelPoolManager(
            num_pools=num_pools,
            maxsize=maxsize,
            block=block,
            # Pass the raw spec; the pool resolves it lazily at first connect
            client_cert_spec=self._client_cert_spec,
            cert_store_name=self._cert_store_name,
            schannel_verify=self._schannel_verify,
            ca_store_handle=self._ca_store_handle,
            **connection_kw,
        )

    def send(self, request: Any, **kwargs: Any) -> Any:
        # requests passes verify= and cert= as kwargs; we handle them via our
        # own parameters so we suppress them here.
        kwargs.pop("cert", None)
        # Override verify with our setting if it was left at the default
        kwargs["verify"] = self._schannel_verify
        return super().send(request, **kwargs)

    def close(self) -> None:
        if self._client_cert_context is not None:
            self._client_cert_context.close()
            self._client_cert_context = None
        super().close()
