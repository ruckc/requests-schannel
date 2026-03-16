"""requests integration — SchannelAdapter and convenience session factory."""

from __future__ import annotations

from typing import Any

from .context import SchannelContext

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError as exc:
    raise ImportError(
        "requests is required for SchannelAdapter. "
        "Install with: pip install requests-schannel[requests]"
    ) from exc


class SchannelAdapter(HTTPAdapter):
    """requests HTTPAdapter that uses Windows SChannel for TLS.

    Replaces OpenSSL with SChannel, enabling smartcard/PKI client
    authentication via the Windows certificate store.

    Usage::

        import requests
        from requests_schannel import SchannelAdapter

        session = requests.Session()
        adapter = SchannelAdapter(client_cert_thumbprint="AB12CD...")
        session.mount("https://", adapter)
        resp = session.get("https://example.com")
    """

    def __init__(
        self,
        client_cert_thumbprint: str | None = None,
        client_cert_subject: str | None = None,
        auto_select_client_cert: bool = False,
        cert_store_name: str = "MY",
        alpn_protocols: list[str] | None = None,
        backend: str | None = None,
        schannel_context: SchannelContext | None = None,
        **kwargs: Any,
    ) -> None:
        self._schannel_context = schannel_context or self._build_context(
            client_cert_thumbprint=client_cert_thumbprint,
            client_cert_subject=client_cert_subject,
            auto_select_client_cert=auto_select_client_cert,
            cert_store_name=cert_store_name,
            alpn_protocols=alpn_protocols,
            backend=backend,
        )
        super().__init__(**kwargs)

    @staticmethod
    def _build_context(
        client_cert_thumbprint: str | None,
        client_cert_subject: str | None,
        auto_select_client_cert: bool,
        cert_store_name: str,
        alpn_protocols: list[str] | None,
        backend: str | None,
    ) -> SchannelContext:
        ctx = SchannelContext(backend=backend)
        if client_cert_thumbprint:
            ctx.client_cert_thumbprint = client_cert_thumbprint
        if client_cert_subject:
            ctx.client_cert_subject = client_cert_subject
        ctx.auto_select_client_cert = auto_select_client_cert
        ctx.cert_store_name = cert_store_name
        if alpn_protocols:
            ctx.set_alpn_protocols(alpn_protocols)
        return ctx

    def send(  # type: ignore[override]
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: None | float | tuple[float, float] = None,
        verify: bool | str = True,
        cert: None | str | tuple[str, str] = None,
        proxies: Any = None,
    ) -> requests.Response:
        """Override to prevent requests/urllib3 from overriding SChannel's verify_mode.

        urllib3 unconditionally sets ``ssl_context.verify_mode`` based on the
        ``cert_reqs`` value derived from *verify*.  For SChannel the
        verification policy is already encoded in the credential / ISC flags,
        so we always pass ``verify=False`` to the base class to stop urllib3
        from clobbering our settings.
        """
        return super().send(
            request,
            stream=stream,
            timeout=timeout,
            verify=False,
            cert=cert,
            proxies=proxies,
        )

    def init_poolmanager(  # type: ignore[override]
        self,
        num_pools: int = 10,
        maxsize: int = 10,
        block: bool = False,
        **connection_pool_kw: Any,
    ) -> None:
        """Override to inject SchannelContext as the ssl_context."""
        connection_pool_kw["ssl_context"] = self._schannel_context
        super().init_poolmanager(num_pools, maxsize, block, **connection_pool_kw)  # type: ignore[no-untyped-call]

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        """Override to inject SchannelContext for HTTPS proxies."""
        proxy_kwargs["ssl_context"] = self._schannel_context
        return super().proxy_manager_for(proxy, **proxy_kwargs)  # type: ignore[no-untyped-call]

    @property
    def schannel_context(self) -> SchannelContext:
        """The underlying SchannelContext for this adapter."""
        return self._schannel_context


def create_session(
    client_cert_thumbprint: str | None = None,
    client_cert_subject: str | None = None,
    auto_select_client_cert: bool = False,
    cert_store_name: str = "MY",
    alpn_protocols: list[str] | None = None,
    backend: str | None = None,
    **kwargs: Any,
) -> requests.Session:
    """Create a pre-configured requests session using Windows SChannel.

    Convenience factory that creates a session with SchannelAdapter
    already mounted for all HTTPS URLs.

    Usage::

        from requests_schannel import create_session

        session = create_session(client_cert_thumbprint="AB12CD...")
        resp = session.get("https://example.com")
    """
    adapter = SchannelAdapter(
        client_cert_thumbprint=client_cert_thumbprint,
        client_cert_subject=client_cert_subject,
        auto_select_client_cert=auto_select_client_cert,
        cert_store_name=cert_store_name,
        alpn_protocols=alpn_protocols,
        backend=backend,
        **kwargs,
    )
    session = requests.Session()
    session.mount("https://", adapter)
    return session
