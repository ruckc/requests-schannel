"""requests-schannel — Windows SChannel TLS for requests and websockets.

This package replaces OpenSSL with Windows SChannel for TLS connections,
enabling smartcard/PKI mutual authentication using the Windows certificate store.

Public API is available via submodules::

    from requests_schannel.backend import CertInfo, ConnectionInfo, StreamSizes, TlsVersion
    from requests_schannel.context import SchannelContext
    from requests_schannel.socket import SchannelSocket
    from requests_schannel.adapters import SchannelAdapter, create_session
    from requests_schannel.async_socket import AsyncSchannelSocket
    from requests_schannel.ws import schannel_connect
"""

