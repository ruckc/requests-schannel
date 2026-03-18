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
