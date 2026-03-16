# requests-schannel

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![OS: Windows](https://img.shields.io/badge/os-Windows-0078D6.svg)](https://www.microsoft.com/windows)

Windows SChannel TLS/mTLS provider for [requests](https://docs.python-requests.org/) and [websockets](https://websockets.readthedocs.io/) — smartcard and PKI authentication via native Windows APIs.

**requests-schannel** replaces OpenSSL with the built-in Windows SChannel SSPI provider, enabling:

- **Smartcard / PIV authentication** — use certificates on hardware tokens without exporting private keys
- **Windows certificate store integration** — select client certificates by thumbprint, subject, or let Windows auto-select
- **Native trust store** — server verification uses the Windows trust store (no CA bundle files)
- **TLS 1.2 / 1.3** with ALPN negotiation
- **Zero native dependencies** — pure-Python ctypes backend included; optional [sspilib](https://github.com/jborean93/sspilib) backend for enhanced performance

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [requests Integration](#requests-integration)
  - [WebSocket Integration](#websocket-integration)
  - [Low-Level Socket API](#low-level-socket-api)
  - [Async Socket API](#async-socket-api)
- [Client Certificate (mTLS)](#client-certificate-mtls)
- [Backends](#backends)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Error Handling](#error-handling)
- [Testing](#testing)
- [License](#license)

## Installation

```bash
pip install requests-schannel
```

With optional dependencies:

```bash
# requests integration
pip install requests-schannel[requests]

# websockets integration
pip install requests-schannel[websockets]

# sspilib backend (recommended for production)
pip install requests-schannel[sspilib]

# Everything
pip install requests-schannel[all]
```

> **Note:** This library requires **Windows** and **Python 3.12+**.

## Quick Start

```python
import requests
from requests_schannel import SchannelAdapter

session = requests.Session()
session.mount("https://", SchannelAdapter())

resp = session.get("https://example.com")
print(resp.status_code)
```

## Usage

### requests Integration

#### Drop-in Adapter

Mount `SchannelAdapter` onto a `requests.Session` to route all HTTPS traffic through SChannel:

```python
import requests
from requests_schannel import SchannelAdapter

session = requests.Session()
session.mount("https://", SchannelAdapter())

resp = session.get("https://www.howsmyssl.com/a/check")
print(resp.json()["tls_version"])
```

#### Convenience Session Factory

`create_session()` returns a pre-configured session with the adapter already mounted:

```python
from requests_schannel import create_session

session = create_session()
resp = session.get("https://example.com")
```

### WebSocket Integration

Connect to WebSocket servers over TLS using SChannel:

```python
import asyncio
from requests_schannel.ws import schannel_connect

async def main():
    async with schannel_connect("wss://echo.websocket.org") as ws:
        await ws.send("hello")
        response = await ws.recv()
        print(response)

asyncio.run(main())
```

### Low-Level Socket API

Use `SchannelContext` and `SchannelSocket` directly for custom TLS connections:

```python
import socket
from requests_schannel import SchannelContext

ctx = SchannelContext()
ctx.set_alpn_protocols(["http/1.1"])

raw_sock = socket.create_connection(("example.com", 443))
tls_sock = ctx.wrap_socket(raw_sock, server_hostname="example.com")

tls_sock.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
print(tls_sock.recv(4096))
tls_sock.close()
```

### Async Socket API

For asyncio applications that need TLS without requests or websockets:

```python
import asyncio
from requests_schannel import SchannelContext, AsyncSchannelSocket

async def main():
    ctx = SchannelContext()
    sock = await AsyncSchannelSocket.connect("example.com", 443, ctx)

    await sock.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    data = await sock.recv(4096)
    print(data)
    await sock.close()

asyncio.run(main())
```

## Client Certificate (mTLS)

Select a client certificate from the Windows certificate store for mutual TLS authentication.

### By Thumbprint

```python
from requests_schannel import SchannelAdapter, create_session

# Using the adapter directly
adapter = SchannelAdapter(client_cert_thumbprint="AB12CD34EF56...")
session = requests.Session()
session.mount("https://", adapter)

# Or using the convenience factory
session = create_session(client_cert_thumbprint="AB12CD34EF56...")
```

### By Subject Name

```python
session = create_session(client_cert_subject="CN=myuser")
```

### Auto-Select

Let Windows choose a suitable client certificate (may display a UI prompt):

```python
session = create_session(auto_select_client_cert=True)
```

### Custom Certificate Store

By default, certificates are loaded from the `"MY"` (Personal) store. Specify a different store:

```python
session = create_session(
    client_cert_thumbprint="AB12CD34EF56...",
    cert_store_name="MY",  # "MY", "Root", "CA", etc.
)
```

### WebSocket mTLS

```python
async with schannel_connect(
    "wss://secure.example.com/ws",
    client_cert_thumbprint="AB12CD34EF56...",
) as ws:
    await ws.send("authenticated!")
```

## Backends

requests-schannel provides two backends for interacting with the Windows SChannel API:

| Backend | Description | Install |
|---------|-------------|---------|
| **ctypes** | Pure-Python ctypes calls to `secur32.dll` / `crypt32.dll`. Zero dependencies. Ships with the package. | Built-in |
| **sspilib** | Uses the [sspilib](https://github.com/jborean93/sspilib) package for SSPI operations. Recommended for production. | `pip install requests-schannel[sspilib]` |

The backend is auto-selected (sspilib if available, otherwise ctypes). To force a specific backend:

```python
from requests_schannel import SchannelAdapter, SchannelContext

# Via adapter
adapter = SchannelAdapter(backend="ctypes")

# Via context
ctx = SchannelContext(backend="sspilib")
```

## API Reference

### `SchannelAdapter`

`requests.adapters.HTTPAdapter` subclass for SChannel TLS.

```python
SchannelAdapter(
    client_cert_thumbprint: str | None = None,
    client_cert_subject: str | None = None,
    auto_select_client_cert: bool = False,
    cert_store_name: str = "MY",
    alpn_protocols: list[str] | None = None,
    backend: str | None = None,
    schannel_context: SchannelContext | None = None,
    **kwargs,  # passed to HTTPAdapter
)
```

**Properties:**
- `schannel_context` — the underlying `SchannelContext` instance

### `create_session()`

Convenience factory that returns a `requests.Session` with `SchannelAdapter` mounted on `https://`.

```python
create_session(
    client_cert_thumbprint: str | None = None,
    client_cert_subject: str | None = None,
    auto_select_client_cert: bool = False,
    cert_store_name: str = "MY",
    alpn_protocols: list[str] | None = None,
    backend: str | None = None,
    **kwargs,
) -> requests.Session
```

### `SchannelContext`

`ssl.SSLContext`-compatible object backed by Windows SChannel. Thread-safe — the credential handle is shared; each `wrap_socket()` creates a new per-connection security context.

```python
SchannelContext(backend: str | SchannelBackend | None = None)
```

**Properties:**
- `client_cert_thumbprint` — SHA-1 thumbprint for mTLS client cert selection
- `client_cert_subject` — subject name substring for client cert selection
- `auto_select_client_cert` — let Windows auto-select a client cert
- `cert_store_name` — Windows certificate store name (default `"MY"`)
- `minimum_version` / `maximum_version` — `TlsVersion.TLSv1_2` or `TlsVersion.TLSv1_3`
- `verify_mode` — `ssl.CERT_REQUIRED` (default) or `ssl.CERT_NONE`
- `check_hostname` — enable/disable hostname verification

**Methods:**
- `set_alpn_protocols(protocols: list[str])` — set ALPN protocol list (e.g. `["h2", "http/1.1"]`)
- `wrap_socket(sock, server_hostname=..., do_handshake_on_connect=True) -> SchannelSocket`
- `load_cert_chain()`, `load_verify_locations()`, `set_ciphers()` — no-ops for `ssl.SSLContext` compatibility

### `SchannelSocket`

TLS-wrapped socket with an `ssl.SSLSocket`-compatible interface.

**Methods:**
- `do_handshake()` — perform the TLS handshake
- `send(data: bytes) -> int` / `write(data: bytes) -> int`
- `recv(bufsize: int) -> bytes` / `read(nbytes: int) -> bytes`
- `recv_into(buffer, nbytes) -> int`
- `getpeercert(binary_form=False)` — get peer certificate
- `selected_alpn_protocol() -> str | None`
- `version() -> str | None` — negotiated TLS version
- `close()` — send close_notify and close the connection
- `makefile(mode, buffering)` — create a file-like wrapper (for urllib3 compatibility)

### `AsyncSchannelSocket`

Async wrapper around `SchannelSocket` for asyncio.

```python
# Connect and handshake
sock = await AsyncSchannelSocket.connect(host, port, context)

# Wrap existing socket
sock = await AsyncSchannelSocket.wrap(raw_sock, context, server_hostname)

# I/O
await sock.send(data)
data = await sock.recv(4096)
await sock.close()
```

### `schannel_connect()`

Async context manager for WebSocket connections over SChannel TLS.

```python
async with schannel_connect(
    uri: str,
    *,
    context: SchannelContext | None = None,
    client_cert_thumbprint: str | None = None,
    client_cert_subject: str | None = None,
    auto_select_client_cert: bool = False,
    cert_store_name: str = "MY",
    backend: str | None = None,
    timeout: float | None = 30.0,
    additional_headers: dict[str, str] | None = None,
    **ws_kwargs,
) as ws:
    ...
```

### Data Classes

- **`TlsVersion`** — enum: `TLSv1_2`, `TLSv1_3`
- **`CertInfo`** — certificate metadata: `thumbprint`, `subject`, `issuer`, `friendly_name`, `not_before`, `not_after`, `has_private_key`, `serial_number`, `der_encoded`
- **`ConnectionInfo`** — TLS connection details: `protocol_version`, `cipher_algorithm`, `cipher_strength`, `hash_algorithm`, `hash_strength`, `exchange_algorithm`, `exchange_strength`
- **`StreamSizes`** — SChannel buffer sizes: `header`, `trailer`, `max_message`, `buffers`, `block_size`

## Configuration

### TLS Version

```python
from requests_schannel import SchannelContext, TlsVersion

ctx = SchannelContext()
ctx.minimum_version = TlsVersion.TLSv1_2  # default
ctx.maximum_version = TlsVersion.TLSv1_3  # default
```

### ALPN Protocols

```python
ctx = SchannelContext()
ctx.set_alpn_protocols(["h2", "http/1.1"])
```

### Disable Server Verification

> **Warning:** Only use this for testing/development.

```python
import ssl
ctx = SchannelContext()
ctx.verify_mode = ssl.CERT_NONE
ctx.check_hostname = False
```

## Error Handling

All exceptions inherit from `SchannelError`:

| Exception | Description |
|-----------|-------------|
| `SchannelError` | Base exception for all SChannel errors |
| `HandshakeError` | TLS handshake failed |
| `CertificateError` | Base for certificate-related errors |
| `CertificateNotFoundError` | Certificate not found in the Windows store |
| `CertificateExpiredError` | Certificate has expired |
| `CertificateUntrustedError` | Certificate chain is not trusted |
| `CertificateVerificationError` | Server certificate verification failed |
| `CredentialError` | Failed to acquire SSPI credentials |
| `DecryptionError` | Failed to decrypt incoming TLS data |
| `EncryptionError` | Failed to encrypt outgoing TLS data |
| `BackendError` | Backend (sspilib or ctypes) is unavailable |
| `ContextExpiredError` | Security context has expired |
| `RenegotiationError` | TLS renegotiation failed |

```python
from requests_schannel._errors import SchannelError, CertificateNotFoundError

try:
    session = create_session(client_cert_thumbprint="INVALID...")
    session.get("https://secure.example.com")
except CertificateNotFoundError:
    print("Certificate not found in store")
except SchannelError as e:
    print(f"SChannel error: {e}")
```

## Testing

```bash
# Install dev dependencies
pip install -e ".[test]"

# Run unit tests
pytest tests/unit/

# Run integration tests (requires Windows with network access)
pytest tests/integration/

# Run all tests with coverage
pytest --cov=requests_schannel --cov-report=term-missing
```

## License

[MIT](https://opensource.org/licenses/MIT)