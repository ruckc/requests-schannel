# requests-schannel

A `requests` transport adapter that uses **Windows SChannel** for TLS, providing:

- **Server certificate validation** using the Windows Certificate Store (including enterprise / domain CAs)
- **Client certificate authentication** using certificates from the Windows Certificate Store, including certificates stored on **smart cards and hardware tokens** — without ever exporting the private key
- Transparent integration with the `requests` API

## Requirements

- Python 3.12+
- Windows (SChannel is a Windows-only API)

## Installation

```bash
pip install requests-schannel
# or, with uv:
uv add requests-schannel
```

## Quick Start

```python
import requests
from requests_schannel import SchannelAdapter

session = requests.Session()

# Attach the adapter for all HTTPS traffic
adapter = SchannelAdapter()
session.mount("https://", adapter)

response = session.get("https://example.com/")
print(response.status_code)
```

## Client Certificate Authentication (mTLS)

Select a client certificate from the Windows **"MY"** (Personal) certificate store by its SHA-1 thumbprint:

```python
from requests_schannel import SchannelAdapter

adapter = SchannelAdapter(
    client_cert="AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
)
```

Or select by subject common name:

```python
adapter = SchannelAdapter(
    client_cert="subject:CN=John Smith",
)
```

The private key is **never exported**. All cryptographic operations (including the TLS handshake signature) are delegated to the Windows Cryptographic Service Provider (CSP) or Key Storage Provider (KSP) associated with the certificate. This is why smart cards and hardware tokens work transparently — the private key never leaves the device.

## Smart Card Support

Soft and hardware PKI certificates stored in the Windows certificate store are used identically. For a smart card certificate:

1. Insert the smart card (the Windows mini-driver / CSP is loaded automatically).
2. Open the Windows Certificate Manager (`certmgr.msc`) and locate your certificate in **Personal → Certificates**. Note the thumbprint.
3. Pass that thumbprint to `SchannelAdapter`.

When `requests` initiates the TLS handshake, SChannel calls into the smart card CSP to perform the required private key operation. If needed, Windows will prompt for the PIN automatically.

## Disabling Server Certificate Verification

```python
# Not recommended for production
adapter = SchannelAdapter(verify=False)
```

## Development

This project uses [uv](https://docs.astral.sh/uv/) for dependency management.

```bash
# Install dev dependencies
uv sync --extra dev

# Run tests
uv run pytest

# Run tests with coverage report
uv run pytest --cov=requests_schannel --cov-report=html
```

Tests that exercise SChannel are skipped automatically on non-Windows platforms.

## License

MIT
