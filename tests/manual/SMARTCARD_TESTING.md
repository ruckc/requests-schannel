# Smartcard Testing Guide

These tests require physical smartcard hardware and cannot be automated in CI.

## Prerequisites

1. **PIV-compatible smartcard** (e.g., YubiKey with PIV, CAC card)
2. **Smartcard reader** (built-in or USB)
3. **Client certificate** provisioned on the smartcard
4. **Certificate registered** in the Windows certificate store (Windows should auto-detect it when the smartcard is inserted)

## Running Smartcard Tests

```powershell
# From the project root
uv run pytest tests/manual/ --smartcard -v
```

## Manual Test Steps

### 1. Verify Certificate Visibility

1. Insert your smartcard
2. Open `certmgr.msc` → Personal → Certificates
3. Verify your smartcard certificate appears
4. Note the **thumbprint** (double-click cert → Details → Thumbprint)

### 2. Test with Thumbprint

```python
from requests_schannel import create_session

session = create_session(client_cert_thumbprint="YOUR_THUMBPRINT_HERE")
resp = session.get("https://your-mtls-server.example.com/")
print(resp.status_code)
```

Expected: Windows should prompt for your smartcard PIN, then the request should succeed.

### 3. Test with Auto-Select

```python
from requests_schannel import create_session

session = create_session(auto_select_client_cert=True)
resp = session.get("https://your-mtls-server.example.com/")
print(resp.status_code)
```

Expected: Windows may show a certificate selection dialog, then prompt for PIN.

### 4. Test WebSocket with Smartcard

```python
import asyncio
from requests_schannel.ws import schannel_connect

async def main():
    async with schannel_connect(
        "wss://your-mtls-server.example.com/ws",
        client_cert_thumbprint="YOUR_THUMBPRINT_HERE",
    ) as ws:
        await ws.send("hello")
        response = await ws.recv()
        print(response)

asyncio.run(main())
```
