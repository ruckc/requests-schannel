"""Shared fixtures for the requests-schannel test suite."""

from __future__ import annotations

import http.server
import ssl
import subprocess
import sys
import threading
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# --- Markers ---

def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests with mocks")
    config.addinivalue_line("markers", "integration: Integration tests requiring Windows + certs")
    config.addinivalue_line("markers", "compat: Compatibility tests with requests/websockets")
    config.addinivalue_line("markers", "network: Tests requiring internet access")
    config.addinivalue_line("markers", "smartcard: Manual smartcard tests (skipped by default)")
    config.addinivalue_line("markers", "slow: Longer-running tests")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Auto-skip smartcard tests unless --smartcard flag is passed."""
    if not config.getoption("--smartcard", default=False):
        skip_smartcard = pytest.mark.skip(reason="Smartcard tests require --smartcard flag")
        for item in items:
            if "smartcard" in item.keywords:
                item.add_marker(skip_smartcard)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--smartcard", action="store_true", default=False, help="Run smartcard tests")


# --- Skip helpers ---

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows only")


# --- Mock backend fixture ---

@pytest.fixture
def mock_backend() -> MagicMock:
    """A fully mocked SchannelBackend for unit tests."""
    from requests_schannel.backend import (
        ConnectionInfo,
        CredentialHandle,
        HandshakeResult,
        SchannelBackend,
        SecurityContext,
        StreamSizes,
    )

    backend = MagicMock(spec=SchannelBackend)
    backend.acquire_credentials.return_value = CredentialHandle(handle="mock_cred")
    backend.create_context.return_value = SecurityContext(handle="mock_ctx")
    backend.handshake_step.return_value = HandshakeResult(
        output_token=b"", complete=True, extra_data=b""
    )
    backend.get_stream_sizes.return_value = StreamSizes(
        header=5, trailer=36, max_message=16384, buffers=4, block_size=1
    )
    backend.encrypt.side_effect = lambda ctx, data: b"\x00" * 5 + data + b"\x00" * 36
    backend.decrypt.return_value = (b"decrypted", b"")
    backend.get_negotiated_protocol.return_value = None
    backend.get_connection_info.return_value = ConnectionInfo(
        protocol_version="TLSv1.2",
        cipher_algorithm=0x6610,
        cipher_strength=256,
        hash_algorithm=0x800C,
        hash_strength=256,
        exchange_algorithm=0xAE06,
        exchange_strength=256,
    )
    backend.get_peer_certificate.return_value = b"\x30\x82\x01\x00"  # fake DER
    backend.shutdown.return_value = b""
    return backend


@pytest.fixture
def mock_credential() -> Any:
    from requests_schannel.backend import CredentialHandle
    return CredentialHandle(handle="mock_cred")


# --- TLS Test Certificate Infrastructure ---

@dataclass
class TestCerts:
    """Holds paths and thumbprints for test certificates."""
    root_ca_thumbprint: str
    server_thumbprint: str
    client_thumbprint: str
    server_pfx_path: Path
    server_pfx_password: str
    temp_dir: Path


@pytest.fixture(scope="session")
def tls_certs(tmp_path_factory: pytest.TempPathFactory) -> Generator[TestCerts]:
    """Create a test PKI (Root CA → Server + Client certs) using PowerShell.

    Session-scoped: created once, cleaned up after all tests.
    Only runs on Windows.
    """
    if sys.platform != "win32":
        pytest.skip("Certificate generation requires Windows")

    temp_dir = tmp_path_factory.mktemp("certs")
    pfx_path = temp_dir / "server.pfx"
    pfx_password = "test-password"

    # PowerShell script to create test PKI
    ps_script = f"""
    $ErrorActionPreference = 'Stop'

    # Create Root CA
    $rootCA = New-SelfSignedCertificate `
        -Subject "CN=Test Root CA" `
        -KeyUsage CertSign, CRLSign `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -CertStoreLocation "Cert:\\CurrentUser\\My" `
        -NotAfter (Get-Date).AddYears(1) `
        -TextExtension @("2.5.29.19={{text}}cA=true")

    # Export Root CA to trusted store
    $rootCert = Export-Certificate -Cert $rootCA -FilePath "{temp_dir}\\rootca.cer"
    Import-Certificate -FilePath "{temp_dir}\\rootca.cer" -CertStoreLocation "Cert:\\CurrentUser\\Root"

    # Create Server cert signed by Root CA
    $serverCert = New-SelfSignedCertificate `
        -Subject "CN=localhost" `
        -DnsName "localhost" `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -CertStoreLocation "Cert:\\CurrentUser\\My" `
        -NotAfter (Get-Date).AddYears(1) `
        -Signer $rootCA `
        -TextExtension @("2.5.29.37={{text}}1.3.6.1.5.5.7.3.1")

    # Create Client cert signed by Root CA
    $clientCert = New-SelfSignedCertificate `
        -Subject "CN=Test Client" `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -CertStoreLocation "Cert:\\CurrentUser\\My" `
        -NotAfter (Get-Date).AddYears(1) `
        -Signer $rootCA `
        -TextExtension @("2.5.29.37={{text}}1.3.6.1.5.5.7.3.2")

    # Export server cert as PFX for Python ssl module
    $pfxPass = ConvertTo-SecureString -String "{pfx_password}" -Force -AsPlainText
    Export-PfxCertificate -Cert $serverCert -FilePath "{pfx_path}" -Password $pfxPass

    # Output thumbprints
    Write-Output "ROOT=$($rootCA.Thumbprint)"
    Write-Output "SERVER=$($serverCert.Thumbprint)"
    Write-Output "CLIENT=$($clientCert.Thumbprint)"
    """

    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        capture_output=True,
        text=True,
        timeout=60,
    )

    if result.returncode != 0:
        pytest.skip(f"Certificate creation failed: {result.stderr}")

    # Parse thumbprints from output
    thumbprints: dict[str, str] = {}
    for line in result.stdout.strip().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            thumbprints[key.strip()] = value.strip()

    certs = TestCerts(
        root_ca_thumbprint=thumbprints.get("ROOT", ""),
        server_thumbprint=thumbprints.get("SERVER", ""),
        client_thumbprint=thumbprints.get("CLIENT", ""),
        server_pfx_path=pfx_path,
        server_pfx_password=pfx_password,
        temp_dir=temp_dir,
    )

    yield certs

    # Cleanup: remove test certs from store
    cleanup_script = f"""
    $ErrorActionPreference = 'SilentlyContinue'
    Get-ChildItem "Cert:\\CurrentUser\\My" | Where-Object {{
        $_.Thumbprint -in @("{certs.root_ca_thumbprint}", "{certs.server_thumbprint}", "{certs.client_thumbprint}")
    }} | Remove-Item -Force
    Get-ChildItem "Cert:\\CurrentUser\\Root" | Where-Object {{
        $_.Thumbprint -eq "{certs.root_ca_thumbprint}"
    }} | Remove-Item -Force
    """
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", cleanup_script],
        capture_output=True,
        timeout=30,
    )


@pytest.fixture
def tls_test_server(tls_certs: TestCerts) -> Generator[tuple[str, int]]:
    """Start a local HTTPS server using the test PKI certs.

    Yields (host, port). Server runs in background thread and shuts down after test.
    """
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(
        certfile=str(tls_certs.server_pfx_path),
        password=tls_certs.server_pfx_password,
    )
    # Try loading as PKCS12 if cert_chain fails
    # ssl needs PEM, so we may need to convert — use the PFX directly via load_cert_chain
    # if it fails, skip the test
    try:
        ssl_ctx.load_cert_chain(
            certfile=str(tls_certs.server_pfx_path),
            password=tls_certs.server_pfx_password,
        )
    except ssl.SSLError:
        pytest.skip("Could not load server certificate")

    class SimpleHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            pass  # Suppress server logs during tests

    server = http.server.HTTPServer(("127.0.0.1", 0), SimpleHandler)
    server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
    host, port = server.server_address

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield str(host), port

    server.shutdown()


# --- Backend parametrize fixture ---

@pytest.fixture(params=["sspilib", "ctypes"])
def backend_name(request: pytest.FixtureRequest) -> str:
    """Parametrized backend name for running tests against both backends."""
    name: str = request.param
    if name == "sspilib":
        try:
            import sspilib  # noqa: F401
        except ImportError:
            pytest.skip("sspilib not installed")
    return name
