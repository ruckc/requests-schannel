"""Shared fixtures for the requests-schannel test suite."""

from __future__ import annotations

import datetime
import http.server
import ssl
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
    config.addinivalue_line("markers", "large_download: Large download perf tests (skipped by default)")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Auto-skip smartcard and large-download tests unless their flags are passed."""
    if not config.getoption("--smartcard", default=False):
        skip_smartcard = pytest.mark.skip(reason="Smartcard tests require --smartcard flag")
        for item in items:
            if "smartcard" in item.keywords:
                item.add_marker(skip_smartcard)
    if not config.getoption("--large-download", default=False):
        skip_dl = pytest.mark.skip(reason="Large download tests require --large-download flag")
        for item in items:
            if "large_download" in item.keywords:
                item.add_marker(skip_dl)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--smartcard", action="store_true", default=False, help="Run smartcard tests")
    parser.addoption("--large-download", action="store_true", default=False, help="Run large download perf tests")


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
    """Holds paths for test certificates (generated in-memory, no Windows store)."""

    server_cert_pem_path: Path
    server_key_pem_path: Path
    ca_cert_pem_path: Path
    client_pfx_path: Path
    client_thumbprint: str
    client_subject: str
    ca_der: bytes
    temp_dir: Path


@pytest.fixture(scope="session")
def tls_certs(tmp_path_factory: pytest.TempPathFactory) -> TestCerts:
    """Create a test PKI (Root CA → Server cert) using the cryptography library.

    Session-scoped: PEM files are written to a temp directory.
    No certificates are installed into the Windows certificate store.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID

    temp_dir = tmp_path_factory.mktemp("certs")

    # Generate Root CA key + cert
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # Generate Server key + cert signed by Root CA
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(__import__("ipaddress").IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Generate Client key + cert signed by Root CA
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_subject_name = "Test Client Cert"
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, client_subject_name)]))
        .issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Compute client cert SHA-1 thumbprint
    client_thumbprint = client_cert.fingerprint(hashes.SHA1()).hex().upper()

    # Export client cert as PKCS12 (PFX) for Windows store import
    client_pfx_path = temp_dir / "client.pfx"
    pfx_password = b"test"
    client_pfx_path.write_bytes(
        pkcs12.serialize_key_and_certificates(
            name=client_subject_name.encode(),
            key=client_key,
            cert=client_cert,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(pfx_password),
        )
    )

    # Write PEM files
    ca_cert_path = temp_dir / "ca_cert.pem"
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    cert_pem_path = temp_dir / "server_cert.pem"
    cert_pem_path.write_bytes(
        server_cert.public_bytes(serialization.Encoding.PEM)
        + ca_cert.public_bytes(serialization.Encoding.PEM)
    )

    key_pem_path = temp_dir / "server_key.pem"
    key_pem_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    return TestCerts(
        server_cert_pem_path=cert_pem_path,
        server_key_pem_path=key_pem_path,
        ca_cert_pem_path=ca_cert_path,
        client_pfx_path=client_pfx_path,
        client_thumbprint=client_thumbprint,
        client_subject=client_subject_name,
        ca_der=ca_cert.public_bytes(serialization.Encoding.DER),
        temp_dir=temp_dir,
    )


@pytest.fixture
def tls_test_server(tls_certs: TestCerts) -> Generator[tuple[str, int]]:
    """Start a local HTTPS server using the test PKI certs.

    Yields (host, port). Server runs in background thread and shuts down after test.
    The server advertises ALPN protocols so clients can negotiate.
    """
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ssl_ctx.load_cert_chain(
            certfile=str(tls_certs.server_cert_pem_path),
            keyfile=str(tls_certs.server_key_pem_path),
        )
    except ssl.SSLError:
        pytest.skip("Could not load server certificate PEM files")

    # Advertise ALPN protocols so ALPN negotiation tests work
    ssl_ctx.set_alpn_protocols(["h2", "http/1.1"])

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


# --- Windows certificate store fixtures ---


@dataclass
class InstalledTestCerts:
    """Info about certs installed into the Windows certificate store."""

    client_thumbprint: str
    client_subject: str


@pytest.fixture(scope="session")
def smartcard_certs(tls_certs: TestCerts) -> Generator[InstalledTestCerts]:
    """Install test client cert into CurrentUser\\MY store.

    Session-scoped: installs once, cleans up after all smartcard tests.
    Uses the library's own crypt32 instance (prototypes already configured)
    to import the PFX directly in-process.
    """
    import ctypes
    import ctypes.wintypes as wt
    import subprocess

    if sys.platform != "win32":
        pytest.skip("Windows only")

    # Import library module to ensure crypt32 prototypes are set
    from requests_schannel.backends.ctypes_backend import PVOID, _crypt32

    class CryptDataBlob(ctypes.Structure):  # noqa: N801 — matches Windows API name
        _fields_ = [("cbData", wt.DWORD), ("pbData", PVOID)]

    pfx_data = tls_certs.client_pfx_path.read_bytes()
    blob = CryptDataBlob()
    blob.cbData = len(pfx_data)
    buf = (ctypes.c_byte * len(pfx_data))(*pfx_data)
    blob.pbData = ctypes.cast(buf, PVOID)

    # Import PFX with CNG KSP preference
    PKCS12_ALLOW_OVERWRITE_KEY = 0x00004000
    PKCS12_PREFER_CNG_KSP = 0x00000100
    pfx_store = _crypt32.PFXImportCertStore(
        ctypes.byref(blob),
        "test",
        PKCS12_ALLOW_OVERWRITE_KEY | PKCS12_PREFER_CNG_KSP,
    )
    assert pfx_store, "PFXImportCertStore failed"

    # Open user MY store and copy cert
    my_store = _crypt32.CertOpenStore(PVOID(10), 0, None, 0x00010000, "MY")
    assert my_store, "CertOpenStore failed"

    pfx_cert = _crypt32.CertEnumCertificatesInStore(pfx_store, None)
    assert pfx_cert, "CertEnumCertificatesInStore failed"

    added = PVOID(None)
    ok = _crypt32.CertAddCertificateContextToStore(
        my_store,
        pfx_cert,
        3,
        ctypes.byref(added),
    )
    assert ok, "CertAddCertificateContextToStore failed"

    _crypt32.CertCloseStore(pfx_store, 0)
    _crypt32.CertCloseStore(my_store, 0)

    yield InstalledTestCerts(
        client_thumbprint=tls_certs.client_thumbprint,
        client_subject=tls_certs.client_subject,
    )

    # Cleanup: delete cert from MY store
    subprocess.run(
        ["certutil", "-delstore", "-user", "My", tls_certs.client_thumbprint],
        capture_output=True,
        text=True,
        timeout=30,
    )


# --- WebSocket echo server fixture ---


@pytest.fixture
def wss_echo_server(tls_certs: TestCerts) -> Generator[tuple[str, int]]:
    """Start a local WSS echo server using the test PKI certs.

    Yields (host, port). Server echoes back any message it receives.
    """
    try:
        import websockets.sync.server as ws_server
    except ImportError:
        pytest.skip("websockets not installed")

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ssl_ctx.load_cert_chain(
            certfile=str(tls_certs.server_cert_pem_path),
            keyfile=str(tls_certs.server_key_pem_path),
        )
    except ssl.SSLError:
        pytest.skip("Could not load server certificate PEM files")

    def echo_handler(websocket: Any) -> None:
        for message in websocket:
            websocket.send(message)

    server = ws_server.serve(
        echo_handler,
        "127.0.0.1",
        0,
        ssl=ssl_ctx,
    )
    server_obj = server.__enter__()
    host, port = server_obj.socket.getsockname()

    thread = threading.Thread(target=server_obj.serve_forever, daemon=True)
    thread.start()

    yield str(host), port

    server_obj.shutdown()


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
