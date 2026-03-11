"""
Shared pytest fixtures for requests-schannel tests.

Certificate generation strategy
--------------------------------
All test certificates are generated in memory using the ``cryptography``
library.  On Windows, the fixtures install them into a *temporary*
certificate store that is created fresh per test-session and cleaned up
automatically.  No private key material is ever written to disk.

Server fixture
--------------
A local TLS server thread is started using Python's standard ``ssl`` module
(OpenSSL-backed) for the *server* side.  Our SChannel adapter is used for
the *client* side – this tests the full mTLS round-trip while keeping the
test infrastructure simple and cross-platform (the server half runs
everywhere).
"""
from __future__ import annotations

import datetime
import ipaddress
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

import pytest

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.datetime.now(datetime.timezone.utc)
_ONE_YEAR = datetime.timedelta(days=365)

requires_cryptography = pytest.mark.skipif(
    not HAS_CRYPTOGRAPHY,
    reason="cryptography package not available",
)

requires_windows = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows SChannel tests only run on Windows",
)


def _make_key() -> "rsa.RSAPrivateKey":
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _base_name(cn: str) -> "x509.Name":
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


# ---------------------------------------------------------------------------
# Certificate fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def ca_cert_and_key():
    """Generate an in-memory CA certificate and RSA private key."""
    if not HAS_CRYPTOGRAPHY:
        pytest.skip("cryptography not available")
    key = _make_key()
    name = _base_name("Test CA")
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW)
        .not_valid_after(_NOW + _ONE_YEAR)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


@pytest.fixture(scope="session")
def server_cert_and_key(ca_cert_and_key):
    """Generate a server certificate signed by the test CA."""
    ca_cert, ca_key = ca_cert_and_key
    key = _make_key()
    name = _base_name("localhost")
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW)
        .not_valid_after(_NOW + _ONE_YEAR)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


@pytest.fixture(scope="session")
def client_cert_and_key(ca_cert_and_key):
    """Generate a client certificate signed by the test CA."""
    ca_cert, ca_key = ca_cert_and_key
    key = _make_key()
    name = _base_name("Test Client")
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW)
        .not_valid_after(_NOW + _ONE_YEAR)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


# ---------------------------------------------------------------------------
# PEM helpers (kept in-memory; never written to disk unless explicitly asked)
# ---------------------------------------------------------------------------


def cert_to_pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_to_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def cert_to_der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def make_pfx(cert, key, ca_cert=None) -> bytes:
    """Create a PKCS#12 blob from a cert and key (no password)."""
    from cryptography.hazmat.primitives.serialization import pkcs12

    cas = [ca_cert] if ca_cert else []
    return pkcs12.serialize_key_and_certificates(
        name=b"test",
        key=key,
        cert=cert,
        cas=cas,
        encryption_algorithm=serialization.NoEncryption(),
    )


# ---------------------------------------------------------------------------
# Windows certificate store fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def windows_client_cert_thumbprint(client_cert_and_key, ca_cert_and_key):
    """
    Install the test client certificate into the current-user MY store and
    return its SHA-1 thumbprint.  Cleans up after the test session.

    Skipped on non-Windows platforms.
    """
    if sys.platform != "win32":
        pytest.skip("Windows only")
    if not HAS_CRYPTOGRAPHY:
        pytest.skip("cryptography not available")

    import ctypes
    import ctypes.wintypes as wintypes

    from requests_schannel._windows_types import (
        CERT_STORE_ADD_REPLACE_EXISTING,
        CERT_SYSTEM_STORE_CURRENT_USER,
        CERT_STORE_PROV_SYSTEM,
        CRYPTOAPI_BLOB,
        _load_crypt32,
    )

    crypt32 = _load_crypt32()

    client_cert, client_key = client_cert_and_key
    ca_cert, _ = ca_cert_and_key

    # Build PKCS#12 blob for import (one-time setup; not an export)
    pfx_bytes = make_pfx(client_cert, client_key, ca_cert)

    blob_data = (ctypes.c_ubyte * len(pfx_bytes))(*pfx_bytes)
    blob = CRYPTOAPI_BLOB()
    blob.cbData = len(pfx_bytes)
    blob.pbData = blob_data

    # Import into a temporary in-memory store (no disk persistence)
    tmp_store = crypt32.PFXImportCertStore(
        ctypes.byref(blob),
        ctypes.c_wchar_p(""),  # empty password
        ctypes.c_ulong(0),
    )
    if not tmp_store:
        pytest.fail(f"PFXImportCertStore failed: {ctypes.GetLastError()}")

    # Open the current-user MY store
    my_store = crypt32.CertOpenStore(
        ctypes.c_void_p(CERT_STORE_PROV_SYSTEM),
        0,
        None,
        CERT_SYSTEM_STORE_CURRENT_USER,
        ctypes.c_wchar_p("MY"),
    )
    if not my_store:
        pytest.fail(f"CertOpenStore(MY) failed: {ctypes.GetLastError()}")

    # Find the cert in the temp store and copy it to MY
    ctx_ptr = crypt32.CertFindCertificateInStore(
        ctypes.c_void_p(tmp_store),
        0x00010001,  # X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
        0,
        0,  # CERT_FIND_ANY
        None,
        None,
    )
    if not ctx_ptr:
        pytest.fail("No certificate found in imported PFX store")

    added_ctx = ctypes.c_void_p(0)
    ok = crypt32.CertAddCertificateContextToStore(
        ctypes.c_void_p(my_store),
        ctypes.c_void_p(ctx_ptr),
        CERT_STORE_ADD_REPLACE_EXISTING,
        ctypes.byref(added_ctx),
    )
    if not ok:
        pytest.fail(f"CertAddCertificateContextToStore failed: {ctypes.GetLastError()}")

    # Compute thumbprint from the CertContext we just added
    from requests_schannel._cert_store import CertContext

    cert_ctx = CertContext(added_ctx.value)
    thumbprint = cert_ctx.thumbprint_hex

    yield thumbprint

    # ---- Cleanup -------------------------------------------------------
    cert_ctx.close()
    crypt32.CertCloseStore(ctypes.c_void_p(my_store), 0)
    crypt32.CertCloseStore(ctypes.c_void_p(tmp_store), 0)


# ---------------------------------------------------------------------------
# Local HTTPS / mTLS test server
# ---------------------------------------------------------------------------


class _SimpleHandler(BaseHTTPRequestHandler):
    """Minimal HTTP/1.1 handler that always returns 200 OK."""

    def do_GET(self) -> None:
        body = b"OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:  # silence output
        pass


class TLSServer(threading.Thread):
    """
    A minimal HTTPS server that runs in a background thread.

    Parameters
    ----------
    certfile / keyfile:
        PEM-encoded server certificate and private key (as *bytes*).
    cafile:
        PEM-encoded CA certificate used to verify client certificates
        (when *require_client_cert* is True).
    require_client_cert:
        Whether to request and verify a client certificate (mTLS).
    """

    def __init__(
        self,
        certfile: bytes,
        keyfile: bytes,
        cafile: Optional[bytes] = None,
        require_client_cert: bool = False,
    ) -> None:
        super().__init__(daemon=True)
        self._certfile = certfile
        self._keyfile = keyfile
        self._cafile = cafile
        self._require_client_cert = require_client_cert
        self._server: Optional[HTTPServer] = None
        self._port: int = 0
        self._ready = threading.Event()

    @property
    def port(self) -> int:
        return self._port

    def run(self) -> None:
        import tempfile
        import os

        # ssl.SSLContext needs file paths; write cert/key to a temp directory
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = os.path.join(tmpdir, "server.crt")
            key_path = os.path.join(tmpdir, "server.key")
            ca_path = os.path.join(tmpdir, "ca.crt") if self._cafile else None

            with open(cert_path, "wb") as f:
                f.write(self._certfile)
            with open(key_path, "wb") as f:
                f.write(self._keyfile)
            if ca_path and self._cafile:
                with open(ca_path, "wb") as f:
                    f.write(self._cafile)

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(cert_path, key_path)

            if self._require_client_cert and ca_path:
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.load_verify_locations(ca_path)

            httpd = HTTPServer(("127.0.0.1", 0), _SimpleHandler)
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
            self._server = httpd
            self._port = httpd.server_address[1]
            self._ready.set()
            httpd.serve_forever()

    def start_and_wait(self) -> "TLSServer":
        self.start()
        self._ready.wait(timeout=10)
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()


# ---------------------------------------------------------------------------
# Server fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def tls_server(server_cert_and_key, ca_cert_and_key):
    """
    A TLS server (no client cert requirement) whose certificate is signed by
    the test CA.
    """
    server_cert, server_key = server_cert_and_key
    server = TLSServer(
        certfile=cert_to_pem(server_cert),
        keyfile=key_to_pem(server_key),
    )
    server.start_and_wait()
    yield server
    server.stop()


@pytest.fixture(scope="session")
def mtls_server(server_cert_and_key, ca_cert_and_key):
    """
    A TLS server that requires a client certificate signed by the test CA
    (mutual TLS / mTLS).
    """
    server_cert, server_key = server_cert_and_key
    ca_cert, _ = ca_cert_and_key
    server = TLSServer(
        certfile=cert_to_pem(server_cert),
        keyfile=key_to_pem(server_key),
        cafile=cert_to_pem(ca_cert),
        require_client_cert=True,
    )
    server.start_and_wait()
    yield server
    server.stop()
