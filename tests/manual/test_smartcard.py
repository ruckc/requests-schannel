"""Manual smartcard tests — skipped unless --smartcard flag is passed."""

from __future__ import annotations

import sys

import pytest

pytestmark = [
    pytest.mark.smartcard,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


class TestSmartcardAuth:
    """Tests that require a physical smartcard.

    These are skipped by default. Run with:
        pytest tests/manual/ --smartcard -v
    """

    def test_smartcard_cert_visible(self) -> None:
        """Verify smartcard certificates appear in the Windows store."""
        from requests_schannel.backends import get_cert_store

        store = get_cert_store()
        handle = store.open("MY", machine=False)
        try:
            certs = store.enumerate(handle)
            # Should find at least one cert (from smartcard)
            assert len(certs) > 0, "No certificates found in MY store"
            # Print certs for manual verification
            for cert in certs:
                print(f"  Subject: {cert.subject}")
                print(f"  Thumbprint: {cert.thumbprint}")
                print(f"  Has Private Key: {cert.has_private_key}")
                print()
        finally:
            store.close(handle)

    def test_smartcard_auto_select(self) -> None:
        """Connect with auto-selected smartcard cert.

        This may trigger a Windows certificate selection dialog and PIN prompt.
        """
        import requests

        from requests_schannel.adapters import SchannelAdapter

        session = requests.Session()
        adapter = SchannelAdapter(auto_select_client_cert=True)
        session.mount("https://", adapter)

        # Replace with your test server URL
        # resp = session.get("https://your-mtls-server.example.com/")
        # assert resp.status_code == 200
        pytest.skip("Replace URL with your mTLS test server and uncomment")
