"""Tests for the backend ABC contract."""

from __future__ import annotations

import pytest

from requests_schannel.backend import (
    CertInfo,
    CertStore,
    ConnectionInfo,
    CredentialConfig,
    CredentialHandle,
    HandshakeResult,
    SchannelBackend,
    SecurityContext,
    StreamSizes,
    TlsVersion,
)


@pytest.mark.unit
class TestSchannelBackendABC:
    """Verify abstract base class contract."""

    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError, match="abstract"):
            SchannelBackend()  # type: ignore[abstract]

    def test_subclass_must_implement_all_methods(self) -> None:
        """A minimal incomplete subclass should fail to instantiate."""

        class IncompleteBackend(SchannelBackend):
            pass

        with pytest.raises(TypeError, match="abstract"):
            IncompleteBackend()  # type: ignore[abstract]

    def test_complete_subclass_works(self) -> None:
        """A fully implemented subclass can be instantiated."""

        class MinimalBackend(SchannelBackend):
            def acquire_credentials(self, config):
                return CredentialHandle(handle=None)

            def create_context(self, credential, target_name, flags=0, alpn_protocols=None):
                return SecurityContext()

            def handshake_step(self, context, in_token=None):
                return HandshakeResult(output_token=b"", complete=True)

            def encrypt(self, context, plaintext):
                return plaintext

            def decrypt(self, context, ciphertext):
                return (ciphertext, b"")

            def shutdown(self, context):
                return b""

            def get_peer_certificate(self, context):
                return b""

            def get_connection_info(self, context):
                return ConnectionInfo("TLSv1.2", 0, 0, 0, 0, 0, 0)

            def get_stream_sizes(self, context):
                return StreamSizes(0, 0, 16384, 4, 1)

            def get_negotiated_protocol(self, context):
                return None

            def free_credentials(self, credential):
                pass

            def free_context(self, context):
                pass

        backend = MinimalBackend()
        assert isinstance(backend, SchannelBackend)


@pytest.mark.unit
class TestCertStoreABC:
    """Verify CertStore abstract base class."""

    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError, match="abstract"):
            CertStore()  # type: ignore[abstract]


@pytest.mark.unit
class TestCredentialHandle:
    """Test CredentialHandle data class."""

    def test_creation(self) -> None:
        handle = CredentialHandle(handle="test_handle", backend_data={"key": "value"})
        assert handle.raw == "test_handle"
        assert handle.backend_data == {"key": "value"}

    def test_default_backend_data(self) -> None:
        handle = CredentialHandle(handle="h")
        assert handle.backend_data is None


@pytest.mark.unit
class TestSecurityContext:
    """Test SecurityContext data class."""

    def test_creation(self) -> None:
        ctx = SecurityContext(handle="ctx_handle")
        assert ctx.raw == "ctx_handle"
        assert ctx.stream_sizes is None

    def test_mutable_handle(self) -> None:
        ctx = SecurityContext()
        ctx.raw = "new_handle"
        assert ctx.raw == "new_handle"

    def test_stream_sizes(self) -> None:
        ctx = SecurityContext()
        sizes = StreamSizes(header=5, trailer=36, max_message=16384, buffers=4, block_size=1)
        ctx.stream_sizes = sizes
        assert ctx.stream_sizes.header == 5
        assert ctx.stream_sizes.max_message == 16384


@pytest.mark.unit
class TestCredentialConfig:
    """Test CredentialConfig dataclass."""

    def test_defaults(self) -> None:
        config = CredentialConfig()
        assert config.manual_validation is False

    def test_manual_validation_clears_auto(self) -> None:
        from requests_schannel._constants import (
            SCH_CRED_AUTO_CRED_VALIDATION,
            SCH_CRED_MANUAL_CRED_VALIDATION,
        )

        config = CredentialConfig(manual_validation=True)
        assert config.flags & SCH_CRED_MANUAL_CRED_VALIDATION
        assert not (config.flags & SCH_CRED_AUTO_CRED_VALIDATION)


@pytest.mark.unit
class TestTlsVersion:
    """Test TLS version enum."""

    def test_values(self) -> None:
        assert TlsVersion.TLSv1_2 == 0x00000800
        assert TlsVersion.TLSv1_3 == 0x00002000

    def test_ordering(self) -> None:
        assert TlsVersion.TLSv1_2 < TlsVersion.TLSv1_3


@pytest.mark.unit
class TestDataClasses:
    """Test frozen dataclasses."""

    def test_cert_info(self) -> None:
        info = CertInfo(
            thumbprint="AABB",
            subject="CN=Test",
            issuer="CN=CA",
            friendly_name="Test Cert",
            not_before=0.0,
            not_after=1.0,
            has_private_key=True,
            serial_number="01",
            der_encoded=b"\x30",
        )
        assert info.thumbprint == "AABB"
        assert info.has_private_key is True

    def test_cert_info_frozen(self) -> None:
        info = CertInfo("A", "B", "C", "D", 0.0, 1.0, True, "01", b"")
        with pytest.raises(AttributeError):
            info.thumbprint = "changed"  # type: ignore[misc]

    def test_stream_sizes(self) -> None:
        sizes = StreamSizes(header=5, trailer=36, max_message=16384, buffers=4, block_size=1)
        assert sizes.header == 5
        assert sizes.max_message == 16384

    def test_connection_info(self) -> None:
        info = ConnectionInfo(
            protocol_version="TLSv1.3",
            cipher_algorithm=0x6610,
            cipher_strength=256,
            hash_algorithm=0x800C,
            hash_strength=256,
            exchange_algorithm=0xAE06,
            exchange_strength=256,
        )
        assert info.protocol_version == "TLSv1.3"
        assert info.cipher_strength == 256

    def test_handshake_result(self) -> None:
        r = HandshakeResult(output_token=b"token", complete=False, extra_data=b"extra")
        assert r.output_token == b"token"
        assert r.complete is False
        assert r.extra_data == b"extra"
