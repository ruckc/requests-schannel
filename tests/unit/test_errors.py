"""Tests for the exception hierarchy and SSPI error mapping."""

from __future__ import annotations

import pytest

from requests_schannel import _constants as c
from requests_schannel._errors import (
    _SSPI_ERROR_MAP,
    _SSPI_ERROR_MESSAGES,
    BackendError,
    CertificateError,
    CertificateExpiredError,
    CertificateNotFoundError,
    CertificateUntrustedError,
    CertificateVerificationError,
    ContextExpiredError,
    CredentialError,
    DecryptionError,
    EncryptionError,
    HandshakeError,
    RenegotiationError,
    SchannelError,
    sspi_error,
)


@pytest.mark.unit
class TestExceptionHierarchy:
    """Verify exception class hierarchy."""

    def test_base_exception(self) -> None:
        assert issubclass(SchannelError, Exception)

    def test_handshake_is_schannel_error(self) -> None:
        assert issubclass(HandshakeError, SchannelError)

    def test_certificate_errors(self) -> None:
        assert issubclass(CertificateError, SchannelError)
        assert issubclass(CertificateNotFoundError, CertificateError)
        assert issubclass(CertificateExpiredError, CertificateError)
        assert issubclass(CertificateUntrustedError, CertificateError)
        assert issubclass(CertificateVerificationError, CertificateError)

    def test_credential_error(self) -> None:
        assert issubclass(CredentialError, SchannelError)

    def test_encryption_errors(self) -> None:
        assert issubclass(DecryptionError, SchannelError)
        assert issubclass(EncryptionError, SchannelError)

    def test_backend_error(self) -> None:
        assert issubclass(BackendError, SchannelError)

    def test_context_expired(self) -> None:
        assert issubclass(ContextExpiredError, SchannelError)

    def test_renegotiation_error(self) -> None:
        assert issubclass(RenegotiationError, SchannelError)

    def test_all_catchable_by_base(self) -> None:
        """All custom exceptions should be catchable as SchannelError."""
        error_classes = [
            HandshakeError,
            CertificateNotFoundError,
            CertificateExpiredError,
            CertificateUntrustedError,
            CertificateVerificationError,
            CredentialError,
            DecryptionError,
            EncryptionError,
            BackendError,
            ContextExpiredError,
            RenegotiationError,
        ]
        for cls in error_classes:
            exc = cls("test")
            assert isinstance(exc, SchannelError)


@pytest.mark.unit
class TestSspiErrorMap:
    """Test SSPI status code → exception mapping."""

    def test_known_codes_mapped(self) -> None:
        assert c.SEC_E_CERT_EXPIRED in _SSPI_ERROR_MAP
        assert c.SEC_E_UNTRUSTED_ROOT in _SSPI_ERROR_MAP
        assert c.SEC_E_NO_CREDENTIALS in _SSPI_ERROR_MAP

    def test_cert_expired_maps_correctly(self) -> None:
        assert _SSPI_ERROR_MAP[c.SEC_E_CERT_EXPIRED] is CertificateExpiredError

    def test_untrusted_root_maps_correctly(self) -> None:
        assert _SSPI_ERROR_MAP[c.SEC_E_UNTRUSTED_ROOT] is CertificateUntrustedError

    def test_no_credentials_maps_correctly(self) -> None:
        assert _SSPI_ERROR_MAP[c.SEC_E_NO_CREDENTIALS] is CredentialError

    def test_invalid_token_maps_to_handshake(self) -> None:
        assert _SSPI_ERROR_MAP[c.SEC_E_INVALID_TOKEN] is HandshakeError

    def test_algorithm_mismatch_maps_to_handshake(self) -> None:
        assert _SSPI_ERROR_MAP[c.SEC_E_ALGORITHM_MISMATCH] is HandshakeError


@pytest.mark.unit
class TestSspiErrorMessages:
    """Test friendly error messages."""

    def test_known_codes_have_messages(self) -> None:
        for code in _SSPI_ERROR_MAP:
            assert code in _SSPI_ERROR_MESSAGES, f"Missing message for 0x{code:08X}"

    def test_messages_are_descriptive(self) -> None:
        for code, msg in _SSPI_ERROR_MESSAGES.items():
            assert len(msg) > 10, f"Message too short for 0x{code:08X}: {msg!r}"


@pytest.mark.unit
class TestSspiErrorFactory:
    """Test the sspi_error() factory function."""

    def test_known_code_returns_correct_type(self) -> None:
        exc = sspi_error(c.SEC_E_CERT_EXPIRED)
        assert isinstance(exc, CertificateExpiredError)

    def test_unknown_code_returns_base(self) -> None:
        exc = sspi_error(0xDEADBEEF)
        assert type(exc) is SchannelError
        assert "0xDEADBEEF" in str(exc)

    def test_context_included_in_message(self) -> None:
        exc = sspi_error(c.SEC_E_CERT_EXPIRED, context="during handshake")
        assert "during handshake" in str(exc)
        assert "expired" in str(exc).lower()

    def test_no_context(self) -> None:
        exc = sspi_error(c.SEC_E_UNTRUSTED_ROOT)
        assert "untrusted" in str(exc).lower()
