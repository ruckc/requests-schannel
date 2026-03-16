"""Tests for SChannel/SSPI constant values against Windows SDK headers."""

from __future__ import annotations

import pytest

from requests_schannel import _constants as c


@pytest.mark.unit
class TestSspiReturnCodes:
    """Verify SSPI return codes match Windows SDK values."""

    def test_sec_e_ok(self) -> None:
        assert c.SEC_E_OK == 0x00000000

    def test_sec_i_continue_needed(self) -> None:
        assert c.SEC_I_CONTINUE_NEEDED == 0x00090312

    def test_sec_i_complete_needed(self) -> None:
        assert c.SEC_I_COMPLETE_NEEDED == 0x00090313

    def test_sec_i_complete_and_continue(self) -> None:
        assert c.SEC_I_COMPLETE_AND_CONTINUE == 0x00090314

    def test_sec_e_incomplete_message(self) -> None:
        assert c.SEC_E_INCOMPLETE_MESSAGE == 0x80090318

    def test_sec_e_invalid_token(self) -> None:
        assert c.SEC_E_INVALID_TOKEN == 0x80090308

    def test_sec_e_cert_expired(self) -> None:
        assert c.SEC_E_CERT_EXPIRED == 0x80090328

    def test_sec_e_untrusted_root(self) -> None:
        assert c.SEC_E_UNTRUSTED_ROOT == 0x80090325

    def test_sec_e_algorithm_mismatch(self) -> None:
        assert c.SEC_E_ALGORITHM_MISMATCH == 0x80090331


@pytest.mark.unit
class TestSecBufferTypes:
    """Verify SecBuffer type constants."""

    def test_secbuffer_empty(self) -> None:
        assert c.SECBUFFER_EMPTY == 0

    def test_secbuffer_data(self) -> None:
        assert c.SECBUFFER_DATA == 1

    def test_secbuffer_token(self) -> None:
        assert c.SECBUFFER_TOKEN == 2

    def test_secbuffer_extra(self) -> None:
        assert c.SECBUFFER_EXTRA == 5

    def test_secbuffer_stream_header(self) -> None:
        assert c.SECBUFFER_STREAM_HEADER == 7

    def test_secbuffer_stream_trailer(self) -> None:
        assert c.SECBUFFER_STREAM_TRAILER == 6

    def test_secbuffer_application_protocols(self) -> None:
        assert c.SECBUFFER_APPLICATION_PROTOCOLS == 18


@pytest.mark.unit
class TestSchannelProtocols:
    """Verify SChannel protocol flags."""

    def test_tls12_client(self) -> None:
        assert c.SP_PROT_TLS1_2_CLIENT == 0x00000800

    def test_tls13_client(self) -> None:
        assert c.SP_PROT_TLS1_3_CLIENT == 0x00002000

    def test_default_includes_tls12(self) -> None:
        assert c.SP_PROT_TLS_CLIENT_DEFAULT & c.SP_PROT_TLS1_2_CLIENT

    def test_default_includes_tls13(self) -> None:
        assert c.SP_PROT_TLS_CLIENT_DEFAULT & c.SP_PROT_TLS1_3_CLIENT


@pytest.mark.unit
class TestSchannelCredFlags:
    """Verify SChannel credential flags."""

    def test_manual_cred_validation(self) -> None:
        assert c.SCH_CRED_MANUAL_CRED_VALIDATION == 0x00000008

    def test_auto_cred_validation(self) -> None:
        assert c.SCH_CRED_AUTO_CRED_VALIDATION == 0x00000020

    def test_revocation_check_chain(self) -> None:
        assert c.SCH_CRED_REVOCATION_CHECK_CHAIN == 0x00000200


@pytest.mark.unit
class TestIscReqFlags:
    """Verify ISC_REQ flag compositions."""

    def test_tls_client_includes_stream(self) -> None:
        assert c.ISC_REQ_TLS_CLIENT & c.ISC_REQ_STREAM

    def test_tls_client_includes_confidentiality(self) -> None:
        assert c.ISC_REQ_TLS_CLIENT & c.ISC_REQ_CONFIDENTIALITY

    def test_mtls_does_not_include_mutual_auth(self) -> None:
        """SChannel does not support ISC_REQ_MUTUAL_AUTH; mTLS flags must omit it."""
        assert not (c.ISC_REQ_TLS_CLIENT_MTLS & c.ISC_REQ_MUTUAL_AUTH)

    def test_mtls_includes_supplied_creds(self) -> None:
        assert c.ISC_REQ_TLS_CLIENT_MTLS & c.ISC_REQ_USE_SUPPLIED_CREDS


@pytest.mark.unit
class TestContextAttributes:
    """Verify context attribute constants."""

    def test_stream_sizes(self) -> None:
        assert c.SECPKG_ATTR_STREAM_SIZES == 4

    def test_remote_cert_context(self) -> None:
        assert c.SECPKG_ATTR_REMOTE_CERT_CONTEXT == 0x53

    def test_connection_info(self) -> None:
        assert c.SECPKG_ATTR_CONNECTION_INFO == 0x5A

    def test_application_protocol(self) -> None:
        assert c.SECPKG_ATTR_APPLICATION_PROTOCOL == 0x23


@pytest.mark.unit
class TestMiscConstants:
    """Verify miscellaneous constants."""

    def test_tls_max_record_size(self) -> None:
        assert c.TLS_MAX_RECORD_SIZE == 16384

    def test_cert_store_prov_system(self) -> None:
        assert c.CERT_STORE_PROV_SYSTEM == 10

    def test_encoding_default(self) -> None:
        assert c.ENCODING_DEFAULT == (c.X509_ASN_ENCODING | c.PKCS_7_ASN_ENCODING)
