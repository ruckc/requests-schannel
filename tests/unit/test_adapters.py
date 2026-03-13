"""Tests for the requests HTTPAdapter integration."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

_BACKEND_PATCH = "requests_schannel.context.get_backend"


@pytest.mark.unit
class TestSchannelAdapter:
    """Test SchannelAdapter configuration and pool manager injection."""

    def test_adapter_creates_context(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.adapters import SchannelAdapter

            adapter = SchannelAdapter()
            assert adapter.schannel_context is not None

    def test_adapter_with_thumbprint(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.adapters import SchannelAdapter

            adapter = SchannelAdapter(client_cert_thumbprint="AABB")
            assert adapter.schannel_context.client_cert_thumbprint == "AABB"

    def test_adapter_with_subject(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.adapters import SchannelAdapter

            adapter = SchannelAdapter(client_cert_subject="CN=Test")
            assert adapter.schannel_context.client_cert_subject == "CN=Test"

    def test_adapter_with_auto_select(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.adapters import SchannelAdapter

            adapter = SchannelAdapter(auto_select_client_cert=True)
            assert adapter.schannel_context.auto_select_client_cert is True

    def test_adapter_with_custom_context(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.adapters import SchannelAdapter
            from requests_schannel.context import SchannelContext

            ctx = SchannelContext(backend=mock_get.return_value)
            adapter = SchannelAdapter(schannel_context=ctx)
            assert adapter.schannel_context is ctx

    def test_adapter_init_poolmanager_injects_context(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.adapters import SchannelAdapter

            adapter = SchannelAdapter()

            with patch.object(
                adapter.__class__.__bases__[0],  # HTTPAdapter
                "init_poolmanager",
            ) as mock_init:
                adapter.init_poolmanager(10, 10, False)
                call_kwargs = mock_init.call_args
                assert "ssl_context" in call_kwargs.kwargs
                assert call_kwargs.kwargs["ssl_context"] is adapter.schannel_context

    def test_adapter_with_alpn(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.adapters import SchannelAdapter

            adapter = SchannelAdapter(alpn_protocols=["h2", "http/1.1"])
            assert adapter.schannel_context._alpn_protocols == ["h2", "http/1.1"]


@pytest.mark.unit
class TestCreateSession:
    """Test the convenience create_session factory."""

    def test_creates_session_with_adapter(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.adapters import create_session

            session = create_session()
            # Session should have SchannelAdapter mounted on https://
            adapter = session.get_adapter("https://example.com")
            from requests_schannel.adapters import SchannelAdapter

            assert isinstance(adapter, SchannelAdapter)

    def test_creates_session_with_thumbprint(self) -> None:
        with patch(_BACKEND_PATCH) as mock_get:
            mock_get.return_value = MagicMock()
            from requests_schannel.adapters import create_session

            session = create_session(client_cert_thumbprint="AABB")
            adapter = session.get_adapter("https://example.com")
            from requests_schannel.adapters import SchannelAdapter

            assert isinstance(adapter, SchannelAdapter)
            assert adapter.schannel_context.client_cert_thumbprint == "AABB"
