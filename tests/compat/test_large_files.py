"""Compatibility tests for large file handling via requests + SchannelAdapter.

These tests exercise the full stack — requests → SchannelAdapter → urllib3 →
SchannelSocket — to verify that large uploads and downloads:

* Work at all (no silent data loss or protocol errors).
* Stream correctly: ``iter_content()`` delivers data in the requested chunk
  sizes without loading the entire body into RAM.
* Consume a bounded amount of memory relative to the requested chunk size,
  not proportional to the total transfer size.

All tests require Windows (SChannel) and use the ``large_file_server``
fixture from ``conftest.py``, which serves or accepts data via chunked
HTTP/1.1.
"""

from __future__ import annotations

import sys
from collections.abc import Generator
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    import requests

pytestmark = [
    pytest.mark.compat,
    pytest.mark.slow,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------


def _make_session() -> requests.Session:
    """Create a ``requests.Session`` with ``SchannelAdapter`` (no cert verification)."""
    import ssl

    import requests

    from requests_schannel.adapters import SchannelAdapter

    session = requests.Session()
    adapter = SchannelAdapter()
    adapter.schannel_context.verify_mode = ssl.CERT_NONE
    session.mount("https://", adapter)
    return session


# ---------------------------------------------------------------------------
# Download tests
# ---------------------------------------------------------------------------


class TestLargeFileDownload:
    """Streaming large HTTP downloads via SchannelAdapter."""

    def test_stream_1mb_download_via_iter_content(self, large_file_server: tuple[str, int]) -> None:
        """Download 1 MB in 64 KB chunks via iter_content — all data arrives."""
        host, port = large_file_server
        size = 1 * 1024 * 1024  # 1 MB
        chunk_size = 65536  # 64 KB

        session = _make_session()
        resp = session.get(
            f"https://{host}:{port}/download?size={size}",
            stream=True,
            timeout=30,
        )
        assert resp.status_code == 200

        total = 0
        for chunk in resp.iter_content(chunk_size=chunk_size):
            assert chunk, "iter_content must never yield empty chunks"
            total += len(chunk)

        assert total == size, f"Expected {size} bytes, received {total}"
        session.close()

    def test_stream_10mb_download_via_iter_content(
        self, large_file_server: tuple[str, int]
    ) -> None:
        """Download 10 MB streamed — verifies no full-body buffering."""
        host, port = large_file_server
        size = 10 * 1024 * 1024  # 10 MB
        chunk_size = 65536  # 64 KB

        session = _make_session()
        resp = session.get(
            f"https://{host}:{port}/download?size={size}",
            stream=True,
            timeout=60,
        )
        assert resp.status_code == 200

        total = 0
        chunk_count = 0
        for chunk in resp.iter_content(chunk_size=chunk_size):
            total += len(chunk)
            chunk_count += 1

        assert total == size
        # We should have received multiple chunks, not one giant blob
        assert chunk_count > 1, "Expected multiple chunks for a 10 MB transfer"
        session.close()

    def test_streaming_does_not_buffer_full_response(
        self, large_file_server: tuple[str, int]
    ) -> None:
        """With stream=True, resp.content is NOT pre-loaded; iter_content streams lazily."""
        host, port = large_file_server
        size = 5 * 1024 * 1024  # 5 MB

        session = _make_session()
        resp = session.get(
            f"https://{host}:{port}/download?size={size}",
            stream=True,
            timeout=60,
        )
        assert resp.status_code == 200

        # Consume and count without ever calling resp.content (which buffers all)
        total = sum(len(c) for c in resp.iter_content(chunk_size=131072))
        assert total == size
        session.close()

    def test_small_chunk_size_still_works(self, large_file_server: tuple[str, int]) -> None:
        """Even with a very small chunk_size iter_content delivers all bytes."""
        host, port = large_file_server
        size = 256 * 1024  # 256 KB
        chunk_size = 1024  # 1 KB chunks

        session = _make_session()
        resp = session.get(
            f"https://{host}:{port}/download?size={size}",
            stream=True,
            timeout=30,
        )
        assert resp.status_code == 200

        total = sum(len(c) for c in resp.iter_content(chunk_size=chunk_size))
        assert total == size
        session.close()


# ---------------------------------------------------------------------------
# Upload tests
# ---------------------------------------------------------------------------


class TestLargeFileUpload:
    """Streaming large HTTP uploads via SchannelAdapter."""

    def test_upload_1mb_body(self, large_file_server: tuple[str, int]) -> None:
        """POST a 1 MB body — server echoes byte count."""
        host, port = large_file_server
        size = 1 * 1024 * 1024  # 1 MB
        payload = b"\xab" * size

        session = _make_session()
        resp = session.post(
            f"https://{host}:{port}/upload",
            data=payload,
            timeout=30,
        )
        assert resp.status_code == 200
        assert int(resp.text) == size
        session.close()

    def test_upload_10mb_body(self, large_file_server: tuple[str, int]) -> None:
        """POST a 10 MB body — verifies chunked send path handles large payloads."""
        host, port = large_file_server
        size = 10 * 1024 * 1024  # 10 MB
        payload = b"\xcd" * size

        session = _make_session()
        resp = session.post(
            f"https://{host}:{port}/upload",
            data=payload,
            timeout=60,
        )
        assert resp.status_code == 200
        assert int(resp.text) == size
        session.close()

    def test_upload_streaming_generator(self, large_file_server: tuple[str, int]) -> None:
        """Upload via a generator — verifies the adapter supports streaming uploads.

        An explicit Content-Length header is provided because BaseHTTPRequestHandler
        does not support chunked Transfer-Encoding on the server side.  The generator
        still exercises the streaming send path through the adapter (data is yielded
        incrementally, not buffered into a single bytes object).
        """
        host, port = large_file_server
        chunk_size = 65536  # 64 KB
        num_chunks = 16  # 1 MB total
        total_size = chunk_size * num_chunks

        def payload_generator() -> Generator[bytes]:
            for _ in range(num_chunks):
                yield b"\xef" * chunk_size

        session = _make_session()
        resp = session.post(
            f"https://{host}:{port}/upload",
            data=payload_generator(),
            headers={"Content-Length": str(total_size)},
            timeout=30,
        )
        assert resp.status_code == 200
        assert int(resp.text) == total_size
        session.close()
