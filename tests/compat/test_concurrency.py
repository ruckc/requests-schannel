"""Concurrency tests: ThreadPoolExecutor and ProcessPoolExecutor with SchannelAdapter.

These tests verify that requests-schannel is safe to use in multi-threaded and
multi-process environments.  Each test uses a local HTTPS server (started by the
``tls_test_server`` fixture) so no network access is required.
"""

from __future__ import annotations

import concurrent.futures
import sys

import pytest

pytestmark = [
    pytest.mark.compat,
    pytest.mark.slow,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]

# ---------------------------------------------------------------------------
# Module-level helper — must be at module scope so it can be pickled by
# ProcessPoolExecutor (which uses multiprocessing.spawn on Windows).
# ---------------------------------------------------------------------------


def _make_https_request(url: str) -> int:
    """Create a fresh SchannelAdapter session, make a GET request, return status code.

    Defined at module level so it is picklable for use in worker processes.
    """
    import ssl

    import requests

    from requests_schannel.adapters import SchannelAdapter

    session = requests.Session()
    adapter = SchannelAdapter()
    adapter.schannel_context.verify_mode = ssl.CERT_NONE
    session.mount("https://", adapter)
    try:
        resp = session.get(url, timeout=10)
        return resp.status_code
    finally:
        session.close()


# ---------------------------------------------------------------------------
# ThreadPoolExecutor tests
# ---------------------------------------------------------------------------


class TestThreadPoolExecutor:
    """Verify concurrent usage of SchannelAdapter from multiple threads."""

    def test_concurrent_requests_separate_sessions(self, tls_test_server: tuple[str, int]) -> None:
        """Each thread creates its own session and makes an independent request."""
        _, port = tls_test_server
        url = f"https://localhost:{port}/"
        num_workers = 5

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(_make_https_request, url) for _ in range(num_workers)]
            results = [f.result(timeout=30) for f in concurrent.futures.as_completed(futures)]

        assert len(results) == num_workers
        assert all(status == 200 for status in results)

    def test_concurrent_requests_shared_session(self, tls_test_server: tuple[str, int]) -> None:
        """Multiple threads share a single session (exercises the connection pool)."""
        import ssl

        import requests

        from requests_schannel.adapters import SchannelAdapter

        _, port = tls_test_server
        url = f"https://localhost:{port}/"
        num_workers = 5

        session = requests.Session()
        adapter = SchannelAdapter()
        adapter.schannel_context.verify_mode = ssl.CERT_NONE
        session.mount("https://", adapter)

        def _request(_: int) -> int:
            return session.get(url, timeout=10).status_code

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
                futures = [executor.submit(_request, i) for i in range(num_workers)]
                results = [f.result(timeout=30) for f in concurrent.futures.as_completed(futures)]
        finally:
            session.close()

        assert len(results) == num_workers
        assert all(status == 200 for status in results)

    def test_concurrent_requests_many_threads(self, tls_test_server: tuple[str, int]) -> None:
        """Stress-test with a larger number of concurrent threads."""
        _, port = tls_test_server
        url = f"https://localhost:{port}/"
        num_workers = 20

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(_make_https_request, url) for _ in range(num_workers)]
            results = [f.result(timeout=30) for f in concurrent.futures.as_completed(futures)]

        assert len(results) == num_workers
        assert all(status == 200 for status in results)


# ---------------------------------------------------------------------------
# ProcessPoolExecutor tests
# ---------------------------------------------------------------------------


class TestProcessPoolExecutor:
    """Verify that SchannelAdapter works correctly in worker processes."""

    def test_concurrent_requests_separate_processes(self, tls_test_server: tuple[str, int]) -> None:
        """Each worker process creates its own session and makes a request."""
        _, port = tls_test_server
        url = f"https://localhost:{port}/"
        num_workers = 3

        with concurrent.futures.ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(_make_https_request, url) for _ in range(num_workers)]
            results = [f.result(timeout=60) for f in concurrent.futures.as_completed(futures)]

        assert len(results) == num_workers
        assert all(status == 200 for status in results)

    def test_sequential_requests_multiple_processes(self, tls_test_server: tuple[str, int]) -> None:
        """Reuse the same pool to send requests sequentially across reused workers."""
        _, port = tls_test_server
        url = f"https://localhost:{port}/"
        num_requests = 4

        with concurrent.futures.ProcessPoolExecutor(max_workers=2) as executor:
            # map() blocks until all results are ready
            statuses = list(executor.map(_make_https_request, [url] * num_requests, timeout=60))

        assert len(statuses) == num_requests
        assert all(status == 200 for status in statuses)
