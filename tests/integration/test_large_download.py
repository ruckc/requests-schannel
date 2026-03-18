"""Performance comparison: default requests (OpenSSL) vs SchannelAdapter for large downloads."""

from __future__ import annotations

import logging
import sys
import time
from dataclasses import dataclass

import pytest
import requests

from requests_schannel.adapters import SchannelAdapter

pytestmark = [
    pytest.mark.integration,
    pytest.mark.large_download,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
]

logger = logging.getLogger(__name__)

# Remote URLs with approximate sizes — used for real-world download benchmarks.
DOWNLOAD_TARGETS = [
    pytest.param(
        "https://proof.ovh.net/files/100Mb.dat",
        100_000_000,
        id="100MB-ovh",
    ),
    # pytest.param(
    #     "https://proof.ovh.net/files/1Gb.dat",
    #     1_000_000_000,
    #     id="1GB-ovh",
    # ),
]

CHUNK_SIZE = 1024 * 1024  # 1 MiB


@dataclass
class DownloadResult:
    """Captures timing and throughput for a single download."""

    label: str
    url: str
    elapsed_s: float
    bytes_downloaded: int

    @property
    def throughput_mbps(self) -> float:
        if self.elapsed_s == 0:
            return 0.0
        return (self.bytes_downloaded * 8) / (self.elapsed_s * 1_000_000)


def _download_streamed(session: requests.Session, url: str, label: str) -> DownloadResult:
    """Stream-download *url* and return timing metrics."""
    total = 0
    start = time.perf_counter()
    with session.get(url, stream=True, timeout=120) as resp:
        resp.raise_for_status()
        for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
            total += len(chunk)
    elapsed = time.perf_counter() - start
    return DownloadResult(label=label, url=url, elapsed_s=elapsed, bytes_downloaded=total)


def _log_comparison(default_result: DownloadResult, schannel_result: DownloadResult) -> None:
    """Log a side-by-side comparison of the two results."""
    logger.info(
        "\n"
        "======== Download Performance Comparison ========\n"
        "URL          : %s\n"
        "-------------------------------------------------\n"
        "%-12s : %8.2f s  |  %10.2f Mbps  |  %d bytes\n"
        "%-12s : %8.2f s  |  %10.2f Mbps  |  %d bytes\n"
        "-------------------------------------------------\n"
        "Delta        : %+.2f s  (positive = schannel slower)\n"
        "Ratio        : %.2fx\n"
        "=================================================",
        default_result.url,
        default_result.label,
        default_result.elapsed_s,
        default_result.throughput_mbps,
        default_result.bytes_downloaded,
        schannel_result.label,
        schannel_result.elapsed_s,
        schannel_result.throughput_mbps,
        schannel_result.bytes_downloaded,
        schannel_result.elapsed_s - default_result.elapsed_s,
        schannel_result.elapsed_s / default_result.elapsed_s if default_result.elapsed_s else 0,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLargeDownloadPerformance:
    """Compare download throughput between default requests and SchannelAdapter."""

    @pytest.mark.timeout(300)
    @pytest.mark.parametrize("url, expected_min_bytes", DOWNLOAD_TARGETS)
    def test_download_default_requests(
        self, url: str, expected_min_bytes: int, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Baseline: download via default requests (OpenSSL/certifi)."""
        with caplog.at_level(logging.INFO, logger=__name__):
            session = requests.Session()
            result = _download_streamed(session, url, label="openssl")
            logger.info(
                "[openssl] %s — %.2f s, %.2f Mbps, %d bytes",
                url,
                result.elapsed_s,
                result.throughput_mbps,
                result.bytes_downloaded,
            )
            assert result.bytes_downloaded >= expected_min_bytes * 0.95

    @pytest.mark.timeout(300)
    @pytest.mark.parametrize("url, expected_min_bytes", DOWNLOAD_TARGETS)
    def test_download_schannel(
        self, url: str, expected_min_bytes: int, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Download via SchannelAdapter (Windows SChannel TLS)."""
        with caplog.at_level(logging.INFO, logger=__name__):
            session = requests.Session()
            session.mount("https://", SchannelAdapter())
            result = _download_streamed(session, url, label="schannel")
            logger.info(
                "[schannel] %s — %.2f s, %.2f Mbps, %d bytes",
                url,
                result.elapsed_s,
                result.throughput_mbps,
                result.bytes_downloaded,
            )
            assert result.bytes_downloaded >= expected_min_bytes * 0.95

    @pytest.mark.timeout(600)
    @pytest.mark.parametrize("url, expected_min_bytes", DOWNLOAD_TARGETS)
    def test_head_to_head(
        self, url: str, expected_min_bytes: int, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Back-to-back download with both adapters, logging the comparison."""
        with caplog.at_level(logging.INFO, logger=__name__):
            # --- default (OpenSSL) ---
            default_session = requests.Session()
            default_result = _download_streamed(default_session, url, label="openssl")

            # --- SChannel ---
            schannel_session = requests.Session()
            schannel_session.mount("https://", SchannelAdapter())
            schannel_result = _download_streamed(schannel_session, url, label="schannel")

            _log_comparison(default_result, schannel_result)

            # Sanity: both downloaded roughly the same amount
            assert abs(default_result.bytes_downloaded - schannel_result.bytes_downloaded) < 4096

    @pytest.mark.timeout(600)
    def test_head_to_head_multiple_runs(self, caplog: pytest.LogCaptureFixture) -> None:
        """Run 3 iterations of the 100 MB download and report averages."""
        url = "https://proof.ovh.net/files/100Mb.dat"
        iterations = 3

        default_times: list[float] = []
        schannel_times: list[float] = []

        with caplog.at_level(logging.INFO, logger=__name__):
            for i in range(iterations):
                logger.info("--- Iteration %d/%d ---", i + 1, iterations)

                default_session = requests.Session()
                dr = _download_streamed(default_session, url, label="openssl")
                default_times.append(dr.elapsed_s)

                schannel_session = requests.Session()
                schannel_session.mount("https://", SchannelAdapter())
                sr = _download_streamed(schannel_session, url, label="schannel")
                schannel_times.append(sr.elapsed_s)

                _log_comparison(dr, sr)

            avg_default = sum(default_times) / len(default_times)
            avg_schannel = sum(schannel_times) / len(schannel_times)
            logger.info(
                "\n"
                "======== Average over %d iterations ========\n"
                "openssl  avg : %.2f s\n"
                "schannel avg : %.2f s\n"
                "delta        : %+.2f s\n"
                "ratio        : %.2fx\n"
                "=============================================",
                iterations,
                avg_default,
                avg_schannel,
                avg_schannel - avg_default,
                avg_schannel / avg_default if avg_default else 0,
            )
