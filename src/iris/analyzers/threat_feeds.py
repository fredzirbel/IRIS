"""Threat feed orchestrator analyzer for IRIS."""

from __future__ import annotations

import concurrent.futures
import socket
from typing import Any
from urllib.parse import urlparse

import tldextract

from iris.analyzers.base import BaseAnalyzer
from iris.config import get_api_key
from iris.feeds.abuseipdb import AbuseIPDBFeed
from iris.feeds.google_safebrowsing import GoogleSafeBrowsingFeed
from iris.feeds.virustotal import VirusTotalFeed
from iris.models import AnalyzerResult, AnalyzerStatus, FeedResult, Finding


_FEED_DISPLAY_ORDER: dict[str, int] = {
    "VirusTotal": 1,
    "AbuseIPDB": 2,
    "Google Safe Browsing": 3,
}


class ThreatFeedAnalyzer(BaseAnalyzer):
    """Orchestrate all threat feed checks against a URL.

    Initializes each feed that has a valid API key (or doesn't need one),
    runs all checks concurrently, and aggregates results. Feed results are
    stored in `last_feed_results` for the scanner to extract.
    """

    name = "Threat Feed Integration"
    weight = 20.0

    def __init__(self) -> None:
        """Initialize the analyzer with an empty feed results list."""
        self.last_feed_results: list[FeedResult] = []

    def analyze(self, url: str, config: dict[str, Any], *, browser: Any = None) -> AnalyzerResult:
        """Run all configured threat feeds against the URL.

        Args:
            url: The URL to check.
            config: The loaded configuration dictionary.
            browser: Unused — accepted for interface compliance.

        Returns:
            AnalyzerResult summarizing threat feed findings.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else hostname
        timeout = config.get("requests", {}).get("timeout", 10)

        # Resolve IP
        ip = self._resolve_ip(hostname)

        # Build list of feeds with valid config
        feeds = self._build_feeds(config, timeout)

        if not feeds:
            self.last_feed_results = []
            return AnalyzerResult(
                analyzer_name=self.name,
                status=AnalyzerStatus.SKIPPED,
                score=0.0,
                max_weight=self.weight,
                error_message="No threat feeds configured (add API keys to config)",
            )

        # Run all feeds concurrently
        feed_results: list[FeedResult] = []
        findings: list[Finding] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(feeds)) as executor:
            future_to_feed = {
                executor.submit(self._check_feed, feed, url, domain, ip): feed
                for feed in feeds
            }
            for future in concurrent.futures.as_completed(future_to_feed):
                result, finding = future.result()
                feed_results.append(result)
                if finding is not None:
                    findings.append(finding)

        for fr in feed_results:
            fr.display_order = _FEED_DISPLAY_ORDER.get(fr.feed_name, 99)
        self.last_feed_results = feed_results

        matches = sum(1 for fr in feed_results if fr.matched)
        score = min(100.0, matches * 50.0) if matches > 0 else 0.0

        return AnalyzerResult(
            analyzer_name=self.name,
            status=AnalyzerStatus.COMPLETED,
            score=score,
            max_weight=self.weight,
            findings=findings,
        )

    def _check_feed(
        self, feed: Any, url: str, domain: str, ip: str | None
    ) -> tuple[FeedResult, Finding | None]:
        """Run a single feed check with error handling.

        Args:
            feed: The feed instance to check.
            url: The URL to check.
            domain: The extracted domain.
            ip: Resolved IP address, or None.

        Returns:
            Tuple of (FeedResult, Finding or None).
        """
        try:
            result = feed.check(url, domain, ip)
            if result.matched:
                finding = Finding(
                    description=f"{result.feed_name}: {result.details}",
                    score_contribution=50.0,
                    severity="critical",
                )
            else:
                finding = Finding(
                    description=f"{result.feed_name}: {result.details}",
                    score_contribution=0.0,
                    severity="info",
                )
            return result, finding
        except Exception as e:
            result = FeedResult(
                feed_name=feed.name,
                matched=False,
                details=f"Error: {e}",
            )
            return result, None

    def _resolve_ip(self, hostname: str) -> str | None:
        """Resolve hostname to IP address.

        Args:
            hostname: The hostname to resolve.

        Returns:
            IP address string, or None if resolution failed.
        """
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    def _build_feeds(self, config: dict[str, Any], timeout: int) -> list:
        """Build the list of feeds that have valid configuration.

        Args:
            config: The loaded configuration dictionary.
            timeout: Request timeout in seconds.

        Returns:
            List of initialized feed instances.
        """
        feeds = []

        vt_key = get_api_key(config, "virustotal")
        if vt_key:
            feeds.append(VirusTotalFeed(api_key=vt_key, timeout=timeout))

        gsb_key = get_api_key(config, "google_safebrowsing")
        if gsb_key:
            feeds.append(GoogleSafeBrowsingFeed(api_key=gsb_key, timeout=timeout))

        abuseipdb_key = get_api_key(config, "abuseipdb")
        if abuseipdb_key:
            feeds.append(AbuseIPDBFeed(api_key=abuseipdb_key, timeout=timeout))

        return feeds
