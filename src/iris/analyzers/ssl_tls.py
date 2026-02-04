"""SSL/TLS certificate analysis for phishing detection."""

from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import tldextract

from iris.analyzers.base import BaseAnalyzer
from iris.models import AnalyzerResult, AnalyzerStatus, Finding


# Certificate issuers commonly used by free/automated CAs
FREE_CERT_ISSUERS = [
    "let's encrypt",
    "letsencrypt",
    "zerossl",
    "buypass",
    "ssl.com free",
]


class SSLTLSAnalyzer(BaseAnalyzer):
    """Analyze the SSL/TLS certificate for phishing indicators.

    Checks certificate issuer, age, subject/domain mismatch,
    and free cert usage on brand-impersonating domains.
    """

    name = "SSL/TLS Certificate"
    weight = 15.0

    def analyze(self, url: str, config: dict[str, Any], *, browser: Any = None) -> AnalyzerResult:
        """Retrieve and inspect the SSL certificate for the URL's host.

        Args:
            url: The URL to analyze.
            config: The loaded configuration dictionary.

        Returns:
            AnalyzerResult with SSL/TLS findings.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        port = parsed.port or 443

        if parsed.scheme == "http":
            return AnalyzerResult(
                analyzer_name=self.name,
                status=AnalyzerStatus.COMPLETED,
                score=20.0,
                max_weight=self.weight,
                findings=[
                    Finding(
                        description="Site uses HTTP (no TLS encryption)",
                        score_contribution=20.0,
                        severity="medium",
                    )
                ],
            )

        cert = self._get_certificate(hostname, port, config)
        if cert is None:
            return AnalyzerResult(
                analyzer_name=self.name,
                status=AnalyzerStatus.COMPLETED,
                score=25.0,
                max_weight=self.weight,
                findings=[
                    Finding(
                        description="Could not retrieve SSL certificate",
                        score_contribution=25.0,
                        severity="medium",
                    )
                ],
            )

        findings: list[Finding] = []

        checks = [
            self._check_cert_issuer(cert, hostname, config),
            self._check_cert_age(cert),
            self._check_subject_mismatch(cert, hostname),
            self._check_cert_expiry(cert),
        ]

        for result in checks:
            if result is not None:
                findings.append(result)

        score = min(100.0, sum(f.score_contribution for f in findings))

        return AnalyzerResult(
            analyzer_name=self.name,
            status=AnalyzerStatus.COMPLETED,
            score=score,
            max_weight=self.weight,
            findings=findings,
        )

    def _get_certificate(
        self, hostname: str, port: int, config: dict[str, Any]
    ) -> dict | None:
        """Retrieve the SSL certificate from the server.

        Args:
            hostname: The hostname to connect to.
            port: The port number.
            config: Configuration dictionary.

        Returns:
            Certificate info dict, or None if retrieval failed.
        """
        timeout = config.get("requests", {}).get("timeout", 10)

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.getpeercert(binary_form=False)
        except (ssl.SSLError, ssl.CertificateError):
            # Try without verification to still get cert info
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        return ssock.getpeercert(binary_form=False)
            except Exception:
                return None
        except Exception:
            return None

    def _check_cert_issuer(
        self, cert: dict, hostname: str, config: dict[str, Any]
    ) -> Finding | None:
        """Check if a free cert is being used on a brand-impersonating domain.

        Args:
            cert: The certificate info dictionary.
            hostname: The hostname being checked.
            config: Configuration with brand list.

        Returns:
            Finding if free cert + brand impersonation detected.
        """
        issuer_parts = cert.get("issuer", ())
        issuer_str = ""
        for part in issuer_parts:
            for key, value in part:
                if key == "organizationName":
                    issuer_str = value.lower()
                    break

        is_free_cert = any(free in issuer_str for free in FREE_CERT_ISSUERS)
        if not is_free_cert:
            return None

        # Check if domain looks like it's impersonating a brand
        extracted = tldextract.extract(hostname)
        domain = extracted.domain.lower()
        brands = config.get("brands", [])

        for brand_fqdn in brands:
            brand_name = tldextract.extract(brand_fqdn).domain.lower()
            if brand_name in domain and domain != brand_name:
                return Finding(
                    description=(
                        f"Free certificate (issued by '{issuer_str}') on domain "
                        f"that contains brand name '{brand_name}'"
                    ),
                    score_contribution=25.0,
                    severity="high",
                )

        return None

    def _check_cert_age(self, cert: dict) -> Finding | None:
        """Check if the certificate was issued very recently.

        Args:
            cert: The certificate info dictionary.

        Returns:
            Finding if cert was issued less than 7 days ago.
        """
        not_before = cert.get("notBefore")
        if not not_before:
            return None

        try:
            issued_date = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
            issued_date = issued_date.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - issued_date).days

            if age_days < 7:
                return Finding(
                    description=f"Certificate issued very recently ({age_days} days ago)",
                    score_contribution=15.0,
                    severity="medium",
                )
        except (ValueError, TypeError):
            pass

        return None

    def _check_subject_mismatch(self, cert: dict, hostname: str) -> Finding | None:
        """Check if the certificate subject doesn't match the hostname.

        Args:
            cert: The certificate info dictionary.
            hostname: The hostname to verify against.

        Returns:
            Finding if there's a subject/hostname mismatch.
        """
        try:
            ssl.match_hostname(cert, hostname)
        except ssl.CertificateError:
            return Finding(
                description=f"Certificate subject does not match hostname '{hostname}'",
                score_contribution=30.0,
                severity="high",
            )
        except (ValueError, AttributeError):
            pass

        return None

    def _check_cert_expiry(self, cert: dict) -> Finding | None:
        """Check if the certificate is expired.

        Args:
            cert: The certificate info dictionary.

        Returns:
            Finding if the cert is expired.
        """
        not_after = cert.get("notAfter")
        if not not_after:
            return None

        try:
            expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)

            if expiry_date < datetime.now(timezone.utc):
                return Finding(
                    description="SSL certificate is expired",
                    score_contribution=25.0,
                    severity="high",
                )
        except (ValueError, TypeError):
            pass

        return None
