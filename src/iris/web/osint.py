"""OSINT link generator for IRIS scan reports."""

from __future__ import annotations

import base64
from urllib.parse import quote


def generate_osint_links(
    url: str,
    domain: str,
    ip: str = "",
) -> list[dict[str, str]]:
    """Build clickable OSINT links for external threat-intel tools.

    Args:
        url: The full URL that was scanned.
        domain: The extracted domain (e.g. "example.com").
        ip: The resolved IP address, if available.

    Returns:
        A list of dicts with keys: name, url, icon_class, description.
    """
    # VirusTotal uses an unpadded base64url-encoded URL as its ID
    vt_url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    encoded_url = quote(url, safe="")

    links: list[dict[str, str]] = [
        {
            "name": "VirusTotal (URL)",
            "url": f"https://www.virustotal.com/gui/url/{vt_url_id}",
            "icon_class": "vt",
            "description": "Multi-engine URL scan results",
        },
        {
            "name": "VirusTotal (Domain)",
            "url": f"https://www.virustotal.com/gui/domain/{domain}",
            "icon_class": "vt",
            "description": "Domain reputation and history",
        },
        {
            "name": "Google Transparency",
            "url": f"https://transparencyreport.google.com/safe-browsing/search?url={encoded_url}",
            "icon_class": "google",
            "description": "Google Safe Browsing transparency report",
        },
        {
            "name": "who.is",
            "url": f"https://who.is/whois/{domain}",
            "icon_class": "whois",
            "description": "WHOIS registration lookup",
        },
        {
            "name": "URLScan.io",
            "url": f"https://urlscan.io/search/#{encoded_url}",
            "icon_class": "urlscan",
            "description": "Live site scan and analysis",
        },
    ]

    # IP-specific links — only included when an IP is available
    if ip:
        links.insert(
            2,
            {
                "name": "AbuseIPDB",
                "url": f"https://www.abuseipdb.com/check/{ip}",
                "icon_class": "abuseipdb",
                "description": "IP abuse confidence score",
            },
        )
        links.insert(
            3,
            {
                "name": "Shodan",
                "url": f"https://www.shodan.io/host/{ip}",
                "icon_class": "shodan",
                "description": "Host exposure and open ports",
            },
        )

    return links
