"""IRIS analyzers package."""

from iris.analyzers.download import DownloadAnalyzer
from iris.analyzers.http_response import HTTPResponseAnalyzer
from iris.analyzers.link_discovery import LinkDiscoveryAnalyzer
from iris.analyzers.page_content import PageContentAnalyzer
from iris.analyzers.ssl_tls import SSLTLSAnalyzer
from iris.analyzers.threat_feeds import ThreatFeedAnalyzer
from iris.analyzers.url_lexical import URLLexicalAnalyzer
from iris.analyzers.whois_dns import WhoisDNSAnalyzer

ALL_ANALYZERS = [
    URLLexicalAnalyzer,
    WhoisDNSAnalyzer,
    SSLTLSAnalyzer,
    HTTPResponseAnalyzer,
    PageContentAnalyzer,
    DownloadAnalyzer,
    ThreatFeedAnalyzer,
    LinkDiscoveryAnalyzer,
]

__all__ = ["ALL_ANALYZERS"]
