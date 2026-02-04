# IRIS — Intelligent Risk Inspection System

<div align="center">

![IRIS](PhishGuard.jpg)

**Containerized URL analysis platform for phishing detection and threat assessment.**

[![Docker Image](https://img.shields.io/badge/ghcr.io-fredzirbel%2Firis-blue?logo=docker)](https://ghcr.io/fredzirbel/iris)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

</div>

---

IRIS scans URLs across 8 security dimensions simultaneously — lexical analysis, SSL certificates, WHOIS records, HTTP headers, page content, link discovery, file downloads, and threat intelligence feeds — then produces a weighted risk score with an interactive results dashboard streamed in real time.

## Features

- **8 Security Analyzers** running concurrently across URL, network, and content layers
- **Real-time SSE Streaming** — results appear progressively as each analyzer completes
- **Playwright-based Screenshot Capture** with URL banner overlay and redirect detection
- **Active Link Discovery** — clicks sign-in/login buttons to find hidden credential harvesters
- **File Download Analysis** — detects automatic downloads, computes SHA-256, queries VirusTotal
- **Threat Feed Integration** — VirusTotal, Google Safe Browsing, AbuseIPDB
- **OSINT Link Panel** — one-click links to VirusTotal, URLScan.io, Shodan, AbuseIPDB, and more
- **Cloudflare Bypass** — navigates past Cloudflare phishing interstitials for analysis
- **DNS-over-HTTPS Fallback** — resolves domains blocked by ISP/router DNS filters
- **Dark-themed Web UI** with collapsible sections and mobile-responsive layout
- **CLI Mode** for scripted/automated scanning

## Quick Start

### Docker (Recommended)

Pull and run the pre-built image:

```bash
docker run -p 8000:8000 --shm-size=2g ghcr.io/fredzirbel/iris:latest
```

Open **http://localhost:8000** and paste a URL to scan.

### Docker Compose (with API Keys)

For full threat feed integration:

```bash
git clone https://github.com/fredzirbel/IRIS.git
cd IRIS
cp config/default.yaml config/local.yaml
```

Edit `config/local.yaml` with your API keys, then:

```bash
docker compose up --build
```

### Environment Variables

Alternatively, pass API keys as environment variables:

```bash
docker run -p 8000:8000 --shm-size=2g \
  -e VIRUSTOTAL_API_KEY=your_key \
  -e GOOGLE_SAFEBROWSING_API_KEY=your_key \
  -e ABUSEIPDB_API_KEY=your_key \
  ghcr.io/fredzirbel/iris:latest
```

## Analyzers

| Analyzer | Weight | What It Checks |
|----------|--------|----------------|
| **URL Lexical Analysis** | 20 | Domain age indicators, typosquatting (Levenshtein distance), suspicious TLDs, URL shorteners, excessive subdomains, IP-based URLs, homoglyph characters |
| **WHOIS/DNS Inspection** | 15 | Domain registration age, registrar reputation, missing WHOIS privacy, PTR records, nameserver anomalies |
| **SSL/TLS Certificate** | 15 | Certificate validity, issuer trust, self-signed detection, expiration, SAN mismatch |
| **HTTP Response Analysis** | 15 | Redirect chains, missing security headers (CSP, X-Frame-Options), suspicious status codes, cross-domain redirects |
| **Page Content Analysis** | 15 | Login form detection, brand impersonation keywords, hidden form fields, credential harvesting patterns |
| **Link Discovery** | 15 | Clicks auth-related buttons on the page, inspects destination for credential forms, cross-domain redirects, and brand spoofing |
| **Threat Feed Integration** | 20 | Queries VirusTotal, Google Safe Browsing, and AbuseIPDB for known malicious indicators |
| **Download Analysis** | 15 | Detects auto-downloads, flags suspicious file extensions, computes SHA-256, queries VirusTotal for file reputation |

## Scoring

IRIS produces a **0–100 risk score** using weighted aggregation across all analyzers. Scores map to risk categories:

| Score | Category | Meaning |
|-------|----------|---------|
| 0–15 | **Safe** | No significant indicators detected |
| 16–35 | **Suspicious** | Some anomalies — proceed with caution |
| 36–55 | **Likely Phishing** | Strong phishing indicators — do not enter credentials |
| 56–100 | **Confirmed Phishing** | Matched by threat intelligence feeds or overwhelming evidence |

Special categories exist for file download threats: **Malicious File Download** and **Suspicious File Download**.

When a threat feed returns a positive match, the score is boosted into the 60–95 range with per-feed bonuses, ensuring confirmed threats always display a high score.

## Architecture

```
                    ┌──────────────────────────────────────────┐
                    │              FastAPI Web UI               │
                    │         (SSE streaming results)           │
                    └──────────────┬───────────────────────────┘
                                   │
                    ┌──────────────▼───────────────────────────┐
                    │          Scanner Orchestrator             │
                    │    (ThreadPoolExecutor + Playwright)      │
                    └──────────────┬───────────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
     ┌────────▼────────┐ ┌────────▼────────┐ ┌────────▼────────┐
     │  Thread Pool    │ │  Playwright      │ │  Deferred       │
     │  (concurrent)   │ │  (sequential)    │ │  (post-browser) │
     ├─────────────────┤ ├─────────────────┤ ├─────────────────┤
     │ URL Lexical     │ │ Page Content    │ │ Download        │
     │ WHOIS/DNS       │ │ Link Discovery  │ │  Analysis       │
     │ SSL/TLS         │ │                 │ │                 │
     │ HTTP Response   │ │ Screenshot      │ │                 │
     │ Threat Feeds    │ │  Capture        │ │                 │
     └─────────────────┘ └─────────────────┘ └─────────────────┘
```

- **Thread pool analyzers** run concurrently (network I/O bound)
- **Playwright analyzers** run sequentially on a dedicated thread (browser-bound)
- **Deferred analyzers** get a browser fallback pass after the thread pool finishes
- The **browser is persistent** across scans — eliminating 2–5s of Chrome launch overhead
- **Screenshots** are captured immediately after page content analysis while the page is fresh

## OSINT Links

Each scan report includes one-click links to external tools for deeper investigation:

- **VirusTotal** — URL and domain reputation
- **Google Transparency Report** — Safe Browsing status
- **URLScan.io** — live site scan
- **who.is** — WHOIS registration lookup
- **AbuseIPDB** — IP abuse history (when IP is resolved)
- **Shodan** — host exposure and open ports (when IP is resolved)

## Configuration

The default configuration (`config/default.yaml`) works out of the box for basic scanning. For threat feed integration, create `config/local.yaml`:

```yaml
api_keys:
  virustotal: "your-api-key"
  google_safebrowsing: "your-api-key"
  abuseipdb: "your-api-key"
```

### Configuration Options

| Section | Key | Description |
|---------|-----|-------------|
| `api_keys` | `virustotal`, `google_safebrowsing`, `abuseipdb` | API keys for threat feed integration |
| `scoring.weights` | `url_lexical`, `whois_dns`, `ssl_tls`, etc. | Analyzer weight distribution (must sum to 100) |
| `scoring.thresholds` | `safe`, `suspicious`, `likely_phishing` | Score boundaries for risk categories |
| `brands` | List of FQDNs | Brand names to check for impersonation/typosquatting |
| `suspicious_tlds` | List of TLDs | TLDs commonly used in phishing (e.g., `.xyz`, `.top`) |
| `url_shorteners` | List of domains | Known URL shortener services |
| `abused_hosting_domains` | List of domains | CDN/hosting platforms commonly abused for payload delivery |
| `suspicious_extensions` | List of extensions | File extensions flagged as potentially malicious |

## CLI Usage

IRIS also supports command-line scanning:

```bash
# Basic scan
iris https://example.com

# Verbose output with all findings
iris -v https://suspicious-site.xyz

# Passive-only mode (no HTTP fetch or page rendering)
iris --no-active https://example.com

# Custom config file
iris -c config/local.yaml https://example.com
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Home page with URL input form |
| `POST` | `/api/scan` | Start a scan (JSON body: `{"url": "..."}`) — returns `{scan_id}` |
| `GET` | `/stream/{scan_id}` | SSE event stream for real-time results |
| `GET` | `/results/{scan_id}` | Full results page (static mode) |
| `GET` | `/results/{scan_id}?stream=1` | Results page with live SSE streaming |
| `POST` | `/api/hash-lookup` | Manual SHA-256 hash lookup via VirusTotal |

## Development

### Local Setup

```bash
git clone https://github.com/fredzirbel/IRIS.git
cd IRIS
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
playwright install chromium
```

### Running Tests

```bash
pytest
```

### Linting

```bash
ruff check src/
```

## Tech Stack

- **Backend:** Python 3.11, FastAPI, Uvicorn
- **Browser Automation:** Playwright (Chromium)
- **Frontend:** Jinja2 templates, vanilla JS, CSS (dark theme)
- **Streaming:** Server-Sent Events (SSE)
- **Container:** Docker, Docker Compose
- **CI/CD:** GitHub Actions (auto-publish to GHCR)

## License

MIT
