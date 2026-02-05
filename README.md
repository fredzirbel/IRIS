<div align="center">

# IRIS — Intelligent Risk Inspection System

**Containerized URL analysis platform for phishing detection and threat assessment.**

[![Docker Image](https://img.shields.io/badge/ghcr.io-fredzirbel%2Firis-blue?logo=docker)](https://ghcr.io/fredzirbel/iris)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

</div>

---

IRIS scans URLs across 8 security dimensions simultaneously — lexical analysis, SSL certificates, WHOIS records, HTTP headers, page content, link discovery, file downloads, and threat intelligence feeds — then produces a weighted risk score with an interactive results dashboard streamed in real time.

## Features

- **8 Security Analyzers** running concurrently across URL, network, and content layers
- **3-Tier Scoring** — Safe / Uncertain / Malicious with weighted confidence percentages
- **Real-time SSE Streaming** — results appear progressively as each analyzer completes
- **Bulk Scanning** — scan up to 50 URLs concurrently (3 parallel workers) with progress tracking
- **REST API** — synchronous and async JSON endpoints for SOAR playbook integration
- **Defanged IOC Display** — all URLs rendered as `hxxps://example[.]com` for safe sharing
- **Copy Report** — one-click clipboard export of full reports; per-field copy buttons for IOCs
- **Playwright-based Screenshot Capture** with URL banner overlay and redirect detection
- **Active Link Discovery** — clicks sign-in/login buttons to find hidden credential harvesters
- **File Download Analysis** — detects automatic downloads, computes SHA-256, queries VirusTotal
- **Threat Feed Integration** — VirusTotal, Google Safe Browsing, AbuseIPDB
- **OSINT Link Panel** — one-click links to VirusTotal (including redirect hops), URLScan.io, AbuseIPDB, and more
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

IRIS uses a **dual-signal scoring engine** that blends analyzer scores (45%) with threat feed results (55%) into a final 0–100 risk score. Each result includes a **confidence percentage** (50–99%) reflecting the strength and diversity of evidence.

| Score | Category | Meaning |
|-------|----------|---------|
| 0–25 | **Safe** | No significant indicators detected |
| 26–59 | **Uncertain** | Some anomalies — investigate further before taking action |
| 60–100 | **Malicious** | Strong phishing indicators or confirmed by threat intelligence |

Special categories exist for file download threats: **Malicious File Download** and **Suspicious File Download**.

Threat feed matches are weighted individually (VirusTotal 40%, Google Safe Browsing 35%, AbuseIPDB 25%) and blended with analyzer evidence. Multiple confirming feeds drive both the score and confidence higher.

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
- **Thread-local browser pool** — each of 3 scan worker threads maintains its own persistent Playwright/Chromium instance, enabling concurrent scans while avoiding greenlet conflicts
- **Screenshots** are captured immediately after page content analysis while the page is fresh

## OSINT Links

Each scan report includes one-click links to external tools for deeper investigation:

- **VirusTotal** — URL and domain reputation
- **VirusTotal (Redirect Hops)** — separate URL and domain lookups for each redirect in the chain
- **Google Transparency Report** — Safe Browsing status
- **URLScan.io** — live site scan
- **who.is** — WHOIS registration lookup
- **AbuseIPDB** — IP abuse history (when IP is resolved)

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
| `scoring.thresholds` | `safe`, `malicious` | Score boundaries for 3-tier risk categories |
| `scoring.blend` | `analyzer_weight`, `feed_weight` | Relative weight of analyzers vs. threat feeds (must sum to 1.0) |
| `scoring.feed_weights` | `VirusTotal`, `Google Safe Browsing`, `AbuseIPDB` | Per-feed weight distribution for blended scoring |
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

### Web UI

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Home page with URL input form |
| `GET` | `/bulk` | Bulk scan page (accepts `?id=` to restore a cached session) |
| `GET` | `/results/{scan_id}` | Full results page (static mode) |
| `GET` | `/results/{scan_id}?stream=1` | Results page with live SSE streaming |
| `GET` | `/stream/{scan_id}` | SSE event stream for real-time results |

### REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Start an async scan — returns `{"scan_id": "..."}` for SSE streaming |
| `POST` | `/api/scan/sync` | Run a synchronous scan — blocks and returns complete JSON results |
| `GET` | `/api/results/{scan_id}` | Retrieve completed scan results as JSON (includes defanged URLs) |
| `POST` | `/api/hash-lookup` | Manual SHA-256 hash lookup via VirusTotal |
| `POST` | `/api/bulk` | Create or update a bulk scan session |
| `GET` | `/api/bulk/{bulk_id}` | Retrieve a cached bulk scan session |

### SOAR Integration Example

```bash
# Synchronous scan — blocks until complete (set timeout ≥ 120s)
curl -X POST http://localhost:8000/api/scan/sync \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.xyz"}'

# Retrieve a previous scan
curl http://localhost:8000/api/results/abc123def456
```

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
