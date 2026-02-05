"""Shared Playwright browser utilities for IRIS.

Provides a consistent browser launch configuration and Cloudflare phishing
interstitial bypass.  Used by the screenshot module, link discovery analyzer,
and any other component that needs to load pages in a real browser.

Key features:
- Uses system Chrome (``channel='chrome'``) for a legitimate TLS fingerprint.
- Runs headed but with the window off-screen so no GUI is visible.
- Disables Chrome's built-in Safe Browsing to avoid browser-level blocks.
- Detects and automatically bypasses Cloudflare "Suspected Phishing"
  interstitial pages by waiting for the Turnstile challenge to auto-solve,
  then submitting the bypass form.
- Falls back to DoH-based DNS when the system resolver blocks a domain.
"""

from __future__ import annotations

import logging

from playwright.sync_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
)
from playwright.sync_api import (
    TimeoutError as PlaywrightTimeout,
)

from iris.dns_util import build_chromium_args

logger = logging.getLogger(__name__)

# Realistic Chrome user-agent.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Anti-detection init script injected into every browser context.
# Overrides the most commonly-checked fingerprinting properties so that
# the Linux container looks like a normal Windows desktop browser.
_INIT_SCRIPT = """
    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
    Object.defineProperty(navigator, 'platform', {get: () => 'Win32'});
    Object.defineProperty(navigator, 'oscpu', {get: () => undefined});
    Object.defineProperty(navigator, 'plugins', {
        get: () => [1, 2, 3, 4, 5]
    });
    Object.defineProperty(navigator, 'languages', {
        get: () => ['en-US', 'en']
    });
    Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8});
    Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});

    // Override User-Agent Client Hints (used by modern fingerprinters)
    if (navigator.userAgentData) {
        Object.defineProperty(navigator, 'userAgentData', {
            get: () => ({
                brands: [
                    {brand: 'Chromium', version: '124'},
                    {brand: 'Google Chrome', version: '124'},
                    {brand: 'Not-A.Brand', version: '99'}
                ],
                mobile: false,
                platform: 'Windows',
                getHighEntropyValues: () => Promise.resolve({
                    architecture: 'x86',
                    bitness: '64',
                    model: '',
                    platform: 'Windows',
                    platformVersion: '15.0.0',
                    uaFullVersion: '124.0.0.0',
                    fullVersionList: [
                        {brand: 'Chromium', version: '124.0.0.0'},
                        {brand: 'Google Chrome', version: '124.0.0.0'}
                    ]
                })
            })
        });
    }

    window.chrome = {runtime: {}};
"""

# Maximum time (ms) to wait for Cloudflare Turnstile to auto-solve.
_TURNSTILE_TIMEOUT_MS = 15000
_TURNSTILE_POLL_MS = 500


def launch_browser(pw: Playwright, url: str) -> Browser:
    """Launch a browser configured for phishing analysis.

    Uses the system-installed Chrome (headed, off-screen) to get a real
    TLS fingerprint that passes Cloudflare Turnstile.  Falls back to
    bundled Chromium in headless mode if system Chrome is unavailable.

    Args:
        pw: An active Playwright instance from ``sync_playwright()``.
        url: The URL that will be navigated to (used to build DNS args).

    Returns:
        A launched Browser instance.
    """
    base_args = build_chromium_args(url)
    base_args.extend([
        "--disable-features=SafeBrowsing,DnsOverHttps",
        "--disable-client-side-phishing-detection",
        "--safebrowsing-disable-download-protection",
    ])

    # Try system Chrome first (headed, off-screen)
    try:
        browser = pw.chromium.launch(
            headless=False,
            channel="chrome",
            args=base_args + ["--window-position=-9999,-9999"],
        )
        logger.debug("Launched system Chrome (headed, off-screen)")
        return browser
    except Exception as exc:
        logger.debug("System Chrome not available: %s", exc)

    # Fallback: bundled Chromium headless
    browser = pw.chromium.launch(
        headless=True,
        args=base_args,
    )
    logger.debug("Launched bundled Chromium (headless)")
    return browser


def create_context(browser: Browser) -> BrowserContext:
    """Create a browser context with anti-fingerprinting protections.

    Args:
        browser: A launched Browser instance.

    Returns:
        A configured BrowserContext.
    """
    context = browser.new_context(
        viewport={"width": 1280, "height": 720},
        ignore_https_errors=True,
        user_agent=USER_AGENT,
        locale="en-US",
        timezone_id="America/New_York",
    )
    context.add_init_script(_INIT_SCRIPT)
    return context


def navigate_with_bypass(
    page: Page,
    url: str,
    timeout_ms: int = 15000,
) -> int:
    """Navigate to a URL, automatically bypassing Cloudflare phishing blocks.

    If the page is a Cloudflare "Suspected Phishing" interstitial, waits
    for the Turnstile challenge to auto-solve, then submits the bypass
    form and waits for the real page to load.

    Args:
        page: A Playwright Page to navigate.
        url: The URL to load.
        timeout_ms: Navigation timeout in milliseconds.

    Returns:
        The final HTTP status code (0 if navigation failed entirely).
    """
    try:
        resp = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        status = resp.status if resp else 0
    except PlaywrightTimeout:
        logger.warning("Navigation timed out for %s", url)
        return 0
    except Exception as exc:
        logger.warning("Navigation failed for %s: %s", url, exc)
        return 0

    page.wait_for_timeout(2000)

    # Check if we landed on a Cloudflare phishing interstitial
    if _is_cloudflare_phishing_block(page):
        logger.info("Cloudflare phishing interstitial detected for %s", url)
        bypassed = _bypass_cloudflare_interstitial(page)
        if bypassed:
            logger.info("Successfully bypassed Cloudflare interstitial for %s", url)
            return 200
        else:
            logger.warning("Could not bypass Cloudflare interstitial for %s", url)
            return status

    return status


def _is_cloudflare_phishing_block(page: Page) -> bool:
    """Check if the current page is a Cloudflare phishing interstitial.

    Args:
        page: The Playwright page to check.

    Returns:
        True if the page is a Cloudflare phishing/malware block.
    """
    try:
        title = page.evaluate("() => document.title.toLowerCase()")
        if "suspected phishing" in title and "cloudflare" in title:
            return True
        if "suspected malware" in title and "cloudflare" in title:
            return True

        body = page.evaluate(
            "() => document.body ? document.body.innerText.toLowerCase()"
            ".substring(0, 1000) : ''"
        )
        if "suspected phishing" in body and "cloudflare" in body:
            return True
    except Exception:
        pass

    return False


def _bypass_cloudflare_interstitial(page: Page) -> bool:
    """Wait for Turnstile to auto-solve and submit the bypass form.

    Args:
        page: A page showing a Cloudflare phishing interstitial.

    Returns:
        True if the bypass succeeded and the real page loaded.
    """
    # Wait for Turnstile token to be populated
    elapsed = 0
    while elapsed < _TURNSTILE_TIMEOUT_MS:
        try:
            has_token = page.evaluate("""() => {
                const inp = document.querySelector(
                    '[name="cf-turnstile-response"]'
                );
                return inp && inp.value && inp.value.length > 10;
            }""")
            if has_token:
                break
        except Exception:
            pass

        page.wait_for_timeout(_TURNSTILE_POLL_MS)
        elapsed += _TURNSTILE_POLL_MS

    if elapsed >= _TURNSTILE_TIMEOUT_MS:
        logger.debug("Turnstile token did not appear within timeout")
        return False

    # Submit the bypass form
    try:
        page.evaluate("() => document.querySelector('form').submit()")
        page.wait_for_timeout(5000)

        # Check that we actually left the interstitial
        if _is_cloudflare_phishing_block(page):
            return False

        return True
    except Exception as exc:
        logger.debug("Form submission failed: %s", exc)
        return False
