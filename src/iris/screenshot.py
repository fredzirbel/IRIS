"""Screenshot capture for IRIS using Playwright.

Captures full-page screenshots with:
- A URL banner overlay showing the final URL after redirects
- Red box annotations around suspicious page elements
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from playwright.sync_api import Page, sync_playwright, TimeoutError as PlaywrightTimeout

from iris.browser import launch_browser, create_context, navigate_with_bypass

logger = logging.getLogger(__name__)


# CSS selectors and text patterns used to identify suspicious elements
_SUSPICIOUS_SELECTORS = [
    # Password and credential inputs
    'input[type="password"]',
    'input[name*="pass" i]',
    'input[name*="credential" i]',
    'input[name*="login" i]',
    'input[name*="user" i]',
    # Forms that look like login forms
    'form[action*="login" i]',
    'form[action*="signin" i]',
    'form[action*="verify" i]',
    'form[action*="account" i]',
]

# Text content patterns that indicate social engineering
_SUSPICIOUS_TEXT_PATTERNS = [
    "download now",
    "click here to continue",
    "click to continue",
    "verify your account",
    "confirm your identity",
    "update your information",
    "your account has been",
    "suspended",
    "unusual activity",
    "press windows",
    "win+r",
    "windows + r",
    "copy and paste",
    "run this command",
    "powershell",
    "cmd.exe",
    "captcha",
    "verify you are human",
    "click allow",
    "enable notifications",
    "enable content",
]


def capture_screenshot(
    url: str,
    output_dir: Path,
    config: dict[str, Any],
    *,
    browser: Any = None,
) -> Path | None:
    """Capture an annotated full-page screenshot of the URL.

    Navigates to the URL with headless Chromium, injects a URL banner
    showing the final landing URL, highlights suspicious elements with
    red outlines, then takes a full-page screenshot.

    Args:
        url: The URL to screenshot.
        output_dir: Directory to save the screenshot PNG.
        config: The loaded IRIS configuration dictionary.
        browser: Optional shared Playwright Browser instance. When provided,
            a new context is created from it instead of launching a new browser.

    Returns:
        Path to the saved screenshot, or None if capture failed.
    """
    timeout_ms = config.get("requests", {}).get("timeout", 10) * 1000
    nav_timeout_ms = max(timeout_ms * 3, 15000)

    parsed = urlparse(url)
    domain = (parsed.hostname or "unknown").replace(".", "_")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"{domain}_{timestamp}.png"
    output_path = output_dir / filename

    own_browser = browser is None

    try:
        if own_browser:
            pw_ctx = sync_playwright().start()
            browser = launch_browser(pw_ctx, url)

        context = create_context(browser)
        page = context.new_page()

        status = navigate_with_bypass(page, url, timeout_ms=nav_timeout_ms)
        if status == 0:
            context.close()
            if own_browser:
                browser.close()
                pw_ctx.stop()
            logger.warning("Screenshot navigation failed for %s", url)
            return None

        # Get the final URL after any redirects
        final_url = page.url

        # Inject URL banner overlay
        _inject_url_banner(page, final_url, url)

        # Annotate suspicious elements
        annotation_count = _annotate_suspicious_elements(page)
        logger.debug("Annotated %d suspicious elements on %s", annotation_count, url)

        page.screenshot(path=str(output_path), full_page=True)
        context.close()
        if own_browser:
            browser.close()
            pw_ctx.stop()

        logger.info("Screenshot saved: %s", output_path)
        return output_path

    except PlaywrightTimeout:
        logger.warning("Screenshot timed out for %s", url)
        return None
    except Exception as exc:
        logger.error("Screenshot failed for %s: %s", url, exc)
        return None


def _inject_url_banner(page: Page, final_url: str, original_url: str) -> None:
    """Inject a URL bar banner at the top of the page.

    Shows the final URL after redirects. If the URL changed from the
    original, both are displayed.

    Args:
        page: The Playwright page object.
        final_url: The URL the page actually landed on.
        original_url: The URL that was originally requested.
    """
    # Escape quotes for safe JS injection
    final_escaped = final_url.replace("\\", "\\\\").replace("'", "\\'")
    original_escaped = original_url.replace("\\", "\\\\").replace("'", "\\'")

    # Treat http→https upgrade (same host+path) as a non-redirect
    final_norm = final_url.rstrip("/")
    original_norm = original_url.rstrip("/")
    redirected = final_norm != original_norm
    if redirected and original_norm.replace("http://", "https://", 1) == final_norm:
        redirected = False

    redirect_line = ""
    if redirected:
        redirect_line = (
            f"<div style='font-size:13px;color:#ff6b6b;margin-top:2px;'>"
            f"Redirected from: {original_escaped}</div>"
        )

    page.evaluate(f"""() => {{
        const banner = document.createElement('div');
        banner.id = 'iris-url-banner';
        banner.innerHTML = `
            <div style="
                position: relative;
                top: 0;
                left: 0;
                width: 100%;
                background: #2d2d2d;
                color: #e0e0e0;
                font-family: 'Segoe UI', Consolas, monospace;
                font-size: 16px;
                padding: 8px 16px;
                box-sizing: border-box;
                z-index: 999999;
                border-bottom: 2px solid #444;
                display: flex;
                flex-direction: column;
            ">
                <div style="display:flex;align-items:center;gap:8px;">
                    <span style="
                        background: #c0392b;
                        color: white;
                        font-size: 10px;
                        font-weight: bold;
                        padding: 2px 6px;
                        border-radius: 3px;
                    ">IRIS</span>
                    <span style="
                        background: #3d3d3d;
                        padding: 4px 12px;
                        border-radius: 4px;
                        flex: 1;
                        overflow: hidden;
                        text-overflow: ellipsis;
                        white-space: nowrap;
                    ">{final_escaped}</span>
                </div>
                {redirect_line}
            </div>
        `;
        document.body.insertBefore(banner, document.body.firstChild);
    }}""")


def _annotate_suspicious_elements(page: object) -> int:
    """Find and highlight suspicious elements on the page.

    Draws red outlines around elements matching suspicious CSS selectors
    or containing suspicious text patterns. Adds a small label above
    each highlighted element.

    Args:
        page: The Playwright page object.

    Returns:
        Number of elements annotated.
    """
    selectors_json = json.dumps(_SUSPICIOUS_SELECTORS)
    patterns_json = json.dumps(_SUSPICIOUS_TEXT_PATTERNS)

    count = page.evaluate(f"""() => {{
        const selectors = {selectors_json};
        const textPatterns = {patterns_json};
        let annotationCount = 0;

        function annotateElement(el, reason) {{
            // Skip if already annotated or not visible
            if (el.dataset.irisAnnotated) return false;
            const rect = el.getBoundingClientRect();
            if (rect.width === 0 || rect.height === 0) return false;

            el.dataset.irisAnnotated = 'true';
            el.style.outline = '3px solid #e74c3c';
            el.style.outlineOffset = '2px';
            el.style.position = el.style.position || 'relative';

            // Add label
            const label = document.createElement('div');
            label.textContent = reason;
            label.style.cssText = `
                position: absolute;
                top: -22px;
                left: 0;
                background: #e74c3c;
                color: white;
                font-size: 10px;
                font-weight: bold;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: Arial, sans-serif;
                z-index: 999998;
                white-space: nowrap;
                pointer-events: none;
            `;

            // Make parent relative if needed for label positioning
            const parent = el.parentElement;
            if (parent) {{
                const parentPos = window.getComputedStyle(parent).position;
                if (parentPos === 'static') {{
                    parent.style.position = 'relative';
                }}
            }}

            el.style.position = 'relative';
            el.appendChild(label);
            annotationCount++;
            return true;
        }}

        // Check CSS selectors
        for (const selector of selectors) {{
            try {{
                const elements = document.querySelectorAll(selector);
                elements.forEach(el => {{
                    let reason = 'SUSPICIOUS INPUT';
                    if (el.type === 'password' || (el.name && el.name.toLowerCase().includes('pass'))) {{
                        reason = 'PASSWORD FIELD';
                    }} else if (el.tagName === 'FORM') {{
                        reason = 'SUSPICIOUS FORM';
                    }}
                    annotateElement(el, reason);
                }});
            }} catch(e) {{}}
        }}

        // Check text content patterns
        const walker = document.createTreeWalker(
            document.body,
            NodeFilter.SHOW_ELEMENT,
            null
        );

        const clickableElements = [];
        while (walker.nextNode()) {{
            const node = walker.currentNode;
            const tag = node.tagName.toLowerCase();
            // Only check interactive/visible elements and headings
            if (['a', 'button', 'div', 'span', 'p', 'h1', 'h2', 'h3', 'h4', 'li', 'label'].includes(tag)) {{
                clickableElements.push(node);
            }}
        }}

        for (const el of clickableElements) {{
            // Get direct text content (not children's text)
            const text = el.textContent.toLowerCase().trim();
            if (!text || text.length > 500) continue;

            for (const pattern of textPatterns) {{
                if (text.includes(pattern)) {{
                    let reason = 'SUSPICIOUS TEXT';
                    if (pattern.includes('download')) reason = 'DOWNLOAD BUTTON';
                    else if (pattern.includes('captcha') || pattern.includes('human')) reason = 'CAPTCHA/VERIFICATION';
                    else if (pattern.includes('win+r') || pattern.includes('windows + r') || pattern.includes('powershell') || pattern.includes('cmd.exe') || pattern.includes('run this command') || pattern.includes('copy and paste')) reason = 'CLICKFIX ATTACK';
                    else if (pattern.includes('allow') || pattern.includes('notification') || pattern.includes('enable')) reason = 'PERMISSION PROMPT';
                    else if (pattern.includes('verify') || pattern.includes('confirm') || pattern.includes('update') || pattern.includes('suspended') || pattern.includes('unusual')) reason = 'SOCIAL ENGINEERING';
                    else if (pattern.includes('click')) reason = 'SUSPICIOUS BUTTON';
                    annotateElement(el, reason);
                    break;
                }}
            }}
        }}

        return annotationCount;
    }}""")

    return count or 0
