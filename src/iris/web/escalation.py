"""Phishing escalation report generator for IRIS.

Generates a pre-filled escalation snippet in markdown format based on
IRIS scan data.  The template mirrors the SOC escalation format used
at Critical Start so analysts can paste the output directly into their
ticketing system and fill in any remaining alert-specific fields.

Functions:
    generate_escalation  -- Build a full markdown escalation report.
    generate_kql_queries -- Produce ready-to-paste KQL hunting queries.
"""

from __future__ import annotations

import base64
from typing import Any

from iris.web.defang import defang as defang_url


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _vt_url_link(url: str) -> str:
    """Return a VirusTotal GUI link for a given URL.

    Uses unpadded base64url encoding, matching the convention in
    ``iris.web.osint``.

    Args:
        url: The raw (fanged) URL to encode.

    Returns:
        Full VirusTotal URL analysis link.
    """
    vt_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return f"https://www.virustotal.com/gui/url/{vt_id}"


def _vt_ip_link(ip: str) -> str:
    """Return a VirusTotal GUI link for an IP address.

    Args:
        ip: The IPv4 or IPv6 address string.

    Returns:
        Full VirusTotal IP address analysis link.
    """
    return f"https://www.virustotal.com/gui/ip-address/{ip}"


def _abuseipdb_link(ip: str) -> str:
    """Return an AbuseIPDB check link for an IP address.

    Args:
        ip: The IPv4 or IPv6 address string.

    Returns:
        Full AbuseIPDB check link.
    """
    return f"https://www.abuseipdb.com/check/{ip}"


# ---------------------------------------------------------------------------
# KQL query generator
# ---------------------------------------------------------------------------


def generate_kql_queries(
    domain: str,
    url: str,
    sender_domain: str = "",
) -> list[dict[str, str]]:
    """Generate ready-to-paste KQL hunting queries for Microsoft Defender / Sentinel.

    Produces queries for URL click analysis, similar email discovery,
    user sign-in activity, and optionally sender-domain email history.

    Args:
        domain: The domain from the suspicious URL (e.g. ``"evil.com"``).
        url: The full suspicious URL that was scanned.
        sender_domain: Optional sender email domain for an additional
            query filtering by sender domain.

    Returns:
        A list of dicts, each with keys ``name``, ``description``, and
        ``query`` containing the KQL text.
    """
    queries: list[dict[str, str]] = [
        {
            "name": "URL Clicks",
            "description": (
                f"Find all user clicks on URLs containing '{domain}' "
                "in the last 7 days."
            ),
            "query": (
                "UrlClickEvents\n"
                "| where Timestamp > ago(7d)\n"
                f'| where Url contains "{domain}"\n'
                "| summarize ClickCount = count() by AccountUpn, Url, ActionType\n"
                "| sort by ClickCount desc"
            ),
        },
        {
            "name": "Similar Emails",
            "description": (
                f"Find emails containing URLs with '{domain}' "
                "joined with email metadata in the last 7 days."
            ),
            "query": (
                "EmailUrlInfo\n"
                "| where Timestamp > ago(7d)\n"
                f'| where Url contains "{domain}"\n'
                "| join kind=inner (EmailEvents | where Timestamp > ago(7d)) "
                "on NetworkMessageId\n"
                "| summarize EmailCount = count() by "
                "SenderFromAddress, Subject, NetworkMessageId\n"
                "| sort by EmailCount desc"
            ),
        },
        {
            "name": "User Sign-in Activity",
            "description": (
                "Review failed and anomalous sign-in events for the "
                "affected user in the last 7 days.  Replace {{UPN}} "
                "with the user's UPN."
            ),
            "query": (
                "SigninLogs\n"
                "| where TimeGenerated > ago(7d)\n"
                '| where UserPrincipalName == "{{UPN}}"\n'
                '| where ResultType != "0"\n'
                "| project TimeGenerated, UserPrincipalName, "
                "AppDisplayName, IPAddress, Location, ResultType, "
                "ResultDescription\n"
                "| sort by TimeGenerated desc"
            ),
        },
    ]

    if sender_domain:
        queries.append({
            "name": "Sender Domain Emails",
            "description": (
                f"Find all emails from the sender domain '{sender_domain}' "
                "in the last 7 days."
            ),
            "query": (
                "EmailEvents\n"
                "| where Timestamp > ago(7d)\n"
                f'| where SenderFromDomain == "{sender_domain}"\n'
                "| summarize EmailCount = count() by "
                "SenderFromAddress, Subject\n"
                "| sort by EmailCount desc"
            ),
        })

    return queries


# ---------------------------------------------------------------------------
# Escalation report generator
# ---------------------------------------------------------------------------


def generate_escalation(
    scan_data: dict[str, Any],
    alert_context: dict[str, str] | None = None,
) -> str:
    """Generate a pre-filled phishing escalation report in markdown.

    Mirrors the Critical Start SOC escalation snippet format.  Fields
    that IRIS can derive from scan data are filled in automatically;
    remaining fields are left as ``{{ placeholder }}`` markers for the
    analyst.

    Args:
        scan_data: Dict returned by ``_report_to_copydata()`` in
            ``iris.web.app``.  Expected keys:

            - ``url`` / ``defanged_url`` -- the scanned URL.
            - ``risk_category`` / ``confidence`` / ``timestamp``.
            - ``ip`` / ``domain`` / ``recommendation``.
            - ``redirect_chain`` -- list of redirect-hop URL strings.
            - ``feed_results`` -- list of feed result dicts.
            - ``findings`` -- list of finding dicts.
            - ``file_download`` -- dict or ``None``.

        alert_context: Optional dict of email/alert metadata with any
            of the following keys:

            - ``upn`` -- User Principal Name.
            - ``name`` -- Display name of the affected user.
            - ``subject`` -- Email subject line.
            - ``network_message_id`` -- Exchange Network Message ID.
            - ``sender`` -- Sender email address.
            - ``sender_ip`` -- Sender IP address.
            - ``alert_name`` -- Name/label of the triggering alert.

    Returns:
        A markdown string ready for pasting into a ticketing system.
    """
    ctx = alert_context or {}

    # ----- Resolve alert-context fields or leave placeholders ----------
    alert_name = ctx.get("alert_name", "{{ alert.trigger.product_detail.name_label }}")
    user_name = ctx.get("name", "{{ Name }}")
    upn = ctx.get("upn", "{{ Recipient }}")
    subject = ctx.get("subject", "{{ Subject }}")
    network_msg_id = ctx.get("network_message_id", "{{ Network Message ID }}")
    sender = ctx.get("sender", "{{ Sender }}")
    sender_ip = ctx.get("sender_ip", "{{ Sender IP }}")

    # ----- Sender IP OSINT links --------------------------------------
    if ctx.get("sender_ip"):
        vt_ip = f"[VirusTotal]({_vt_ip_link(sender_ip)}) -"
        abuse_ip = f"[AbuseIPDB]({_abuseipdb_link(sender_ip)}) -"
    else:
        vt_ip = "[VirusTotal](https://www.virustotal.com/gui/ip-address/{{ Sender IP }}) -"
        abuse_ip = "[AbuseIPDB](https://www.abuseipdb.com/check/{{ Sender IP }}) -"

    # ----- URL details -------------------------------------------------
    redirect_chain: list[str] = scan_data.get("redirect_chain", [])
    scanned_url: str = scan_data.get("url", "")

    if redirect_chain:
        initial_url_raw = redirect_chain[0]
        final_url_raw = redirect_chain[-1]
    else:
        initial_url_raw = scanned_url
        final_url_raw = scanned_url

    initial_url_defanged = defang_url(initial_url_raw)
    final_url_defanged = defang_url(final_url_raw)

    initial_vt_link = _vt_url_link(initial_url_raw)
    final_vt_link = _vt_url_link(final_url_raw)

    # ----- Domain for KQL queries --------------------------------------
    domain: str = scan_data.get("domain", "")

    # Extract sender domain if sender address is available
    sender_domain = ""
    if ctx.get("sender") and "@" in ctx["sender"]:
        sender_domain = ctx["sender"].rsplit("@", 1)[-1]

    kql_queries = generate_kql_queries(
        domain=domain,
        url=scanned_url,
        sender_domain=sender_domain,
    )

    # Build KQL references for the snippet
    url_clicks_query = ""
    similar_emails_query = ""
    for q in kql_queries:
        if q["name"] == "URL Clicks":
            url_clicks_query = q["query"]
        elif q["name"] == "Similar Emails":
            similar_emails_query = q["query"]

    # ----- File download subsection ------------------------------------
    file_download_section = ""
    file_dl = scan_data.get("file_download")
    if file_dl:
        filename = file_dl.get("filename", "Unknown")
        sha256 = file_dl.get("sha256", "")
        vt_detections = file_dl.get("vt_detections", 0)
        vt_total = file_dl.get("vt_total_engines", 0)
        threat_label = file_dl.get("popular_threat_label", "")

        vt_file_link = ""
        if sha256:
            vt_file_link = f"https://www.virustotal.com/gui/file/{sha256}"

        file_download_section = (
            "\n* File download detected:\n"
            f"  * Filename: `{filename}`\n"
            f"  * SHA-256: `{sha256}`\n"
        )
        if vt_file_link:
            file_download_section += (
                f"  * VirusTotal: [{vt_detections}/{vt_total}]({vt_file_link})"
            )
            if threat_label:
                file_download_section += f" - {threat_label}"
            file_download_section += "\n"

    # ----- Assemble the full escalation report -------------------------
    report = f"""\
#### Medium Priority
***
#### Observations
{alert_name} has alerted on a malicious URL click involving the user {user_name} with the following details:
* UPN: {upn}
  * [Sign-in logs]
  * [Audit logs]

* Source email details:
  * Subject: {subject}
  * Network message ID: {network_msg_id}
  * Sender: {sender}
  * Sender IP address: {sender_ip}
    * {vt_ip}
    * {abuse_ip}

* URL details:
  * Initial URL: `{initial_url_defanged}` | [Screenshot]
    * [VirusTotal]({initial_vt_link}) -
  * Final landing page URL: `{final_url_defanged}` | [Screenshot]
    * [VirusTotal]({final_vt_link}) -
{file_download_section}
* Advanced hunting queries:
  * [URL clicks] - `` clicks
  * [Similar emails] - `` emails

### Actions Taken
* Requested a `user session revocation` and a `password reset` as a precaution.
* Requested a `domain block indicator`.
* Requested an `email deletion`.

### Risks
Phishing involves malicious actors sending deceptive emails containing suspicious links or attachments, often accompanied by social engineering tactics, with the intent to harvest credentials or execute malicious code on the victim's machine.
* [MITRE | Phishing](https://attack.mitre.org/techniques/T1566/)

### Recommendations
* If this activity is unexpected,
  * Ensure the removal of this email and any related emails.
  * Block the sender address and IP if they are not required for business operations.
  * Monitor the user's account for anomalous follow-on activity.
* If this activity is expected, orchestration can be implemented to suppress future alerts for this behavior, or this alert may be closed with a comment.

`If further action or clarification is needed, please escalate this back to Critical Start.`"""

    return report
