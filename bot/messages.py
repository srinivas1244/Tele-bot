"""Telegram message templates."""
from __future__ import annotations

from scanner.models import ScanResult

WELCOME_MESSAGE = """
👋 *Security Assessment Bot*

I perform authorized, non-destructive security assessments of websites and APIs.

⚠️ *IMPORTANT LEGAL NOTICE*
This bot must only be used on assets you *own* or have *explicit written permission* to test. Unauthorized scanning is illegal.

*What I check:*
• Port scanning (common ports)
• TLS/SSL certificate analysis
• Security headers audit
• Cookie security
• CORS misconfiguration
• Exposed sensitive files & admin panels
• CMS / framework detection
• Frontend dependency CVEs
• API security (Swagger, methods, auth)
• Open redirects

*How to start:*
Send me a URL, domain, or IP address to scan.

*Commands:*
/scan <url> — Start a new scan
/help — Show this help message
/status — Check your scan quota
"""

HELP_MESSAGE = """
*Security Assessment Bot — Help*

*Usage:*
1. Send a URL or domain (e.g., `https://example.com` or `example.com`)
2. Confirm you own or have permission to test the target
3. Wait for the scan to complete (usually 1–3 minutes)
4. Receive your security report

*Commands:*
/scan <url> — Scan a specific URL
/status — Show remaining scans in your quota
/help — Show this message

*Rate limit:* {max_scans} scans per hour per user.

*Important:*
• Only scan assets you own or have explicit permission to test
• All scans are non-destructive and rate-limited
• Reports are provided for educational and authorized security testing purposes only
""".format(max_scans=3)

UNAUTHORIZED_MESSAGE = """
🚫 *Access Denied*

You are not authorized to use this bot.

If you believe this is an error, please contact the bot administrator.
"""

CONFIRMATION_MESSAGE = """
🎯 *Target received:* `{target}`

Before I proceed, I need your explicit confirmation.

*Confirmation required:*
By clicking "I Confirm" below, you declare that:

✅ You own this asset OR have explicit written permission to test it
✅ You understand this is a security assessment tool
✅ You accept full legal responsibility for this scan

⚠️ *Unauthorized scanning is illegal and may violate computer fraud laws.*
"""

RATE_LIMIT_MESSAGE = """
⏱ *Rate limit reached*

You have reached your scan quota ({max_scans} scans per hour).

Please wait *{reset_minutes} minutes* before starting a new scan.

Remaining scans this hour: 0
"""

SCAN_ALREADY_RUNNING_MESSAGE = """
⚙️ *Scan in progress*

You already have an active scan running. Please wait for it to complete before starting a new one.
"""

SCAN_STARTED_MESSAGE = """
🔍 *Scan started*

*Target:* `{target}`
*Scan ID:* `{scan_id}`

Running the following checks:
• 🔌 Port scan (common ports)
• 🔒 TLS/SSL certificate
• 🛡️ Security headers
• 🍪 Cookie security
• 🔗 CORS configuration
• 📁 Sensitive file exposure
• 🔍 CMS/framework detection
• 📦 Frontend dependency CVEs
• 🔌 API security
• ↪️ Open redirect detection
• 🌐 General web checks

⏳ This usually takes 1–3 minutes...
"""

SCAN_COMPLETE_HEADER = """
✅ *Scan Complete*

*Target:* `{target}`
*Duration:* {duration}s
*Risk Level:* {risk_emoji} *{risk_level}*
"""

SCAN_FAILED_MESSAGE = """
❌ *Scan Failed*

*Target:* `{target}`
*Error:* {error}

Please check that the target is accessible and try again.
"""

INVALID_TARGET_MESSAGE = """
❌ *Invalid target*

I couldn't parse `{target}` as a valid URL, domain, or IP address.

*Valid examples:*
• `https://example.com`
• `example.com`
• `192.168.1.1`
• `https://api.example.com/v1`

Please try again with a valid target.
"""


def format_scan_summary(result: ScanResult) -> str:
    """Format a concise Telegram summary of the scan results."""
    risk_emojis = {
        "Critical": "🔴",
        "High": "🟠",
        "Medium": "🟡",
        "Low": "🔵",
        "Informational": "⚪",
    }

    duration = ""
    if result.completed_at and result.started_at:
        secs = int((result.completed_at - result.started_at).total_seconds())
        duration = str(secs)

    risk_emoji = risk_emojis.get(result.risk_level, "⚪")

    lines = [
        SCAN_COMPLETE_HEADER.format(
            target=result.target_normalized,
            duration=duration,
            risk_level=result.risk_level,
            risk_emoji=risk_emoji,
        ),
        "*Finding Summary:*",
    ]

    if result.critical_count:
        lines.append(f"🔴 Critical: {result.critical_count}")
    if result.high_count:
        lines.append(f"🟠 High: {result.high_count}")
    if result.medium_count:
        lines.append(f"🟡 Medium: {result.medium_count}")
    if result.low_count:
        lines.append(f"🔵 Low: {result.low_count}")
    if result.info_count:
        lines.append(f"⚪ Informational: {result.info_count}")

    if not result.findings:
        lines.append("✅ No issues detected!")

    if result.open_ports:
        port_list = ", ".join(f"{p.port}/{p.service}" for p in result.open_ports[:6])
        lines.append(f"\n*Open Ports:* {port_list}")

    if result.technologies_detected:
        tech_list = ", ".join(result.technologies_detected[:4])
        lines.append(f"*Technologies:* {tech_list}")

    # Top 3 critical/high findings preview
    top_findings = [f for f in result.sorted_findings() if f.severity.value in ("Critical", "High")][:3]
    if top_findings:
        lines.append("\n*Top Priority Issues:*")
        for i, f in enumerate(top_findings, 1):
            emoji = risk_emojis.get(f.severity.value, "")
            lines.append(f"{i}. {emoji} {f.name}")

    lines.append("\n📄 Full JSON and PDF reports attached below.")
    return "\n".join(lines)


def format_status_message(user_id: int, remaining: int, max_scans: int) -> str:
    return (
        f"📊 *Your Scan Quota*\n\n"
        f"Remaining scans this hour: *{remaining}/{max_scans}*\n"
        f"Quota resets every 60 minutes.\n\n"
        f"Use /scan <url> to start a new scan."
    )
