"""Web vulnerability checks: version disclosure, mixed content, input reflection."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from scanner.models import Finding, RemediationEffort, Severity


async def check_web(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    """Run all web-layer checks and aggregate findings."""
    findings: list[Finding] = []

    # Fetch main page
    try:
        resp = await client.get(base_url, follow_redirects=True, timeout=12)
    except Exception:
        return []

    html = resp.text
    response_headers = {k.lower(): v for k, v in resp.headers.items()}

    findings.extend(_check_mixed_content(html, base_url))
    findings.extend(_check_version_comment(html, base_url))
    findings.extend(_check_js_source_maps(html, base_url))
    findings.extend(await _check_input_reflection(base_url, client))
    findings.extend(_check_error_pages(html, base_url, resp.status_code))

    return findings


def _check_mixed_content(html: str, base_url: str) -> list[Finding]:
    """Detect HTTP resources loaded on an HTTPS page."""
    if urlparse(base_url).scheme != "https":
        return []

    soup = BeautifulSoup(html, "html.parser")
    http_resources: list[str] = []

    for tag in soup.find_all(["script", "link", "img", "iframe", "frame"]):
        for attr in ["src", "href"]:
            val = tag.get(attr, "")
            if val.startswith("http://"):
                http_resources.append(f"<{tag.name} {attr}={val}>")

    if not http_resources:
        return []

    return [
        Finding(
            name="Mixed Content: HTTP Resources on HTTPS Page",
            severity=Severity.MEDIUM,
            affected_asset=base_url,
            evidence="HTTP resources found:\n" + "\n".join(http_resources[:5]),
            risk_explanation=(
                "HTTPS pages loading resources over HTTP allow network adversaries "
                "to intercept or replace those resources."
            ),
            attacker_impact=(
                "An adversary on the network path could replace an HTTP-loaded script "
                "with malicious code, effectively compromising the HTTPS page's security."
            ),
            business_impact="Degrades HTTPS security; browsers block or warn about mixed content.",
            recommended_fix=(
                "Replace all http:// resource URLs with https:// equivalents. "
                "Use relative URLs (//example.com/asset.js) where possible to automatically "
                "inherit the page protocol."
            ),
            fix_priority=3,
            remediation_effort=RemediationEffort.MEDIUM,
            confidence="High",
            references=["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"],
            validation_steps="After fixing, use browser DevTools > Console to confirm no mixed content warnings.",
            category="web",
        )
    ]


def _check_version_comment(html: str, base_url: str) -> list[Finding]:
    """Look for version strings in HTML comments."""
    findings: list[Finding] = []
    comment_pattern = re.compile(r"<!--(.*?)-->", re.DOTALL)
    version_pattern = re.compile(r"v?(\d+\.\d+[\.\d]*)")

    for match in comment_pattern.finditer(html):
        comment_text = match.group(1)
        if version_pattern.search(comment_text) and len(comment_text.strip()) < 200:
            findings.append(
                Finding(
                    name="Version Information in HTML Comment",
                    severity=Severity.LOW,
                    affected_asset=base_url,
                    evidence=f"HTML comment: <!-- {comment_text.strip()[:100]} -->",
                    risk_explanation="HTML comments may contain version information that aids fingerprinting.",
                    attacker_impact="Reduces adversary effort for identifying applicable CVEs.",
                    business_impact="Minor information disclosure.",
                    recommended_fix="Remove version strings from HTML comments in production builds.",
                    fix_priority=5,
                    remediation_effort=RemediationEffort.LOW,
                    confidence="Medium",
                    references=[],
                    validation_steps="View page source after fix and confirm version strings are absent from comments.",
                    category="web",
                )
            )
            break  # One finding is sufficient

    return findings


def _check_js_source_maps(html: str, base_url: str) -> list[Finding]:
    """Detect exposed JavaScript source maps."""
    soup = BeautifulSoup(html, "html.parser")
    findings: list[Finding] = []
    source_map_urls: list[str] = []

    for script in soup.find_all("script", src=True):
        src = script.get("src", "")
        if src.endswith(".map"):
            source_map_urls.append(src)
        # Also check for sourceMappingURL comments
    map_comment = re.search(r"//# sourceMappingURL=(.+\.map)", html)
    if map_comment:
        source_map_urls.append(map_comment.group(1))

    if source_map_urls:
        findings.append(
            Finding(
                name="JavaScript Source Maps Exposed",
                severity=Severity.MEDIUM,
                affected_asset=base_url,
                evidence="Source map references found:\n" + "\n".join(source_map_urls[:5]),
                risk_explanation=(
                    "Source map files (.map) contain the original, unminified source code. "
                    "Exposing them publicly gives adversaries access to your full application logic."
                ),
                attacker_impact=(
                    "An adversary can reconstruct the original source code, revealing "
                    "business logic, internal API endpoints, authentication flows, "
                    "and potential security weaknesses."
                ),
                business_impact="Intellectual property exposure; facilitates targeted attacks.",
                recommended_fix=(
                    "Remove source map files from production deployments. "
                    "Configure your build tool to exclude .map files from the public directory. "
                    "Webpack: devtool: false in production config."
                ),
                fix_priority=3,
                remediation_effort=RemediationEffort.LOW,
                confidence="High",
                references=["https://developer.chrome.com/articles/source-maps/"],
                validation_steps="Confirm .map files return 404 after removing them from the public directory.",
                category="web",
            )
        )

    return findings


async def _check_input_reflection(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    """
    Test for basic reflected input by injecting a safe, non-harmful string.
    This does NOT test with XSS payloads — only checks if input is echoed back.
    """
    findings: list[Finding] = []
    safe_marker = "SECTEST-REFLECTION-7x4z"

    test_url = f"{base_url.rstrip('/')}/?q={safe_marker}&s={safe_marker}&search={safe_marker}"
    try:
        resp = await client.get(test_url, follow_redirects=True, timeout=8)
    except Exception:
        return []

    if safe_marker in resp.text:
        # Only flag if it's reflected without HTML encoding
        raw_occurrences = resp.text.count(safe_marker)
        encoded = safe_marker.replace("<", "&lt;").replace(">", "&gt;")
        if raw_occurrences > 0:
            findings.append(
                Finding(
                    name="Reflected Input in Response (Potential Reflection Point)",
                    severity=Severity.LOW,
                    affected_asset=test_url,
                    evidence=f"Safe test string '{safe_marker}' was reflected in the page response (unencoded).",
                    risk_explanation=(
                        "User-supplied input is echoed back in the HTTP response without apparent encoding. "
                        "This is a characteristic pattern of reflected XSS vulnerabilities."
                    ),
                    attacker_impact=(
                        "If input is not properly HTML-encoded before output, an adversary could "
                        "craft a URL containing script code that executes in victims' browsers. "
                        "This scan only confirms reflection — manual review is required to confirm XSS."
                    ),
                    business_impact="Potential for client-side attacks against users who visit crafted URLs.",
                    recommended_fix=(
                        "HTML-encode all user-supplied input before rendering it in page output. "
                        "Use your framework's built-in escaping (e.g., Jinja2 auto-escape, React JSX). "
                        "Implement a Content-Security-Policy to reduce XSS impact."
                    ),
                    fix_priority=3,
                    remediation_effort=RemediationEffort.MEDIUM,
                    confidence="Low",
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    ],
                    validation_steps=(
                        "After encoding fixes, confirm the test string is HTML-encoded in the response. "
                        "Manual code review is recommended to confirm no XSS path exists."
                    ),
                    category="web",
                )
            )

    return findings


def _check_error_pages(html: str, base_url: str, status_code: int) -> list[Finding]:
    """Detect stack traces or sensitive information in error pages."""
    findings: list[Finding] = []
    if status_code < 400:
        return []

    stack_patterns = [
        r"Traceback \(most recent call last\)",
        r"at \w+\.\w+\([\w.]+:\d+\)",
        r"Exception in thread",
        r"java\.lang\.\w+Exception",
        r"Microsoft\.[\w.]+\.Exception",
        r"System\.[\w.]+Exception",
        r"Fatal error:",
        r"Warning: .*? in /",
        r"Parse error: .*? in /",
    ]

    for pattern in stack_patterns:
        if re.search(pattern, html, re.IGNORECASE):
            findings.append(
                Finding(
                    name="Stack Trace / Error Details in HTTP Response",
                    severity=Severity.MEDIUM,
                    affected_asset=base_url,
                    evidence=f"Stack trace pattern detected in HTTP {status_code} response.",
                    risk_explanation=(
                        "Detailed error messages and stack traces reveal internal file paths, "
                        "framework versions, and code structure to potential adversaries."
                    ),
                    attacker_impact=(
                        "Stack traces can reveal internal server paths, database queries, "
                        "API keys in stack variables, or framework vulnerabilities to exploit."
                    ),
                    business_impact="Information leakage that aids adversary reconnaissance.",
                    recommended_fix=(
                        "Configure your application and web server to return generic error pages "
                        "in production. Log detailed errors server-side only.\n"
                        "Django: DEBUG = False\nNode/Express: app.set('env', 'production')\nPHP: display_errors = Off"
                    ),
                    fix_priority=3,
                    remediation_effort=RemediationEffort.LOW,
                    confidence="High",
                    references=["https://owasp.org/www-community/Improper_Error_Handling"],
                    validation_steps="After fix, confirm error pages return generic messages without internal details.",
                    category="web",
                )
            )
            break

    return findings
