"""Security header analysis."""
from __future__ import annotations

import re
from typing import List

import httpx

from config import SECURITY_HEADERS, USER_AGENT
from scanner.models import Finding, HeaderAnalysis, RemediationEffort, Severity


async def check_headers(url: str, client: httpx.AsyncClient) -> tuple[list[HeaderAnalysis], list[Finding]]:
    """Fetch the URL and audit all security-relevant response headers."""
    try:
        resp = await client.get(url, follow_redirects=True)
    except Exception:
        return [], []

    response_headers = {k.lower(): v for k, v in resp.headers.items()}
    analyses: list[HeaderAnalysis] = []
    findings: list[Finding] = []

    for header_key, meta in SECURITY_HEADERS.items():
        value = response_headers.get(header_key)
        present = value is not None
        misconfigured = False
        notes = ""

        if present:
            misconfigured, notes = _check_header_value(header_key, value)

        analysis = HeaderAnalysis(
            header_name=meta["name"],
            present=present,
            value=value,
            is_misconfigured=misconfigured,
            notes=notes,
        )
        analyses.append(analysis)

        if not present or misconfigured:
            sev_str = meta["severity"] if not present else "Low"
            # Misconfigured CSP or missing CSP is always High
            if header_key == "content-security-policy":
                sev_str = "High"

            severity = Severity(sev_str)
            if misconfigured:
                finding_name = f"Misconfigured Header: {meta['name']}"
                evidence = f"{meta['name']}: {value} — {notes}"
            else:
                finding_name = f"Missing Security Header: {meta['name']}"
                evidence = f"Header '{meta['name']}' was not returned in the HTTP response."

            findings.append(
                Finding(
                    name=finding_name,
                    severity=severity,
                    affected_asset=url,
                    evidence=evidence,
                    risk_explanation=meta["description"],
                    attacker_impact=_attacker_impact(header_key, misconfigured),
                    business_impact="Increases risk of client-side attacks that can compromise visitors or expose business data.",
                    recommended_fix=meta["recommendation"],
                    fix_priority=_priority(header_key),
                    remediation_effort=RemediationEffort.LOW,
                    confidence="High",
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://securityheaders.com/",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
                    ],
                    validation_steps=(
                        f"After updating your web server or application configuration, "
                        f"re-request {url} and confirm the '{meta['name']}' header is "
                        f"present with the recommended value. Use https://securityheaders.com/ "
                        f"for an independent check."
                    ),
                    category="headers",
                )
            )

    # Check for information-leaking headers
    leak_findings = _check_leaking_headers(response_headers, url)
    findings.extend(leak_findings)

    return analyses, findings


def _check_header_value(header: str, value: str) -> tuple[bool, str]:
    """Return (is_misconfigured, notes) for a present header value."""
    v = value.lower().strip()

    if header == "strict-transport-security":
        if "max-age=0" in v:
            return True, "max-age=0 effectively disables HSTS."
        match = re.search(r"max-age=(\d+)", v)
        if match and int(match.group(1)) < 15768000:
            return True, f"max-age {match.group(1)} is below recommended 6 months (15768000)."

    if header == "x-frame-options":
        if v not in ("deny", "sameorigin"):
            return True, f"Value '{value}' is non-standard; use DENY or SAMEORIGIN."

    if header == "x-content-type-options":
        if v != "nosniff":
            return True, f"Value '{value}' is invalid; must be 'nosniff'."

    if header == "content-security-policy":
        if "unsafe-inline" in v and "unsafe-eval" in v:
            return True, "CSP contains both 'unsafe-inline' and 'unsafe-eval', severely weakening XSS protection."
        if "*" in v and "default-src" in v:
            return True, "CSP uses a wildcard (*) in default-src, which effectively negates XSS protection."

    return False, ""


def _check_leaking_headers(headers: dict[str, str], url: str) -> list[Finding]:
    """Detect server/tech version disclosure via response headers."""
    findings: list[Finding] = []

    leaky = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
             "x-generator", "x-drupal-cache", "x-wp-total"]
    for h in leaky:
        val = headers.get(h)
        if not val:
            continue
        # Only flag if a version number appears
        if re.search(r"\d+\.\d+", val):
            findings.append(
                Finding(
                    name=f"Server Version Disclosure via '{h}' Header",
                    severity=Severity.MEDIUM,
                    affected_asset=url,
                    evidence=f"{h}: {val}",
                    risk_explanation=(
                        "The server reveals its software version in HTTP response headers. "
                        "This helps adversaries identify applicable CVEs quickly."
                    ),
                    attacker_impact=(
                        "An adversary can use the disclosed version to search for known "
                        "vulnerabilities in public databases without any intrusive probing."
                    ),
                    business_impact="Reduces effort required for targeted attacks against known software vulnerabilities.",
                    recommended_fix=(
                        f"Remove or suppress the '{h}' header in your web server configuration. "
                        "For Apache: ServerTokens Prod; ServerSignature Off. "
                        "For Nginx: server_tokens off. "
                        "For IIS: remove X-Powered-By and X-AspNet-Version headers."
                    ),
                    fix_priority=3,
                    remediation_effort=RemediationEffort.LOW,
                    confidence="High",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                    ],
                    validation_steps=(
                        "After suppressing the header, make a fresh request and confirm "
                        f"the '{h}' header is absent or contains no version information."
                    ),
                    category="headers",
                )
            )
    return findings


def _attacker_impact(header: str, misconfigured: bool) -> str:
    impacts = {
        "content-security-policy": (
            "Without a Content Security Policy, an adversary who finds an XSS vector "
            "can execute arbitrary scripts in visitors' browsers, potentially stealing "
            "session cookies, redirecting users to phishing pages, or exfiltrating data."
        ),
        "strict-transport-security": (
            "Without HSTS, visitors may connect over plain HTTP if the HTTPS URL is not "
            "known, exposing credentials and session tokens to network interception on "
            "untrusted networks such as public Wi-Fi."
        ),
        "x-frame-options": (
            "Without X-Frame-Options, the page can be embedded in an invisible iframe on "
            "a malicious site, tricking users into performing unintended actions "
            "(clickjacking)."
        ),
        "x-content-type-options": (
            "Without this header, older browsers may guess a file's content type, which "
            "could allow a malicious uploaded file to be interpreted as executable script."
        ),
        "referrer-policy": (
            "Without a Referrer-Policy, the browser may send the full URL (including query "
            "parameters that may contain tokens or personal data) to third-party sites in "
            "the Referer header."
        ),
        "permissions-policy": (
            "Without a Permissions-Policy, third-party scripts loaded on the page may be "
            "able to silently activate device features such as the microphone or camera "
            "without explicit user consent."
        ),
    }
    return impacts.get(
        header,
        "The missing or misconfigured header weakens browser-level security controls, "
        "potentially enabling client-side attacks against site visitors.",
    )


def _priority(header: str) -> int:
    priorities = {
        "content-security-policy": 1,
        "strict-transport-security": 2,
        "x-frame-options": 2,
        "x-content-type-options": 3,
        "referrer-policy": 4,
        "permissions-policy": 4,
        "cross-origin-opener-policy": 4,
        "cross-origin-resource-policy": 4,
        "cross-origin-embedder-policy": 5,
    }
    return priorities.get(header, 4)
