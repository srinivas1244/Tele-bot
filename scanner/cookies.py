"""Cookie security attribute analysis."""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse

import httpx

from scanner.models import CookieAnalysis, Finding, RemediationEffort, Severity


async def check_cookies(url: str, client: httpx.AsyncClient) -> tuple[list[CookieAnalysis], list[Finding]]:
    """Analyse Set-Cookie headers returned by the given URL."""
    try:
        resp = await client.get(url, follow_redirects=True)
    except Exception:
        return [], []

    is_https = urlparse(url).scheme == "https"
    analyses: list[CookieAnalysis] = []
    findings: list[Finding] = []

    raw_cookies = resp.headers.get_list("set-cookie")
    if not raw_cookies:
        return [], []

    for raw in raw_cookies:
        analysis = _parse_cookie(raw)
        analyses.append(analysis)
        cookie_findings = _audit_cookie(analysis, url, is_https)
        findings.extend(cookie_findings)

    return analyses, findings


def _parse_cookie(raw: str) -> CookieAnalysis:
    """Parse a raw Set-Cookie string into structured attributes."""
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=")[0].strip() if parts else "unknown"

    attrs = {p.lower().split("=")[0].strip(): (p.split("=", 1)[1].strip() if "=" in p else True)
             for p in parts[1:]}

    return CookieAnalysis(
        name=name,
        secure="secure" in attrs,
        http_only="httponly" in attrs,
        same_site=str(attrs["samesite"]) if "samesite" in attrs else None,
        domain=str(attrs["domain"]) if "domain" in attrs else None,
        path=str(attrs["path"]) if "path" in attrs else None,
    )


def _audit_cookie(c: CookieAnalysis, url: str, is_https: bool) -> list[Finding]:
    findings: list[Finding] = []

    # Missing Secure flag on an HTTPS site
    if is_https and not c.secure:
        findings.append(
            Finding(
                name=f"Cookie Missing Secure Flag: '{c.name}'",
                severity=Severity.MEDIUM,
                affected_asset=url,
                evidence=f"Cookie '{c.name}' is set without the Secure attribute.",
                risk_explanation=(
                    "Without the Secure flag, the cookie may be transmitted over "
                    "plain HTTP if the user follows an HTTP link to the site."
                ),
                attacker_impact=(
                    "An adversary on the network could intercept the cookie if it is "
                    "ever sent over plain HTTP, potentially stealing session tokens."
                ),
                business_impact="Risk of session hijacking if users access the site over HTTP.",
                recommended_fix=f"Add the Secure attribute to the '{c.name}' cookie: Set-Cookie: {c.name}=...; Secure",
                fix_priority=3,
                remediation_effort=RemediationEffort.LOW,
                confidence="High",
                references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                validation_steps=f"Re-check the Set-Cookie header for '{c.name}' and confirm 'Secure' is present.",
                category="cookies",
            )
        )

    # Missing HttpOnly flag
    if not c.http_only:
        findings.append(
            Finding(
                name=f"Cookie Missing HttpOnly Flag: '{c.name}'",
                severity=Severity.MEDIUM,
                affected_asset=url,
                evidence=f"Cookie '{c.name}' is set without the HttpOnly attribute.",
                risk_explanation=(
                    "Cookies without HttpOnly can be read by JavaScript, "
                    "making them accessible to XSS payloads."
                ),
                attacker_impact=(
                    "If an XSS vulnerability exists on the site, an adversary's script "
                    "could read this cookie and send its value to an attacker-controlled server."
                ),
                business_impact="Session tokens exposed to XSS are a common cause of account takeover incidents.",
                recommended_fix=f"Add the HttpOnly attribute: Set-Cookie: {c.name}=...; HttpOnly",
                fix_priority=3,
                remediation_effort=RemediationEffort.LOW,
                confidence="High",
                references=["https://owasp.org/www-community/HttpOnly"],
                validation_steps=f"Confirm '{c.name}' has HttpOnly after fix. Try reading it via document.cookie in DevTools — it should not appear.",
                category="cookies",
            )
        )

    # Missing or weak SameSite
    if c.same_site is None:
        findings.append(
            Finding(
                name=f"Cookie Missing SameSite Attribute: '{c.name}'",
                severity=Severity.LOW,
                affected_asset=url,
                evidence=f"Cookie '{c.name}' has no SameSite attribute (defaults to Lax in modern browsers, but None in older ones).",
                risk_explanation=(
                    "Without SameSite, the cookie may be sent with cross-site requests, "
                    "which is a prerequisite for CSRF attacks."
                ),
                attacker_impact=(
                    "In older browsers, a malicious site could trigger cross-origin requests "
                    "that automatically include this cookie, potentially performing actions "
                    "on the user's behalf."
                ),
                business_impact="Risk of CSRF attacks that perform unauthorized actions as authenticated users.",
                recommended_fix=f"Add SameSite=Strict or SameSite=Lax: Set-Cookie: {c.name}=...; SameSite=Strict",
                fix_priority=4,
                remediation_effort=RemediationEffort.LOW,
                confidence="High",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"],
                validation_steps=f"Confirm SameSite is set on '{c.name}' after fix.",
                category="cookies",
            )
        )
    elif c.same_site.lower() == "none" and not c.secure:
        findings.append(
            Finding(
                name=f"Cookie SameSite=None Without Secure: '{c.name}'",
                severity=Severity.MEDIUM,
                affected_asset=url,
                evidence=f"Cookie '{c.name}': SameSite=None but Secure is absent.",
                risk_explanation="SameSite=None requires the Secure attribute; without it, the cookie is rejected by modern browsers and the intent is broken.",
                attacker_impact=(
                    "The cookie allows cross-site requests but without HTTPS enforcement, "
                    "which can expose it to interception."
                ),
                business_impact="Broken cookie behaviour across browsers; potential security gap.",
                recommended_fix=f"Add Secure attribute: Set-Cookie: {c.name}=...; SameSite=None; Secure",
                fix_priority=3,
                remediation_effort=RemediationEffort.LOW,
                confidence="High",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite#none"],
                validation_steps="Verify cookie attributes after fix in browser DevTools > Application > Cookies.",
                category="cookies",
            )
        )

    return findings
