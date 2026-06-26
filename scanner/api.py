"""API security checks: Swagger exposure, CORS, auth indicators, HTTP methods."""
from __future__ import annotations

import asyncio
import json
import re
from typing import Optional
from urllib.parse import urljoin

import httpx

from config import API_DISCOVERY_PATHS
from scanner.models import Finding, RemediationEffort, Severity


async def check_api_security(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    """Run all API security checks."""
    findings: list[Finding] = []

    # Run checks concurrently
    results = await asyncio.gather(
        _discover_api_docs(base_url, client),
        _check_http_methods(base_url, client),
        _check_api_error_messages(base_url, client),
        _check_rate_limit_headers(base_url, client),
        _check_auth_indicators(base_url, client),
        return_exceptions=True,
    )

    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    return findings


async def _discover_api_docs(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    """Check for exposed Swagger/OpenAPI documentation."""
    findings: list[Finding] = []
    semaphore = asyncio.Semaphore(5)

    async def probe(path: str) -> Optional[Finding]:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        async with semaphore:
            try:
                resp = await client.get(url, follow_redirects=False, timeout=8)
            except Exception:
                return None

        if resp.status_code != 200:
            return None

        content_type = resp.headers.get("content-type", "").lower()
        is_json = "json" in content_type or _looks_like_openapi_json(resp.text)
        is_ui = "swagger" in resp.text.lower() or "openapi" in resp.text.lower() or "redoc" in resp.text.lower()

        if not (is_json or is_ui):
            return None

        has_sensitive = _openapi_has_sensitive_endpoints(resp.text)
        severity = Severity.HIGH if has_sensitive else Severity.MEDIUM

        return Finding(
            name=f"Exposed API Documentation: {path}",
            severity=severity,
            affected_asset=url,
            evidence=f"HTTP 200 at {url}. API docs accessible without authentication.",
            risk_explanation=(
                "Publicly accessible API documentation reveals all available endpoints, "
                "parameters, authentication methods, and data models."
            ),
            attacker_impact=(
                "An adversary can use the API documentation to enumerate all available "
                "endpoints, identify authentication requirements, and craft targeted "
                "requests against the API — significantly reducing reconnaissance effort."
            ),
            business_impact="Full API surface exposure aids targeted attacks and competitive intelligence gathering.",
            recommended_fix=(
                "Require authentication to access API documentation in production. "
                "Consider disabling Swagger UI in production entirely and maintaining "
                "docs in a separate, access-controlled environment."
            ),
            fix_priority=2,
            remediation_effort=RemediationEffort.LOW,
            confidence="High",
            references=["https://owasp.org/www-project-api-security/"],
            validation_steps=f"After restricting access, confirm {url} returns 401/403 without valid credentials.",
            category="api",
        )

    tasks = [probe(p) for p in API_DISCOVERY_PATHS]
    results = await asyncio.gather(*tasks)
    findings.extend(r for r in results if r is not None)
    return findings


async def _check_http_methods(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    """Check which HTTP methods are allowed."""
    findings: list[Finding] = []

    try:
        resp = await client.options(base_url, timeout=8)
    except Exception:
        return []

    allow_header = resp.headers.get("allow", "") or resp.headers.get("access-control-allow-methods", "")
    if not allow_header:
        return []

    methods_allowed = [m.strip().upper() for m in allow_header.split(",")]
    dangerous = [m for m in methods_allowed if m in ("TRACE", "TRACK", "DELETE", "PUT", "PATCH")]

    if dangerous:
        for method in dangerous:
            sev = Severity.HIGH if method in ("DELETE", "PUT") else Severity.MEDIUM
            findings.append(
                Finding(
                    name=f"Risky HTTP Method Allowed: {method}",
                    severity=sev,
                    affected_asset=base_url,
                    evidence=f"OPTIONS response Allow: {allow_header}\nDangerous method detected: {method}",
                    risk_explanation=_method_risk(method),
                    attacker_impact=_method_impact(method),
                    business_impact="Risk of unauthorized data modification or deletion if methods are not access-controlled.",
                    recommended_fix=_method_fix(method),
                    fix_priority=2,
                    remediation_effort=RemediationEffort.MEDIUM,
                    confidence="Medium",
                    references=["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"],
                    validation_steps=f"After disabling {method}, re-run OPTIONS and confirm it is absent from the Allow header.",
                    category="api",
                )
            )
    return findings


async def _check_api_error_messages(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    """Check if API returns sensitive error details."""
    findings: list[Finding] = []

    test_paths = [
        urljoin(base_url.rstrip("/") + "/", "api/nonexistent-endpoint-test"),
        urljoin(base_url.rstrip("/") + "/", "api/v1/nonexistent-endpoint-test"),
    ]

    stack_patterns = [
        r"Traceback \(most recent call last\)",
        r"at [\w.]+\([\w.]+:\d+\)",
        r"java\.lang\.\w+Exception",
        r"Microsoft\.[\w.]+\.Exception",
        r"sql.*error",
        r"database.*error",
        r"ORA-\d{5}",
        r"mysql.*error",
        r"postgresql.*error",
    ]

    for url in test_paths:
        try:
            resp = await client.get(url, timeout=8)
        except Exception:
            continue
        if resp.status_code < 400:
            continue
        for pattern in stack_patterns:
            if re.search(pattern, resp.text, re.IGNORECASE):
                findings.append(
                    Finding(
                        name="API Error Messages Leak Internal Details",
                        severity=Severity.MEDIUM,
                        affected_asset=url,
                        evidence=f"HTTP {resp.status_code} response contains stack trace or database error patterns.",
                        risk_explanation="Detailed API error messages reveal internal paths, query structure, or technology stack.",
                        attacker_impact=(
                            "Error details help adversaries understand the technology stack, "
                            "database type, and internal file paths, reducing reconnaissance effort."
                        ),
                        business_impact="Information leakage that aids targeted attack planning.",
                        recommended_fix=(
                            "Return generic error messages in API responses. "
                            "Log detailed errors server-side only. "
                            "Example: {'error': 'An internal error occurred'} — not the full exception."
                        ),
                        fix_priority=3,
                        remediation_effort=RemediationEffort.LOW,
                        confidence="High",
                        references=["https://owasp.org/www-project-api-security/"],
                        validation_steps="After fix, confirm error responses contain only generic messages.",
                        category="api",
                    )
                )
                break

    return findings


async def _check_rate_limit_headers(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    """Check for presence of rate-limit response headers."""
    try:
        resp = await client.get(base_url, timeout=8)
    except Exception:
        return []

    rate_headers = ["x-ratelimit-limit", "x-rate-limit-limit", "ratelimit-limit",
                    "x-ratelimit-remaining", "retry-after"]
    present = [h for h in rate_headers if h in {k.lower() for k in resp.headers.keys()}]

    if not present:
        return [
            Finding(
                name="No Rate-Limiting Headers Detected",
                severity=Severity.LOW,
                affected_asset=base_url,
                evidence="No X-RateLimit-* or Retry-After headers found in the API response.",
                risk_explanation="The absence of rate-limiting headers suggests the API may not enforce request throttling.",
                attacker_impact=(
                    "Without rate limiting, an adversary can make unlimited automated "
                    "requests for credential stuffing, scraping, or abuse."
                ),
                business_impact="Risk of API abuse, scraping, and credential stuffing attacks.",
                recommended_fix=(
                    "Implement rate limiting at the API gateway or application level. "
                    "Return X-RateLimit-Limit, X-RateLimit-Remaining, and X-RateLimit-Reset headers "
                    "so clients can self-throttle."
                ),
                fix_priority=3,
                remediation_effort=RemediationEffort.MEDIUM,
                confidence="Low",
                references=["https://owasp.org/www-project-api-security/"],
                validation_steps="After implementing rate limiting, confirm headers appear on repeated requests.",
                category="api",
            )
        ]
    return []


async def _check_auth_indicators(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    """Check for presence/absence of authentication headers in API responses."""
    findings: list[Finding] = []

    # Check for WWW-Authenticate or common API auth patterns
    try:
        resp = await client.get(base_url, timeout=8)
    except Exception:
        return []

    if resp.status_code == 200:
        auth_headers = ["www-authenticate", "x-auth-token", "authorization"]
        has_auth = any(h in {k.lower() for k in resp.headers.keys()} for h in auth_headers)
        if not has_auth:
            findings.append(
                Finding(
                    name="API Endpoint Accessible Without Authentication",
                    severity=Severity.INFORMATIONAL,
                    affected_asset=base_url,
                    evidence="HTTP 200 returned without any authentication headers in the request.",
                    risk_explanation="The base API URL responds without requiring credentials. This may be intentional for public APIs.",
                    attacker_impact="Unauthenticated access to API if sensitive data is returned.",
                    business_impact="Verify this endpoint is intentionally public and returns only non-sensitive data.",
                    recommended_fix="If this endpoint should require authentication, add appropriate auth middleware.",
                    fix_priority=5,
                    remediation_effort=RemediationEffort.MEDIUM,
                    confidence="Low",
                    references=["https://owasp.org/www-project-api-security/"],
                    validation_steps="Review whether the endpoint requires authentication based on the data it returns.",
                    category="api",
                )
            )
    return findings


def _looks_like_openapi_json(text: str) -> bool:
    try:
        data = json.loads(text)
        return "openapi" in data or "swagger" in data or "paths" in data
    except Exception:
        return False


def _openapi_has_sensitive_endpoints(text: str) -> bool:
    sensitive_patterns = ["/admin", "/user", "/auth", "/token", "/secret", "/internal", "/private"]
    text_lower = text.lower()
    return any(p in text_lower for p in sensitive_patterns)


def _method_risk(method: str) -> str:
    risks = {
        "TRACE": "HTTP TRACE can be abused in cross-site tracing (XST) attacks to steal HTTP headers including cookies.",
        "DELETE": "HTTP DELETE allows deletion of server-side resources if not properly access-controlled.",
        "PUT": "HTTP PUT allows uploading arbitrary files to the server if not properly restricted.",
        "PATCH": "HTTP PATCH allows partial modification of server resources.",
    }
    return risks.get(method, f"HTTP {method} may allow unintended resource manipulation.")


def _method_impact(method: str) -> str:
    impacts = {
        "TRACE": "An adversary could use TRACE to capture HTTP headers from other users' browsers via JavaScript.",
        "DELETE": "An adversary could delete files or API resources if the endpoint lacks proper authorization checks.",
        "PUT": "An adversary could upload malicious files (e.g., web shells) to accessible directories.",
        "PATCH": "An adversary could modify resource attributes if authorization is not properly enforced.",
    }
    return impacts.get(method, f"Unrestricted {method} access could lead to unauthorized data modification.")


def _method_fix(method: str) -> str:
    if method in ("TRACE", "TRACK"):
        return f"Disable {method} in your web server configuration.\nApache: TraceEnable Off\nNginx: add_header X-Trace-Enabled false (or use limit_except)"
    return f"Ensure {method} requests require proper authentication and authorization before processing."
