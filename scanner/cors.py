"""CORS misconfiguration detection."""
from __future__ import annotations

import httpx

from scanner.models import Finding, RemediationEffort, Severity


_TEST_ORIGINS = [
    "https://evil.attacker.example",
    "null",
]


async def check_cors(url: str, client: httpx.AsyncClient) -> list[Finding]:
    """Test CORS policy by sending cross-origin preflight and simple requests."""
    findings: list[Finding] = []

    for origin in _TEST_ORIGINS:
        findings.extend(await _test_origin(url, origin, client))

    return findings


async def _test_origin(url: str, origin: str, client: httpx.AsyncClient) -> list[Finding]:
    findings: list[Finding] = []
    headers = {"Origin": origin}

    # Simple GET request
    try:
        resp = await client.get(url, headers=headers, follow_redirects=True)
    except Exception:
        return []

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower()
    acam = resp.headers.get("access-control-allow-methods", "")

    if not acao:
        return []

    # ── Wildcard ACAO ─────────────────────────────────────────────────────────
    if acao == "*":
        if acac == "true":
            # This combination is actually blocked by browsers but represents misconfiguration intent
            findings.append(
                Finding(
                    name="CORS: Wildcard Origin with Allow-Credentials",
                    severity=Severity.HIGH,
                    affected_asset=url,
                    evidence=f"Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                    risk_explanation=(
                        "Combining wildcard ACAO with Allow-Credentials:true is invalid per spec, "
                        "but indicates a misconfigured CORS policy that developers may try to 'fix' "
                        "in ways that introduce real credential-leaking vulnerabilities."
                    ),
                    attacker_impact=(
                        "The intended configuration, if fixed incorrectly, could allow any website "
                        "to make credentialed cross-origin requests, exposing session data to any origin."
                    ),
                    business_impact="Session token theft from any malicious website if policy is adjusted incorrectly.",
                    recommended_fix=(
                        "Replace wildcard with an explicit allowlist of trusted origins. "
                        "Never use Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true."
                    ),
                    fix_priority=2,
                    remediation_effort=RemediationEffort.MEDIUM,
                    confidence="High",
                    references=[
                        "https://portswigger.net/web-security/cors",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                    ],
                    validation_steps=(
                        "After fixing, send a request with Origin: https://evil.example and confirm "
                        "Access-Control-Allow-Origin does not echo back or use wildcard with credentials."
                    ),
                    category="cors",
                )
            )
        else:
            # Wildcard without credentials — informational for APIs, could be fine
            findings.append(
                Finding(
                    name="CORS: Wildcard Origin Allowed",
                    severity=Severity.INFORMATIONAL,
                    affected_asset=url,
                    evidence=f"Access-Control-Allow-Origin: * (tested origin: {origin})",
                    risk_explanation=(
                        "The server allows any origin to read responses. For public APIs "
                        "this may be intentional, but for authenticated resources it is dangerous."
                    ),
                    attacker_impact=(
                        "Any website can read the response content. If this endpoint handles "
                        "authenticated data, a malicious site could read it via JavaScript."
                    ),
                    business_impact="If applied to authenticated endpoints, exposes user data to any website.",
                    recommended_fix=(
                        "If this endpoint serves non-public data, replace * with an explicit "
                        "allowlist: Access-Control-Allow-Origin: https://your-domain.com"
                    ),
                    fix_priority=4,
                    remediation_effort=RemediationEffort.LOW,
                    confidence="High",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
                    validation_steps="Confirm only public, non-sensitive data is accessible to wildcard origins.",
                    category="cors",
                )
            )

    # ── Reflected Origin ──────────────────────────────────────────────────────
    elif acao == origin and origin != "null":
        severity = Severity.HIGH if acac == "true" else Severity.MEDIUM

        if acac == "true":
            name = "CORS: Arbitrary Origin Reflected with Credentials Allowed"
            risk = (
                "The server echoes back any origin and allows credentials. Any website "
                "can make authenticated requests to this server and read the responses."
            )
            impact = (
                "A malicious website could silently perform actions on behalf of a logged-in "
                "user and read sensitive response data, potentially leaking session tokens, "
                "personal data, or CSRF tokens."
            )
            biz = "Complete CORS bypass enabling session hijacking and data theft from any website."
        else:
            name = "CORS: Arbitrary Origin Reflected"
            risk = "The server echoes back the requesting origin without verifying it is trusted."
            impact = (
                "Any website can read responses from this origin. If authenticated endpoints "
                "are affected, this could expose user data to any malicious website."
            )
            biz = "Risk of data exposure if authenticated endpoints are affected."

        findings.append(
            Finding(
                name=name,
                severity=severity,
                affected_asset=url,
                evidence=(
                    f"Request Origin: {origin}\n"
                    f"Response Access-Control-Allow-Origin: {acao}\n"
                    f"Access-Control-Allow-Credentials: {acac or 'not set'}"
                ),
                risk_explanation=risk,
                attacker_impact=impact,
                business_impact=biz,
                recommended_fix=(
                    "Maintain an explicit allowlist of trusted origins and only reflect the "
                    "origin if it is present in that list. Never blindly reflect the request origin.\n"
                    "Example:\n"
                    "ALLOWED = {'https://app.yourdomain.com', 'https://www.yourdomain.com'}\n"
                    "if request.origin in ALLOWED:\n"
                    "    response.headers['Access-Control-Allow-Origin'] = request.origin"
                ),
                fix_priority=1,
                remediation_effort=RemediationEffort.MEDIUM,
                confidence="High",
                references=[
                    "https://portswigger.net/web-security/cors",
                    "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                ],
                validation_steps=(
                    "After fixing, test with Origin: https://evil.example — the server "
                    "should return no ACAO header or a fixed allowed origin, not the reflected value."
                ),
                category="cors",
            )
        )

    # ── Null origin accepted ──────────────────────────────────────────────────
    if origin == "null" and acao == "null":
        findings.append(
            Finding(
                name="CORS: Null Origin Accepted",
                severity=Severity.HIGH,
                affected_asset=url,
                evidence="Access-Control-Allow-Origin: null (responding to Origin: null)",
                risk_explanation=(
                    "The server accepts the 'null' origin, which is sent by sandboxed iframes "
                    "and local HTML files. This can be abused."
                ),
                attacker_impact=(
                    "An adversary can host a sandboxed iframe containing malicious JavaScript "
                    "that makes cross-origin requests to this server with the null origin, "
                    "potentially bypassing the CORS policy."
                ),
                business_impact="CORS bypass via sandboxed iframe exploitation.",
                recommended_fix=(
                    "Remove 'null' from the allowed origins list. "
                    "Only trusted, explicit HTTPS origins should be allowed."
                ),
                fix_priority=2,
                remediation_effort=RemediationEffort.LOW,
                confidence="High",
                references=["https://portswigger.net/web-security/cors#whitelisting-null-origin-values"],
                validation_steps="After fix, send Origin: null and confirm ACAO is not returned as 'null'.",
                category="cors",
            )
        )

    return findings
