"""Safe open redirect detection using harmless test values."""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

import httpx

from scanner.models import Finding, RemediationEffort, Severity

# Safe, non-malicious indicator domains that clearly signal redirect vulnerability
# (no actual domains that could be mistaken for real targets)
_SAFE_INDICATOR = "open-redirect-test-indicator.invalid"

_REDIRECT_PARAMS = ["url", "redirect", "redirect_to", "redirectUrl", "return",
                     "returnUrl", "return_url", "next", "goto", "target",
                     "destination", "dest", "forward", "location", "continue",
                     "callback", "back", "ref", "referer", "referrer"]

_SAFE_TEST_VALUE = f"https://{_SAFE_INDICATOR}/safe-test"


async def check_open_redirects(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    """
    Test common redirect parameter names with a safe, non-malicious value.
    Flags if the response Location header or body contains the indicator domain.
    """
    findings: list[Finding] = []
    tested: set[str] = set()

    for param in _REDIRECT_PARAMS:
        test_url = f"{base_url.rstrip('/')}/?{param}={_SAFE_TEST_VALUE}"
        if test_url in tested:
            continue
        tested.add(test_url)

        try:
            resp = await client.get(test_url, follow_redirects=False, timeout=8)
        except Exception:
            continue

        if resp.status_code not in (301, 302, 303, 307, 308):
            continue

        location = resp.headers.get("location", "")
        if _SAFE_INDICATOR in location:
            findings.append(
                Finding(
                    name=f"Open Redirect via Parameter: '{param}'",
                    severity=Severity.HIGH,
                    affected_asset=test_url,
                    evidence=(
                        f"Request: GET {test_url}\n"
                        f"Response: HTTP {resp.status_code}\n"
                        f"Location: {location}"
                    ),
                    risk_explanation=(
                        f"The '{param}' parameter accepts an external URL and redirects "
                        "the user to it without validation. This is an open redirect."
                    ),
                    attacker_impact=(
                        "An adversary can craft a link that appears to originate from your "
                        "trusted domain but redirects visitors to a malicious or phishing site. "
                        "Users may trust the link because it starts with your domain name."
                    ),
                    business_impact=(
                        "Open redirects are used in phishing campaigns. If abused, they can "
                        "damage brand reputation and expose users to credential theft."
                    ),
                    recommended_fix=(
                        f"Validate the '{param}' value against an allowlist of trusted paths or domains.\n"
                        "Prefer relative paths over absolute URLs for internal redirects.\n"
                        "Example (Python): if not is_safe_redirect(url): url = '/'\n"
                        "Never accept raw external URLs as redirect destinations."
                    ),
                    fix_priority=2,
                    remediation_effort=RemediationEffort.MEDIUM,
                    confidence="High",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                    ],
                    validation_steps=(
                        f"After fixing, re-test: GET {test_url} and confirm the "
                        f"Location header does not contain an external domain."
                    ),
                    category="redirects",
                )
            )

    return findings


async def check_https_redirect(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    """Verify that HTTP redirects to HTTPS."""
    parsed = urlparse(base_url)
    if parsed.scheme == "https":
        http_url = base_url.replace("https://", "http://", 1)
    else:
        return []

    try:
        resp = await client.get(http_url, follow_redirects=False, timeout=8)
    except Exception:
        return []

    if resp.status_code in (301, 302, 307, 308):
        location = resp.headers.get("location", "")
        if location.startswith("https://"):
            return []  # Correct redirect

    return [
        Finding(
            name="HTTP Does Not Redirect to HTTPS",
            severity=Severity.HIGH,
            affected_asset=http_url,
            evidence=f"GET {http_url} → HTTP {resp.status_code} (no HTTPS redirect).",
            risk_explanation="Visitors accessing the site over plain HTTP receive content without being redirected to the secure HTTPS version.",
            attacker_impact=(
                "Network observers can read and potentially modify all data exchanged "
                "between the user and the server, including form submissions and session tokens."
            ),
            business_impact="Fails security compliance requirements; exposes user data on all non-HTTPS connections.",
            recommended_fix=(
                "Configure a permanent 301 redirect from HTTP to HTTPS.\n"
                "Apache: Redirect permanent / https://yourdomain.com/\n"
                "Nginx: return 301 https://$host$request_uri;\n"
                "Also add: Strict-Transport-Security header to prevent future plain HTTP."
            ),
            fix_priority=1,
            remediation_effort=RemediationEffort.LOW,
            confidence="High",
            references=["https://letsencrypt.org/", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
            validation_steps=f"After fix, confirm: curl -I {http_url} returns HTTP 301 to the HTTPS URL.",
            category="redirects",
        )
    ]
