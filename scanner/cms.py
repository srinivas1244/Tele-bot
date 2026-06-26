"""CMS and web framework detection via safe passive fingerprinting."""
from __future__ import annotations

import re
from typing import Optional

import httpx
from bs4 import BeautifulSoup

from scanner.models import Finding, RemediationEffort, Severity


_CMS_SIGNATURES: list[dict] = [
    {
        "name": "WordPress",
        "patterns": [
            r"/wp-content/", r"/wp-includes/", r"wp-json",
            r'name="generator" content="WordPress',
        ],
        "version_pattern": r'WordPress (\d+\.\d+[\.\d]*)',
        "admin_path": "/wp-admin/",
    },
    {
        "name": "Drupal",
        "patterns": [
            r"/sites/default/files/", r"Drupal.settings",
            r'name="Generator" content="Drupal',
            r"/misc/drupal.js",
        ],
        "version_pattern": r'Drupal (\d+\.\d+)',
        "admin_path": "/admin/",
    },
    {
        "name": "Joomla",
        "patterns": [
            r"/components/com_", r"/modules/mod_",
            r'name="generator" content="Joomla',
        ],
        "version_pattern": r'Joomla! (\d+\.\d+)',
        "admin_path": "/administrator/",
    },
    {
        "name": "Magento",
        "patterns": [r"/skin/frontend/", r"Mage.Cookies", r"/mage/"],
        "version_pattern": r'Magento[\s/](\d+\.\d+)',
        "admin_path": None,
    },
    {
        "name": "Shopify",
        "patterns": [r"cdn\.shopify\.com", r"Shopify\.theme"],
        "version_pattern": None,
        "admin_path": None,
    },
    {
        "name": "Django",
        "patterns": [r'csrfmiddlewaretoken', r"django"],
        "version_pattern": r'Django/(\d+\.\d+)',
        "admin_path": "/admin/",
    },
    {
        "name": "Laravel",
        "patterns": [r"laravel_session", r'XSRF-TOKEN'],
        "version_pattern": r'Laravel v?(\d+\.\d+)',
        "admin_path": None,
    },
    {
        "name": "Ruby on Rails",
        "patterns": [r"rails", r"_rails_", r"X-Request-Id"],
        "version_pattern": r'Rails/(\d+\.\d+)',
        "admin_path": None,
    },
]

_FRAMEWORK_HEADERS: dict[str, str] = {
    "x-powered-by": "Technology",
    "x-aspnet-version": "ASP.NET",
    "x-aspnetmvc-version": "ASP.NET MVC",
    "x-generator": "Generator",
    "x-drupal-cache": "Drupal",
    "x-wp-total": "WordPress",
}


async def detect_cms(url: str, client: httpx.AsyncClient) -> tuple[Optional[str], list[str], list[Finding]]:
    """
    Returns (cms_name, technologies_list, findings).
    """
    try:
        resp = await client.get(url, follow_redirects=True, timeout=12)
    except Exception:
        return None, [], []

    html = resp.text
    response_headers = {k.lower(): v for k, v in resp.headers.items()}
    technologies: list[str] = []
    findings: list[Finding] = []
    detected_cms: Optional[str] = None

    # ── CMS fingerprinting ────────────────────────────────────────────────────
    for cms in _CMS_SIGNATURES:
        matched = any(re.search(p, html, re.IGNORECASE) for p in cms["patterns"])
        if not matched:
            matched = any(re.search(p, str(resp.headers), re.IGNORECASE) for p in cms["patterns"])
        if not matched:
            continue

        detected_cms = cms["name"]
        technologies.append(cms["name"])

        version: Optional[str] = None
        if cms["version_pattern"]:
            m = re.search(cms["version_pattern"], html, re.IGNORECASE)
            if m:
                version = m.group(1)

        if version:
            findings.append(
                Finding(
                    name=f"CMS Version Disclosed: {cms['name']} {version}",
                    severity=Severity.MEDIUM,
                    affected_asset=url,
                    evidence=f"CMS '{cms['name']}' version '{version}' detected in page source.",
                    risk_explanation=(
                        f"The exact version of {cms['name']} is visible in the HTML source. "
                        "This allows adversaries to quickly identify applicable CVEs."
                    ),
                    attacker_impact=(
                        f"An adversary can search NVD/ExploitDB for CVEs affecting "
                        f"{cms['name']} {version} and attempt applicable exploits."
                    ),
                    business_impact="Precise version disclosure reduces the effort required for targeted attacks.",
                    recommended_fix=(
                        f"Remove the version meta tag from {cms['name']} output. "
                        f"In WordPress: remove the generator meta tag via functions.php. "
                        f"Keep {cms['name']} updated to the latest stable version."
                    ),
                    fix_priority=3,
                    remediation_effort=RemediationEffort.LOW,
                    confidence="High",
                    references=[
                        f"https://nvd.nist.gov/products/cpe/search?keyword={cms['name']}",
                    ],
                    validation_steps=f"After removing version disclosure, reload page and confirm version string is absent.",
                    category="cms",
                )
            )
        else:
            technologies_entry = f"{cms['name']} (version not disclosed)"
            if technologies_entry not in technologies:
                technologies.append(technologies_entry)

        break  # Only report primary CMS

    # ── Header-based technology detection ────────────────────────────────────
    for header, tech_name in _FRAMEWORK_HEADERS.items():
        val = response_headers.get(header)
        if val and tech_name not in technologies:
            technologies.append(f"{tech_name}: {val}")
            version_match = re.search(r"(\d+\.\d+[\.\d]*)", val)
            if version_match:
                findings.append(
                    Finding(
                        name=f"Framework Version Disclosed via Header: {header}",
                        severity=Severity.MEDIUM,
                        affected_asset=url,
                        evidence=f"{header}: {val}",
                        risk_explanation=f"The '{header}' header reveals the server-side framework and version.",
                        attacker_impact=(
                            "Version information enables targeted CVE lookups without any further probing."
                        ),
                        business_impact="Reduces adversary effort for vulnerability research.",
                        recommended_fix=f"Suppress the '{header}' header in your web server or framework configuration.",
                        fix_priority=3,
                        remediation_effort=RemediationEffort.LOW,
                        confidence="High",
                        references=["https://owasp.org/www-project-secure-headers/"],
                        validation_steps=f"After fix, confirm '{header}' is absent in response headers.",
                        category="cms",
                    )
                )

    # ── Server header fingerprinting ─────────────────────────────────────────
    server = response_headers.get("server", "")
    if server:
        technologies.append(f"Server: {server}")

    return detected_cms, list(set(technologies)), findings
