"""Frontend dependency detection and known-CVE lookup."""
from __future__ import annotations

import re
from typing import List, Optional
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from scanner.models import Finding, RemediationEffort, Severity
from scanner.cve_lookup import lookup_cves


_JS_LIBRARY_PATTERNS: list[dict] = [
    {"name": "jQuery", "pattern": r"jquery[.-]?v?([\d.]+)(\.min)?\.js", "cpe": "jquery:jquery"},
    {"name": "React", "pattern": r"react[.-]?v?([\d.]+)(\.min)?\.js", "cpe": "facebook:react"},
    {"name": "Angular", "pattern": r"angular[.-]?v?([\d.]+)(\.min)?\.js", "cpe": "google:angular.js"},
    {"name": "Vue.js", "pattern": r"vue[.-]?v?([\d.]+)(\.min)?\.js", "cpe": "vuejs:vue"},
    {"name": "Bootstrap", "pattern": r"bootstrap[.-]?v?([\d.]+)(\.min)?\.js", "cpe": "getbootstrap:bootstrap"},
    {"name": "Lodash", "pattern": r"lodash[.-]?v?([\d.]+)(\.min)?\.js", "cpe": "lodash:lodash"},
    {"name": "Moment.js", "pattern": r"moment[.-]?v?([\d.]+)(\.min)?\.js", "cpe": "momentjs:moment"},
    {"name": "Axios", "pattern": r"axios[.-]?v?([\d.]+)(\.min)?\.js", "cpe": "axios:axios"},
    {"name": "D3.js", "pattern": r"d3[.-]?v?([\d.]+)(\.min)?\.js", "cpe": "d3js:d3"},
    {"name": "Underscore.js", "pattern": r"underscore[.-]?v?([\d.]+)(\.min)?\.js", "cpe": "underscorejs:underscore"},
    {"name": "Backbone.js", "pattern": r"backbone[.-]?v?([\d.]+)(\.min)?\.js", "cpe": "backbonejs:backbonejs"},
    {"name": "Ember.js", "pattern": r"ember[.-]?v?([\d.]+)(\.min)?\.js", "cpe": "emberjs:ember.js"},
]

_INLINE_VERSION_PATTERNS: list[dict] = [
    {"name": "jQuery", "pattern": r"jQuery JavaScript Library v([\d.]+)", "cpe": "jquery:jquery"},
    {"name": "jQuery", "pattern": r"jQuery v([\d.]+)", "cpe": "jquery:jquery"},
    {"name": "React", "pattern": r"React v([\d.]+)", "cpe": "facebook:react"},
    {"name": "Angular", "pattern": r"AngularJS v([\d.]+)", "cpe": "google:angular.js"},
    {"name": "Vue.js", "pattern": r"Vue\.js v([\d.]+)", "cpe": "vuejs:vue"},
    {"name": "Bootstrap", "pattern": r"Bootstrap v([\d.]+)", "cpe": "getbootstrap:bootstrap"},
    {"name": "Lodash", "pattern": r"lodash v([\d.]+)", "cpe": "lodash:lodash"},
]


async def check_dependencies(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    """Detect frontend libraries and check for known CVEs."""
    findings: list[Finding] = []

    try:
        resp = await client.get(base_url, follow_redirects=True, timeout=12)
    except Exception:
        return []

    html = resp.text
    soup = BeautifulSoup(html, "html.parser")

    detected: dict[str, tuple[str, str]] = {}  # name -> (version, cpe)

    # ── Script src patterns ───────────────────────────────────────────────────
    for tag in soup.find_all("script", src=True):
        src = tag.get("src", "")
        for lib in _JS_LIBRARY_PATTERNS:
            m = re.search(lib["pattern"], src, re.IGNORECASE)
            if m:
                version = m.group(1)
                key = lib["name"]
                if key not in detected:
                    detected[key] = (version, lib["cpe"])

    # ── Inline meta generator ─────────────────────────────────────────────────
    meta_gen = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
    if meta_gen:
        content = meta_gen.get("content", "")
        for lib in _INLINE_VERSION_PATTERNS:
            m = re.search(lib["pattern"], content, re.IGNORECASE)
            if m:
                key = lib["name"]
                if key not in detected:
                    detected[key] = (m.group(1), lib["cpe"])

    # ── Inline script content ─────────────────────────────────────────────────
    for script in soup.find_all("script", src=False):
        script_text = script.get_text()[:2000]
        for lib in _INLINE_VERSION_PATTERNS:
            m = re.search(lib["pattern"], script_text, re.IGNORECASE)
            if m:
                key = lib["name"]
                if key not in detected:
                    detected[key] = (m.group(1), lib["cpe"])

    # ── CVE lookup for detected libraries ────────────────────────────────────
    for lib_name, (version, cpe) in detected.items():
        cves = await lookup_cves(lib_name, version)
        if cves:
            high_cves = [c for c in cves if c.get("score", 0) >= 7.0]
            all_cve_ids = [c["id"] for c in cves]
            severity = Severity.HIGH if high_cves else Severity.MEDIUM

            findings.append(
                Finding(
                    name=f"Vulnerable Frontend Library: {lib_name} {version}",
                    severity=severity,
                    affected_asset=base_url,
                    evidence=(
                        f"Detected {lib_name} version {version}.\n"
                        f"Known CVEs: {', '.join(all_cve_ids[:5])}"
                    ),
                    risk_explanation=(
                        f"{lib_name} {version} has {len(cves)} known CVE(s). "
                        f"Outdated libraries are a common source of exploitable vulnerabilities."
                    ),
                    attacker_impact=(
                        f"An adversary can exploit CVE-specific weaknesses in {lib_name} {version} "
                        "such as XSS, prototype pollution, or ReDoS, depending on the specific CVEs."
                    ),
                    business_impact=f"Known CVEs in {lib_name} may enable client-side attacks against all site visitors.",
                    recommended_fix=(
                        f"Upgrade {lib_name} to the latest stable version. "
                        "Remove unused libraries. Audit all third-party JavaScript dependencies regularly."
                    ),
                    fix_priority=2,
                    remediation_effort=RemediationEffort.MEDIUM,
                    confidence="High",
                    references=[f"https://nvd.nist.gov/products/cpe/search?keyword={lib_name}"] + [c.get("url", "") for c in cves[:3]],
                    validation_steps=f"After upgrading, re-run dependency scan and confirm no CVEs are returned for the new version.",
                    category="dependencies",
                    raw_data={"library": lib_name, "version": version, "cves": cves},
                )
            )
        else:
            # Detected but no known CVEs — informational
            findings.append(
                Finding(
                    name=f"Frontend Library Detected: {lib_name} {version}",
                    severity=Severity.INFORMATIONAL,
                    affected_asset=base_url,
                    evidence=f"Detected {lib_name} version {version} in page source.",
                    risk_explanation="No known CVEs detected for this version at scan time. Keep monitoring for new disclosures.",
                    attacker_impact="No immediate known impact. Monitor for future vulnerability disclosures.",
                    business_impact="Outdated libraries may become vulnerable; maintain a dependency update schedule.",
                    recommended_fix=f"Keep {lib_name} updated to the latest stable version.",
                    fix_priority=5,
                    remediation_effort=RemediationEffort.LOW,
                    confidence="High",
                    references=[],
                    validation_steps="",
                    category="dependencies",
                    raw_data={"library": lib_name, "version": version},
                )
            )

    return findings
