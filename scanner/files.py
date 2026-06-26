"""Exposed sensitive file and directory listing detection."""
from __future__ import annotations

import asyncio
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from config import ADMIN_PATHS, SENSITIVE_FILES
from scanner.models import Finding, RemediationEffort, Severity


async def check_sensitive_files(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    """Check for publicly accessible sensitive files."""
    findings: list[Finding] = []
    semaphore = asyncio.Semaphore(5)

    async def probe(path: str) -> Finding | None:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        async with semaphore:
            try:
                resp = await client.get(url, follow_redirects=False, timeout=8)
            except Exception:
                return None
        if resp.status_code not in (200, 206):
            return None
        ct = resp.headers.get("content-type", "").lower()
        # Avoid flagging HTML pages that just redirect to login
        if _is_auth_redirect(resp):
            return None
        return _make_finding(path, url, resp.status_code, ct, resp.text[:300])

    tasks = [probe(f) for f in SENSITIVE_FILES]
    results = await asyncio.gather(*tasks)
    findings.extend(f for f in results if f is not None)

    return findings


async def check_admin_panels(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    """Probe known admin panel paths."""
    findings: list[Finding] = []
    semaphore = asyncio.Semaphore(5)

    async def probe(path: str) -> Finding | None:
        url = urljoin(base_url.rstrip("/"), path)
        async with semaphore:
            try:
                resp = await client.get(url, follow_redirects=False, timeout=8)
            except Exception:
                return None
        if resp.status_code not in (200, 206):
            return None
        if _is_auth_redirect(resp):
            # Admin panel exists but requires login — still worth noting
            return Finding(
                name=f"Admin Panel Detected (Login Required): {path}",
                severity=Severity.MEDIUM,
                affected_asset=url,
                evidence=f"HTTP {resp.status_code} returned at {url} (login page detected).",
                risk_explanation="An admin interface is publicly reachable, exposing it to brute-force and credential stuffing.",
                attacker_impact=(
                    "Adversaries can attempt automated credential guessing against the admin "
                    "login page, which may succeed if weak or default credentials are in use."
                ),
                business_impact="Admin interfaces should not be publicly accessible from the internet.",
                recommended_fix=(
                    "Restrict admin panel access to trusted IP ranges via firewall or VPN. "
                    "Implement MFA on all admin accounts. Monitor for brute-force attempts."
                ),
                fix_priority=2,
                remediation_effort=RemediationEffort.MEDIUM,
                confidence="Medium",
                references=["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"],
                validation_steps="After restricting access, confirm the admin URL returns 403 or is unreachable from external IPs.",
                category="files",
            )
        return Finding(
            name=f"Exposed Admin Panel (No Auth Required): {path}",
            severity=Severity.HIGH,
            affected_asset=url,
            evidence=f"HTTP {resp.status_code} at {url} — no authentication challenge observed.",
            risk_explanation="An admin panel is accessible without credentials from the public internet.",
            attacker_impact=(
                "An adversary can access administrative functionality directly, potentially "
                "managing users, content, configuration, or server state without any credentials."
            ),
            business_impact="Complete administrative compromise of the application may be possible.",
            recommended_fix=(
                "Immediately restrict access to this admin panel. Require strong authentication "
                "and limit access to internal/VPN IPs only."
            ),
            fix_priority=1,
            remediation_effort=RemediationEffort.MEDIUM,
            confidence="High",
            references=["https://owasp.org/www-project-top-ten/"],
            validation_steps="Confirm admin path is inaccessible from external IPs after applying firewall restrictions.",
            category="files",
        )

    tasks = [probe(p) for p in ADMIN_PATHS]
    results = await asyncio.gather(*tasks)
    findings.extend(f for f in results if f is not None)
    return findings


async def check_directory_listing(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    """Detect open directory listing on common paths."""
    findings: list[Finding] = []
    paths_to_check = ["/", "/images/", "/uploads/", "/static/", "/assets/", "/files/", "/backup/", "/logs/"]
    semaphore = asyncio.Semaphore(5)

    async def probe(path: str) -> Finding | None:
        url = urljoin(base_url.rstrip("/"), path)
        async with semaphore:
            try:
                resp = await client.get(url, follow_redirects=True, timeout=8)
            except Exception:
                return None
        if resp.status_code != 200:
            return None
        if _is_directory_listing(resp.text):
            return Finding(
                name=f"Directory Listing Enabled: {path}",
                severity=Severity.HIGH if path in ("/backup/", "/logs/", "/uploads/") else Severity.MEDIUM,
                affected_asset=url,
                evidence=f"Directory index page detected at {url}.",
                risk_explanation=(
                    "Directory listing reveals the file structure of the web server, "
                    "exposing configuration files, backups, and source code."
                ),
                attacker_impact=(
                    "An adversary can browse all files in this directory, potentially "
                    "discovering sensitive files such as backups, credentials, or source code "
                    "that were not intended to be public."
                ),
                business_impact="Unintended disclosure of internal file structure and potentially sensitive files.",
                recommended_fix=(
                    "Disable directory listing in your web server configuration.\n"
                    "Apache: Add 'Options -Indexes' to your .htaccess or virtual host config.\n"
                    "Nginx: Remove 'autoindex on' from your location block."
                ),
                fix_priority=2,
                remediation_effort=RemediationEffort.LOW,
                confidence="High",
                references=["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"],
                validation_steps=f"After disabling directory listing, request {url} and confirm it returns 403 or a custom page.",
                category="files",
            )
        return None

    tasks = [probe(p) for p in paths_to_check]
    results = await asyncio.gather(*tasks)
    findings.extend(f for f in results if f is not None)
    return findings


async def check_robots_sitemap(base_url: str, client: httpx.AsyncClient) -> list[Finding]:
    """Retrieve robots.txt and sitemap.xml for informational paths."""
    findings: list[Finding] = []

    for path in ["/robots.txt", "/sitemap.xml"]:
        url = urljoin(base_url.rstrip("/"), path)
        try:
            resp = await client.get(url, follow_redirects=True, timeout=8)
        except Exception:
            continue
        if resp.status_code != 200:
            continue

        content_preview = resp.text[:500]
        findings.append(
            Finding(
                name=f"{'robots.txt' if 'robots' in path else 'sitemap.xml'} Accessible",
                severity=Severity.INFORMATIONAL,
                affected_asset=url,
                evidence=f"HTTP 200 at {url}.\nPreview:\n{content_preview}",
                risk_explanation=(
                    "robots.txt and sitemap.xml may reveal interesting internal paths, "
                    "admin areas, or content that was intended to be hidden from search engines."
                ),
                attacker_impact=(
                    "An adversary can use these files to discover paths that the owner "
                    "intended to exclude from search engines, which may include admin areas "
                    "or sensitive resources."
                ),
                business_impact="Minor information disclosure; useful for reconnaissance.",
                recommended_fix=(
                    "Review the paths disclosed in these files. Avoid listing sensitive "
                    "paths in robots.txt — security through obscurity is not effective, "
                    "and the Disallow entries are publicly readable."
                ),
                fix_priority=5,
                remediation_effort=RemediationEffort.LOW,
                confidence="High",
                references=["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage"],
                validation_steps="Review paths listed and ensure none expose sensitive resources.",
                category="files",
            )
        )
    return findings


def _is_directory_listing(html: str) -> bool:
    indicators = [
        "index of /",
        "parent directory",
        "<title>directory listing",
        "directory listing for",
    ]
    lower = html.lower()
    return any(ind in lower for ind in indicators)


def _is_auth_redirect(resp: httpx.Response) -> bool:
    """Detect if a 200 response is actually a login redirect disguised as 200."""
    if resp.status_code in (301, 302, 303, 307, 308):
        loc = resp.headers.get("location", "").lower()
        return "login" in loc or "signin" in loc or "auth" in loc
    content_lower = resp.text.lower()[:500]
    return "login" in content_lower and "password" in content_lower


def _make_finding(path: str, url: str, status: int, content_type: str, preview: str) -> Finding:
    """Create a finding for an exposed sensitive file."""
    is_critical = any(kw in path.lower() for kw in [".env", "wp-config", "database", ".sql", "dump", ".git"])
    severity = Severity.CRITICAL if is_critical else Severity.HIGH

    return Finding(
        name=f"Exposed Sensitive File: {path}",
        severity=severity,
        affected_asset=url,
        evidence=f"HTTP {status} — Content-Type: {content_type}\nPreview: {preview[:200]}",
        risk_explanation=f"The file '{path}' is publicly accessible and may contain credentials, configuration, or source code.",
        attacker_impact=(
            "An adversary can download this file and extract credentials, database connection "
            "strings, API keys, or other sensitive configuration that could enable broader compromise."
        ),
        business_impact=(
            "Exposure of credentials or configuration can lead to full application or "
            "infrastructure compromise, data breach, and regulatory penalties."
        ),
        recommended_fix=(
            f"Immediately remove or restrict access to '{path}'.\n"
            "If it contains credentials, rotate all exposed secrets immediately.\n"
            "Use .htaccess or nginx deny rules to block access to sensitive file patterns."
        ),
        fix_priority=1,
        remediation_effort=RemediationEffort.LOW,
        confidence="High",
        references=[
            "https://owasp.org/www-project-top-ten/",
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        ],
        validation_steps=f"After removal/restriction, confirm {url} returns 403 or 404.",
        category="files",
    )
