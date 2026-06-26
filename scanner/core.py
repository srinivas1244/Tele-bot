"""Scanner orchestrator — coordinates all modules and returns a ScanResult."""
from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

import httpx
import tldextract

import config
from scanner.models import ScanResult, ScanStatus
from scanner.ports import scan_ports
from scanner.headers import check_headers
from scanner.tls import check_tls
from scanner.cookies import check_cookies
from scanner.cors import check_cors
from scanner.files import check_sensitive_files, check_admin_panels, check_directory_listing, check_robots_sitemap
from scanner.cms import detect_cms
from scanner.dependencies import check_dependencies
from scanner.api import check_api_security
from scanner.redirects import check_open_redirects, check_https_redirect
from scanner.web import check_web

logger = logging.getLogger(__name__)


def normalize_target(raw: str) -> tuple[str, str]:
    """
    Normalize the input to a URL and determine target type.
    Returns (normalized_url, target_type).
    """
    raw = raw.strip()

    # If it looks like a bare domain or IP, prepend https://
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError(f"Cannot parse target: {raw}")

    # Determine target type
    ext = tldextract.extract(parsed.netloc)
    if _is_ip(parsed.netloc):
        target_type = "ip"
    elif parsed.path.startswith("/api") or "api" in parsed.netloc:
        target_type = "api"
    else:
        target_type = "website"

    normalized = urlunparse((
        parsed.scheme,
        parsed.netloc.lower(),
        parsed.path,
        parsed.params,
        parsed.query,
        "",
    ))
    return normalized.rstrip("/"), target_type


def _is_ip(host: str) -> bool:
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$")
    return bool(ip_pattern.match(host))


def _build_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(config.HTTP_TIMEOUT),
        follow_redirects=False,
        headers={"User-Agent": config.USER_AGENT},
        verify=False,  # We handle TLS separately for inspection
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
    )


async def run_scan(target: str, user_id: int | None = None) -> ScanResult:
    """
    Full scan pipeline. Returns a populated ScanResult.
    """
    normalized, target_type = normalize_target(target)
    result = ScanResult(
        target=target,
        target_normalized=normalized,
        target_type=target_type,
        requested_by=user_id,
        started_at=datetime.now(timezone.utc),
        status=ScanStatus.RUNNING,
    )

    parsed = urlparse(normalized)
    hostname = parsed.hostname or parsed.netloc

    logger.info("Starting scan: %s (type=%s, user=%s)", normalized, target_type, user_id)

    async with _build_client() as client:
        try:
            # ── Phase 1: Port scan (network layer) ────────────────────────────
            logger.info("[%s] Port scan", hostname)
            port_results, port_findings = await scan_ports(hostname)
            result.ports_checked = config.COMMON_PORTS
            result.open_ports = [r for r in port_results if r.open]
            result.findings.extend(port_findings)

            # ── Phase 2: TLS / HTTPS ─────────────────────────────────────────
            logger.info("[%s] TLS check", hostname)
            cert_info, tls_findings = await check_tls(normalized, client)
            result.certificate = cert_info
            result.findings.extend(tls_findings)

            # Check HTTPS redirect
            redirect_findings = await check_https_redirect(normalized, client)
            result.findings.extend(redirect_findings)

            # ── Phase 3: Security headers ────────────────────────────────────
            logger.info("[%s] Header analysis", hostname)
            header_analyses, header_findings = await check_headers(normalized, client)
            result.headers_analyzed = header_analyses
            result.findings.extend(header_findings)

            # ── Phase 4: Cookie analysis ─────────────────────────────────────
            logger.info("[%s] Cookie analysis", hostname)
            cookie_analyses, cookie_findings = await check_cookies(normalized, client)
            result.cookies_analyzed = cookie_analyses
            result.findings.extend(cookie_findings)

            # ── Phase 5: CORS check ───────────────────────────────────────────
            logger.info("[%s] CORS check", hostname)
            cors_findings = await check_cors(normalized, client)
            result.findings.extend(cors_findings)

            # ── Phase 6: Sensitive files, admin panels, directory listing ─────
            logger.info("[%s] File exposure checks", hostname)
            file_findings, admin_findings, dir_findings, robot_findings = await asyncio.gather(
                check_sensitive_files(normalized, client),
                check_admin_panels(normalized, client),
                check_directory_listing(normalized, client),
                check_robots_sitemap(normalized, client),
            )
            for findings_group in (file_findings, admin_findings, dir_findings, robot_findings):
                result.findings.extend(findings_group)

            # ── Phase 7: CMS and technology detection ─────────────────────────
            logger.info("[%s] CMS detection", hostname)
            cms_name, technologies, cms_findings = await detect_cms(normalized, client)
            result.cms_detected = cms_name
            result.technologies_detected = technologies
            result.findings.extend(cms_findings)

            # ── Phase 8: Frontend dependency CVE check ────────────────────────
            logger.info("[%s] Dependency check", hostname)
            dep_findings = await check_dependencies(normalized, client)
            result.findings.extend(dep_findings)

            # ── Phase 9: API security ─────────────────────────────────────────
            logger.info("[%s] API security check", hostname)
            api_findings = await check_api_security(normalized, client)
            result.findings.extend(api_findings)

            # ── Phase 10: Open redirects ──────────────────────────────────────
            logger.info("[%s] Open redirect check", hostname)
            redirect_findings2 = await check_open_redirects(normalized, client)
            result.findings.extend(redirect_findings2)

            # ── Phase 11: General web checks ─────────────────────────────────
            logger.info("[%s] Web checks", hostname)
            web_findings = await check_web(normalized, client)
            result.findings.extend(web_findings)

        except Exception as exc:
            logger.exception("Scan failed for %s: %s", normalized, exc)
            result.status = ScanStatus.FAILED
            result.error = str(exc)
            result.completed_at = datetime.now(timezone.utc)
            return result

    result.status = ScanStatus.COMPLETED
    result.completed_at = datetime.now(timezone.utc)

    # Deduplicate findings by name + asset
    seen: set[str] = set()
    unique_findings: list = []
    for f in result.findings:
        key = f"{f.name}::{f.affected_asset}"
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    result.findings = unique_findings

    # Build summary
    result.scan_summary = _build_summary(result)
    logger.info(
        "[%s] Scan complete. %d findings (C:%d H:%d M:%d L:%d I:%d)",
        hostname,
        len(result.findings),
        result.critical_count,
        result.high_count,
        result.medium_count,
        result.low_count,
        result.info_count,
    )
    return result


def _build_summary(result: ScanResult) -> str:
    duration = ""
    if result.completed_at and result.started_at:
        secs = int((result.completed_at - result.started_at).total_seconds())
        duration = f" (scan took {secs}s)"

    lines = [
        f"Scan of {result.target_normalized} completed{duration}.",
        f"Risk level: {result.risk_level} | Score: {result.risk_score}",
        f"Findings: {result.critical_count} Critical | {result.high_count} High | "
        f"{result.medium_count} Medium | {result.low_count} Low | {result.info_count} Info",
    ]
    if result.open_ports:
        open_list = ", ".join(f"{p.port}/{p.service}" for p in result.open_ports[:8])
        lines.append(f"Open ports: {open_list}")
    if result.technologies_detected:
        lines.append(f"Technologies: {', '.join(result.technologies_detected[:5])}")
    return "\n".join(lines)
