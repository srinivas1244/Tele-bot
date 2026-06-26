"""Safe TCP port check — connect-only, no SYN/UDP/stealth scanning."""
from __future__ import annotations

import asyncio
import logging
from typing import List

from config import COMMON_PORTS, PORT_RISKS, PORT_SCAN_TIMEOUT, PORT_SERVICES
from scanner.models import Finding, PortResult, RemediationEffort, Severity

logger = logging.getLogger(__name__)


async def _check_port(host: str, port: int) -> PortResult:
    """Attempt a single TCP connect; returns PortResult."""
    try:
        future = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(future, timeout=PORT_SCAN_TIMEOUT)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return PortResult(
            port=port,
            open=True,
            service=PORT_SERVICES.get(port, "Unknown"),
            risk=PORT_RISKS.get(port, ""),
        )
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return PortResult(port=port, open=False, service=PORT_SERVICES.get(port, ""))


async def scan_ports(host: str) -> tuple[list[PortResult], list[Finding]]:
    """
    Scan COMMON_PORTS concurrently with capped concurrency.
    Returns (all_results, findings_for_open_ports).
    """
    semaphore = asyncio.Semaphore(10)

    async def bounded_check(port: int) -> PortResult:
        async with semaphore:
            return await _check_port(host, port)

    tasks = [bounded_check(p) for p in COMMON_PORTS]
    results: list[PortResult] = await asyncio.gather(*tasks)

    findings: list[Finding] = []
    for r in results:
        if not r.open:
            continue
        severity, priority = _classify_port(r.port)
        findings.append(
            Finding(
                name=f"Open Port: {r.port}/{r.service}",
                severity=severity,
                affected_asset=f"{host}:{r.port}",
                evidence=f"TCP connection established to port {r.port} ({r.service}).",
                risk_explanation=r.risk or f"Port {r.port} is publicly reachable.",
                attacker_impact=_attacker_impact(r.port),
                business_impact=_business_impact(r.port),
                recommended_fix=_remediation(r.port),
                fix_priority=priority,
                remediation_effort=RemediationEffort.MEDIUM,
                confidence="High",
                references=[
                    "https://www.cisecurity.org/controls/",
                    "https://nvd.nist.gov/",
                ],
                validation_steps=(
                    f"After applying firewall rules, re-run the port scan and "
                    f"confirm port {r.port} is no longer reachable from the internet."
                ),
                category="ports",
                raw_data=r.model_dump(),
            )
        )

    return results, findings


def _classify_port(port: int) -> tuple[Severity, int]:
    """Map port to severity and fix priority."""
    critical_ports = {6379, 9200}       # Redis, Elasticsearch — no auth by default
    high_ports = {3306, 5432, 21}        # MySQL, PostgreSQL, FTP
    medium_ports = {22, 25, 8080, 8443}
    low_ports = {80, 443}

    if port in critical_ports:
        return Severity.CRITICAL, 1
    if port in high_ports:
        return Severity.HIGH, 2
    if port in medium_ports:
        return Severity.MEDIUM, 3
    if port in low_ports:
        return Severity.INFORMATIONAL, 5
    return Severity.LOW, 4


def _attacker_impact(port: int) -> str:
    impacts = {
        6379: (
            "If Redis is accessible without authentication, an adversary can read or "
            "overwrite all cached data, potentially including session tokens or sensitive "
            "application state, without any credentials."
        ),
        9200: (
            "Unauthenticated Elasticsearch access allows an adversary to read, modify, "
            "or delete all indexed data, which may contain personal or business-critical records."
        ),
        3306: (
            "An internet-exposed MySQL port allows adversaries to attempt credential "
            "guessing against the database directly, bypassing application-layer controls."
        ),
        5432: (
            "An internet-exposed PostgreSQL port allows adversaries to attempt credential "
            "guessing and may expose the database to known service vulnerabilities."
        ),
        21: (
            "FTP transmits credentials and data in plaintext. An adversary on the network "
            "path can intercept login credentials and transferred files."
        ),
        22: (
            "An internet-exposed SSH port is a common target for automated credential "
            "guessing. Weak passwords or unpatched versions may allow unauthorized shell access."
        ),
        25: (
            "An open SMTP port may be used for email relay abuse if misconfigured, "
            "enabling spam campaigns that could damage the domain's email reputation."
        ),
        8080: (
            "An alternative HTTP port may expose development or staging interfaces "
            "that lack production-level security controls."
        ),
    }
    return impacts.get(
        port,
        f"An open port {port} increases the attack surface. Adversaries may probe it "
        "for known service vulnerabilities or exploit weak credentials.",
    )


def _business_impact(port: int) -> str:
    business = {
        6379: "Potential full data breach of cached application data; regulatory exposure.",
        9200: "Potential full data breach of search index contents; GDPR/HIPAA implications.",
        3306: "Risk of unauthorized database access leading to data exfiltration or corruption.",
        5432: "Risk of unauthorized database access and potential data breach.",
        21: "Risk of data interception during file transfers; credential theft.",
        22: "Risk of complete server compromise if SSH credentials are weak or keys are stolen.",
        25: "Risk of domain blacklisting and email deliverability issues from relay abuse.",
        8080: "Risk of exposing internal or development resources to the public internet.",
    }
    return business.get(
        port,
        "Increased attack surface may contribute to unauthorized access or data exposure.",
    )


def _remediation(port: int) -> str:
    fixes = {
        6379: "Bind Redis to 127.0.0.1, enable requirepass authentication, and block port 6379 in the firewall.",
        9200: "Restrict Elasticsearch to localhost or a private network; enable X-Pack security with TLS and authentication.",
        3306: "Restrict MySQL to localhost or a private VPC subnet; never expose on the public internet.",
        5432: "Restrict PostgreSQL to localhost or a private VPC subnet; use pg_hba.conf for access control.",
        21: "Disable FTP and migrate to SFTP (port 22) or FTPS. Block port 21 at the firewall.",
        22: "Restrict SSH access to known IP ranges via firewall rules; disable password authentication; use key-based auth only.",
        25: "Configure SPF, DKIM, DMARC; restrict SMTP relay to authenticated users only.",
        8080: "If not required, close port 8080 at the firewall. If required, apply the same security controls as port 80/443.",
    }
    return fixes.get(
        port,
        f"Review whether port {port} needs to be publicly accessible. "
        "If not, block it at the firewall/security-group level.",
    )
