"""SSL/TLS certificate and configuration analysis."""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx

from scanner.models import CertificateInfo, Finding, RemediationEffort, Severity


async def check_tls(url: str, client: httpx.AsyncClient) -> tuple[Optional[CertificateInfo], list[Finding]]:
    """Perform TLS/SSL checks for the given URL."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    findings: list[Finding] = []
    cert_info: Optional[CertificateInfo] = None

    # ── 1. HTTPS redirect check ───────────────────────────────────────────────
    if parsed.scheme == "http":
        https_url = url.replace("http://", "https://", 1)
        try:
            r = await client.get(https_url, follow_redirects=False, timeout=8)
            if r.status_code >= 400:
                findings.append(_no_https_finding(url))
        except Exception:
            findings.append(_no_https_finding(url))

    if parsed.scheme != "https":
        return cert_info, findings

    # ── 2. Certificate details ────────────────────────────────────────────────
    cert_info = await _get_cert_info(hostname, port)
    if cert_info is None:
        findings.append(
            Finding(
                name="TLS Certificate Could Not Be Retrieved",
                severity=Severity.HIGH,
                affected_asset=url,
                evidence="SSL handshake failed or certificate could not be parsed.",
                risk_explanation="A failed TLS handshake may indicate a misconfigured or invalid certificate.",
                attacker_impact=(
                    "Visitors cannot establish a secure encrypted connection, leaving "
                    "data in transit exposed. Browsers will display security warnings."
                ),
                business_impact="Users will see browser security warnings, causing distrust and traffic loss.",
                recommended_fix="Verify the certificate is valid, correctly installed, and the chain is complete.",
                fix_priority=1,
                remediation_effort=RemediationEffort.MEDIUM,
                confidence="Medium",
                references=["https://letsencrypt.org/docs/"],
                validation_steps="Re-check TLS using https://www.ssllabs.com/ssltest/ after fixing.",
                category="tls",
            )
        )
        return cert_info, findings

    now = datetime.now(timezone.utc)

    # ── 3. Expired certificate ────────────────────────────────────────────────
    if cert_info.is_expired:
        findings.append(
            Finding(
                name="SSL Certificate Expired",
                severity=Severity.CRITICAL,
                affected_asset=f"{hostname}:{port}",
                evidence=(
                    f"Certificate expired on {cert_info.valid_until.strftime('%Y-%m-%d') if cert_info.valid_until else 'unknown'}. "
                    f"Days overdue: {abs(cert_info.days_until_expiry or 0)}."
                ),
                risk_explanation="An expired certificate means the TLS connection is no longer trusted by browsers.",
                attacker_impact=(
                    "Visitors receive browser security warnings and may proceed with "
                    "an unverified connection, or be susceptible to man-in-the-middle attacks."
                ),
                business_impact="Expired certificates cause complete service unavailability in strict browsers and mobile apps.",
                recommended_fix="Renew the SSL/TLS certificate immediately. Consider using Let's Encrypt with auto-renewal.",
                fix_priority=1,
                remediation_effort=RemediationEffort.LOW,
                confidence="High",
                references=["https://letsencrypt.org/", "https://certbot.eff.org/"],
                validation_steps="After renewal, verify with: openssl s_client -connect {hostname}:443 -servername {hostname}",
                category="tls",
            )
        )

    # ── 4. Certificate expiring soon ──────────────────────────────────────────
    elif cert_info.days_until_expiry is not None and 0 < cert_info.days_until_expiry <= 30:
        severity = Severity.HIGH if cert_info.days_until_expiry <= 14 else Severity.MEDIUM
        findings.append(
            Finding(
                name=f"SSL Certificate Expiring Soon ({cert_info.days_until_expiry} days)",
                severity=severity,
                affected_asset=f"{hostname}:{port}",
                evidence=f"Certificate expires on {cert_info.valid_until.strftime('%Y-%m-%d') if cert_info.valid_until else 'unknown'}.",
                risk_explanation="The certificate will expire soon, causing service disruption.",
                attacker_impact="After expiry, visitors will see browser warnings and encrypted connections will fail.",
                business_impact="Service unavailability and visitor trust loss if not renewed before expiry.",
                recommended_fix=f"Renew the certificate within the next {cert_info.days_until_expiry} days.",
                fix_priority=1,
                remediation_effort=RemediationEffort.LOW,
                confidence="High",
                references=["https://letsencrypt.org/"],
                validation_steps="Confirm new expiry date after renewal using openssl or SSL Labs.",
                category="tls",
            )
        )

    # ── 5. Self-signed certificate ────────────────────────────────────────────
    if cert_info.is_self_signed:
        findings.append(
            Finding(
                name="Self-Signed SSL Certificate",
                severity=Severity.HIGH,
                affected_asset=f"{hostname}:{port}",
                evidence=f"Subject and Issuer are identical: {cert_info.subject}",
                risk_explanation="Self-signed certificates are not trusted by browsers and provide no identity verification.",
                attacker_impact=(
                    "Users cannot verify the server's identity. An adversary performing "
                    "a man-in-the-middle attack could present a similar self-signed certificate "
                    "and users might accept it."
                ),
                business_impact="Browser security warnings deter visitors and break automated client integrations.",
                recommended_fix="Replace with a certificate from a trusted CA (e.g., Let's Encrypt, DigiCert, Sectigo).",
                fix_priority=1,
                remediation_effort=RemediationEffort.LOW,
                confidence="High",
                references=["https://letsencrypt.org/"],
                validation_steps="After replacement, verify chain is trusted by running: curl -v https://{hostname}",
                category="tls",
            )
        )

    # ── 6. Hostname mismatch ──────────────────────────────────────────────────
    if not cert_info.hostname_matches:
        findings.append(
            Finding(
                name="SSL Certificate Hostname Mismatch",
                severity=Severity.HIGH,
                affected_asset=f"{hostname}:{port}",
                evidence=f"Certificate subject '{cert_info.subject}' does not match hostname '{hostname}'.",
                risk_explanation="The certificate was issued for a different domain.",
                attacker_impact=(
                    "Clients cannot verify they are connecting to the intended server, "
                    "which undermines the purpose of TLS."
                ),
                business_impact="All HTTPS connections to this hostname will fail with a browser security error.",
                recommended_fix=f"Issue a certificate that includes '{hostname}' in the Subject or SAN fields.",
                fix_priority=1,
                remediation_effort=RemediationEffort.LOW,
                confidence="High",
                references=["https://tools.ietf.org/html/rfc6125"],
                validation_steps=f"Run: openssl s_client -connect {hostname}:443 -servername {hostname} and verify the CN/SAN.",
                category="tls",
            )
        )

    # ── 7. Weak TLS version ───────────────────────────────────────────────────
    if cert_info.weak_tls:
        findings.append(
            Finding(
                name=f"Weak TLS Version Negotiated: {cert_info.tls_version}",
                severity=Severity.HIGH,
                affected_asset=f"{hostname}:{port}",
                evidence=f"Server negotiated TLS version: {cert_info.tls_version}",
                risk_explanation="TLS 1.0 and 1.1 are deprecated and contain known cryptographic weaknesses.",
                attacker_impact=(
                    "An adversary capable of observing the network may exploit weaknesses in "
                    "older TLS versions to decrypt or tamper with encrypted traffic."
                ),
                business_impact="Fails PCI-DSS compliance; deprecated by all major browsers.",
                recommended_fix="Disable TLS 1.0 and 1.1; support only TLS 1.2 and TLS 1.3.",
                fix_priority=2,
                remediation_effort=RemediationEffort.MEDIUM,
                confidence="High",
                references=[
                    "https://tools.ietf.org/html/rfc8996",
                    "https://www.ssllabs.com/ssltest/",
                ],
                validation_steps="Use SSL Labs test to confirm only TLS 1.2+ is accepted.",
                category="tls",
            )
        )

    return cert_info, findings


async def _get_cert_info(hostname: str, port: int) -> Optional[CertificateInfo]:
    """Retrieve certificate info using asyncio + ssl."""
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(None, _blocking_cert_check, hostname, port)
    except Exception:
        return None


def _blocking_cert_check(hostname: str, port: int) -> Optional[CertificateInfo]:
    """Blocking SSL certificate inspection (run in executor)."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version() or ""

        if not cert:
            return None

        # Parse validity dates
        not_before = _parse_cert_date(cert.get("notBefore", ""))
        not_after = _parse_cert_date(cert.get("notAfter", ""))
        now = datetime.now(timezone.utc)
        is_expired = not_after is not None and not_after < now
        days_left = int((not_after - now).days) if not_after else None

        # Subject / issuer
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        cn = subject.get("commonName", "")
        issuer_cn = issuer.get("commonName", "")
        is_self_signed = cn == issuer_cn

        # Hostname match
        try:
            ssl.match_hostname(cert, hostname)
            hostname_matches = True
        except ssl.CertificateError:
            hostname_matches = False

        # SANs
        san_domains = [
            val for t, val in cert.get("subjectAltName", []) if t == "DNS"
        ]

        # Weak TLS (TLS 1.0 / 1.1)
        weak = tls_version in ("TLSv1", "TLSv1.1")

        return CertificateInfo(
            subject=cn,
            issuer=issuer_cn,
            valid_from=not_before,
            valid_until=not_after,
            days_until_expiry=days_left,
            is_expired=is_expired,
            is_self_signed=is_self_signed,
            hostname_matches=hostname_matches,
            tls_version=tls_version,
                weak_tls=weak,
            san_domains=san_domains,
        )
    except Exception:
        return None


def _parse_cert_date(date_str: str) -> Optional[datetime]:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _no_https_finding(url: str) -> Finding:
    return Finding(
        name="No HTTPS / Missing HTTPS Redirect",
        severity=Severity.HIGH,
        affected_asset=url,
        evidence="The target responds on HTTP without redirecting to HTTPS.",
        risk_explanation=(
            "All data transmitted between the client and server is unencrypted "
            "and can be intercepted on the network."
        ),
        attacker_impact=(
            "An adversary on the network path (e.g., public Wi-Fi) can read or "
            "modify all data exchanged between users and the site, including login "
            "credentials and session tokens."
        ),
        business_impact="Fails PCI-DSS, GDPR, and browser security requirements; degrades SEO ranking.",
        recommended_fix=(
            "Enable HTTPS and configure a permanent 301 redirect from HTTP to HTTPS. "
            "Add the Strict-Transport-Security header to prevent future plain HTTP connections."
        ),
        fix_priority=1,
        remediation_effort=RemediationEffort.MEDIUM,
        confidence="High",
        references=[
            "https://letsencrypt.org/",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
        ],
        validation_steps="After enabling HTTPS, test: curl -I http://{url} and confirm a 301 redirect to https://.",
        category="tls",
    )
