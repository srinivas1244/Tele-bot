from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


SEVERITY_WEIGHT: dict[str, int] = {
    "Critical": 40,
    "High": 20,
    "Medium": 10,
    "Low": 3,
    "Informational": 1,
}


class RemediationEffort(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class PortResult(BaseModel):
    port: int
    open: bool
    service: str = ""
    risk: str = ""
    banner: Optional[str] = None


class CertificateInfo(BaseModel):
    subject: str = ""
    issuer: str = ""
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    is_expired: bool = False
    is_self_signed: bool = False
    hostname_matches: bool = True
    tls_version: str = ""
    weak_tls: bool = False
    san_domains: List[str] = []


class HeaderAnalysis(BaseModel):
    header_name: str
    present: bool
    value: Optional[str] = None
    is_misconfigured: bool = False
    notes: str = ""


class CookieAnalysis(BaseModel):
    name: str
    secure: bool
    http_only: bool
    same_site: Optional[str]
    domain: Optional[str]
    path: Optional[str]
    issues: List[str] = []


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str
    severity: Severity
    affected_asset: str
    evidence: str
    risk_explanation: str
    attacker_impact: str
    business_impact: str
    recommended_fix: str
    fix_priority: int = 5
    remediation_effort: RemediationEffort = RemediationEffort.MEDIUM
    confidence: str = "Medium"
    references: List[str] = []
    validation_steps: str = ""
    category: str = "general"
    raw_data: Optional[Dict[str, Any]] = None

    @property
    def severity_weight(self) -> int:
        return SEVERITY_WEIGHT.get(self.severity.value, 0)


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str
    target_normalized: str = ""
    target_type: str = "website"
    requested_by: Optional[int] = None
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    status: ScanStatus = ScanStatus.PENDING
    findings: List[Finding] = []
    error: Optional[str] = None

    ports_checked: List[int] = []
    open_ports: List[PortResult] = []
    certificate: Optional[CertificateInfo] = None
    headers_analyzed: List[HeaderAnalysis] = []
    cookies_analyzed: List[CookieAnalysis] = []

    technologies_detected: List[str] = []
    cms_detected: Optional[str] = None
    server_header: Optional[str] = None
    https_redirect: bool = False
    scan_summary: Optional[str] = None
    ai_report: Optional[str] = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFORMATIONAL)

    @property
    def risk_score(self) -> int:
        return sum(f.severity_weight for f in self.findings)

    @property
    def risk_level(self) -> str:
        score = self.risk_score
        if score >= 80 or self.critical_count > 0:
            return "Critical"
        if score >= 40 or self.high_count > 0:
            return "High"
        if score >= 15 or self.medium_count > 0:
            return "Medium"
        if score >= 5:
            return "Low"
        return "Informational"

    def sorted_findings(self) -> List[Finding]:
        order = ["Critical", "High", "Medium", "Low", "Informational"]
        return sorted(self.findings, key=lambda f: (order.index(f.severity.value), f.fix_priority))
