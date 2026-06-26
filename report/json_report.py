"""JSON report export."""
from __future__ import annotations

import json
import os
from datetime import datetime

import config
from scanner.models import ScanResult


def export_json(result: ScanResult) -> str:
    """Export scan result to a JSON file. Returns the file path."""
    os.makedirs(config.REPORT_DIR, exist_ok=True)
    timestamp = result.started_at.strftime("%Y%m%d_%H%M%S")
    safe_target = result.target_normalized.replace("://", "_").replace("/", "_").replace(":", "_")[:60]
    filename = f"{config.REPORT_DIR}/scan_{safe_target}_{timestamp}.json"

    data = {
        "meta": {
            "scan_id": result.scan_id,
            "target": result.target,
            "target_normalized": result.target_normalized,
            "target_type": result.target_type,
            "started_at": result.started_at.isoformat(),
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "status": result.status.value,
            "risk_level": result.risk_level,
            "risk_score": result.risk_score,
        },
        "summary": {
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "informational": result.info_count,
            "total": len(result.findings),
        },
        "technologies": result.technologies_detected,
        "open_ports": [
            {
                "port": p.port,
                "service": p.service,
                "risk": p.risk,
            }
            for p in result.open_ports
        ],
        "certificate": result.certificate.model_dump() if result.certificate else None,
        "findings": [
            {
                "id": f.id,
                "name": f.name,
                "severity": f.severity.value,
                "affected_asset": f.affected_asset,
                "evidence": f.evidence,
                "risk_explanation": f.risk_explanation,
                "attacker_impact": f.attacker_impact,
                "business_impact": f.business_impact,
                "recommended_fix": f.recommended_fix,
                "fix_priority": f.fix_priority,
                "remediation_effort": f.remediation_effort.value,
                "confidence": f.confidence,
                "references": f.references,
                "validation_steps": f.validation_steps,
                "category": f.category,
            }
            for f in result.sorted_findings()
        ],
    }

    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)

    return filename
