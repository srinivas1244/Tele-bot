"""CVE lookup using the NIST NVD API (free, no key required for basic queries)."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CACHE: dict[str, list[dict]] = {}


async def lookup_cves(product: str, version: str) -> list[dict[str, Any]]:
    """
    Query the NVD API for CVEs affecting product:version.
    Returns a list of {id, description, score, severity, url}.
    """
    cache_key = f"{product}:{version}"
    if cache_key in _CACHE:
        return _CACHE[cache_key]

    results: list[dict] = []
    keyword = f"{product} {version}"

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                _NVD_API_BASE,
                params={"keywordSearch": keyword, "resultsPerPage": 10},
                headers={"User-Agent": "SecurityAssessmentBot/1.0"},
            )
        if resp.status_code != 200:
            _CACHE[cache_key] = []
            return []

        data = resp.json()
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            score = _extract_score(metrics)
            severity = _score_to_severity(score)

            if _is_relevant(product, version, desc):
                results.append({
                    "id": cve_id,
                    "description": desc[:300],
                    "score": score,
                    "severity": severity,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                })

    except Exception as exc:
        logger.warning("CVE lookup failed for %s %s: %s", product, version, exc)

    _CACHE[cache_key] = results
    return results


def _extract_score(metrics: dict) -> float:
    """Extract CVSS base score from metrics dict (prefer v3 over v2)."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            try:
                return float(entries[0]["cvssData"]["baseScore"])
            except (KeyError, IndexError, TypeError):
                pass
    return 0.0


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Unknown"


def _is_relevant(product: str, version: str, description: str) -> bool:
    """Basic relevance filter — skip clearly unrelated CVEs."""
    desc_lower = description.lower()
    product_lower = product.lower()
    # Must mention the product name in the description
    return product_lower in desc_lower
