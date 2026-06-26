"""
AI-powered security report generation — completely free providers.

Supported backends (set AI_PROVIDER in .env):
  none   → structured rule-based report, no AI needed (default)
  ollama → local LLM via Ollama (https://ollama.com) — truly free, runs on your machine
  groq   → Groq cloud API free tier (https://console.groq.com) — free API key, no card
"""
from __future__ import annotations

import json
import logging

import httpx

import config
from scanner.models import ScanResult

logger = logging.getLogger(__name__)


async def generate_ai_report(result: ScanResult) -> str:
    """
    Generate a security report using the configured free AI provider.
    Falls back to a structured rule-based report if AI is unavailable.
    """
    provider = config.AI_PROVIDER.lower().strip()

    if provider == "ollama":
        report = await _ollama_report(result)
        if report:
            return report
        logger.warning("Ollama report failed — falling back to structured report.")

    elif provider == "groq":
        report = await _groq_report(result)
        if report:
            return report
        logger.warning("Groq report failed — falling back to structured report.")

    elif provider != "none":
        logger.warning("Unknown AI_PROVIDER '%s' — using structured report.", provider)

    return _structured_report(result)


# ── Ollama backend ────────────────────────────────────────────────────────────

async def _ollama_report(result: ScanResult) -> str | None:
    """Call local Ollama API (http://localhost:11434)."""
    prompt = _build_prompt(result)
    payload = {
        "model": config.OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_predict": 3000,
        },
    }
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{config.OLLAMA_URL.rstrip('/')}/api/generate",
                json=payload,
            )
        if resp.status_code != 200:
            logger.warning("Ollama returned HTTP %d: %s", resp.status_code, resp.text[:200])
            return None
        data = resp.json()
        return data.get("response", "").strip() or None
    except Exception as exc:
        logger.warning("Ollama request error: %s", exc)
        return None


# ── Groq backend ──────────────────────────────────────────────────────────────

async def _groq_report(result: ScanResult) -> str | None:
    """Call Groq free cloud API (OpenAI-compatible endpoint)."""
    if not config.GROQ_API_KEY:
        logger.warning("GROQ_API_KEY not set.")
        return None

    prompt = _build_prompt(result)
    payload = {
        "model": config.GROQ_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 3000,
    }
    headers = {
        "Authorization": f"Bearer {config.GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                json=payload,
                headers=headers,
            )
        if resp.status_code != 200:
            logger.warning("Groq returned HTTP %d: %s", resp.status_code, resp.text[:200])
            return None
        data = resp.json()
        return data["choices"][0]["message"]["content"].strip() or None
    except Exception as exc:
        logger.warning("Groq request error: %s", exc)
        return None


# ── Shared prompt ─────────────────────────────────────────────────────────────

def _build_prompt(result: ScanResult) -> str:
    """Build the security report prompt sent to any LLM."""
    sorted_findings = result.sorted_findings()
    findings_json = json.dumps(
        [
            {
                "id": f.id,
                "name": f.name,
                "severity": f.severity.value,
                "affected_asset": f.affected_asset,
                "evidence": f.evidence[:250],
                "risk_explanation": f.risk_explanation,
                "attacker_impact": f.attacker_impact,
                "business_impact": f.business_impact,
                "recommended_fix": f.recommended_fix,
                "remediation_effort": f.remediation_effort.value,
                "confidence": f.confidence,
                "validation_steps": f.validation_steps,
                "category": f.category,
            }
            for f in sorted_findings
        ],
        indent=2,
    )

    tech_summary = ", ".join(result.technologies_detected[:8]) or "Not detected"
    open_ports = ", ".join(f"{p.port}/{p.service}" for p in result.open_ports[:10]) or "None detected"

    return f"""You are a senior cybersecurity analyst writing a professional security assessment report.
A safe, authorized, non-destructive security scan has been completed.

IMPORTANT RULES:
- Do NOT include exploit code, attack payloads, or step-by-step attack instructions.
- Explain risks in plain language without providing misuse instructions.
- Prioritize Critical and High findings first.
- Write for a development team lead audience.
- Be concise and actionable.

SCAN CONTEXT:
Target: {result.target_normalized}
Date: {result.started_at.strftime('%Y-%m-%d %H:%M UTC')}
Risk Level: {result.risk_level} | Score: {result.risk_score}
Findings: {result.critical_count} Critical | {result.high_count} High | {result.medium_count} Medium | {result.low_count} Low | {result.info_count} Info
Technologies: {tech_summary}
Open Ports: {open_ports}

FINDINGS (JSON):
{findings_json}

Write a report with these sections:

## 1. Executive Summary
2-3 sentences: overall posture, top issues, recommended immediate actions.

## 2. Risk Overview
Finding counts by severity and overall risk level.

## 3. Critical & High Findings
For each Critical/High finding:
**[ID] Name** (Severity | Effort)
- Risk: plain-language explanation
- Business Impact: why this matters
- What an Adversary Could Do: safe risk explanation, NO attack instructions
- Recommended Fix: specific steps
- Validation: how to confirm the fix worked

## 4. Medium Findings
Same format, condensed.

## 5. Low & Informational
Bulleted list: name, one-line description, one-line fix.

## 6. Remediation Roadmap
- Immediate (24-48h): Critical/High low-effort fixes
- Short-term (1-2 weeks): High/Medium fixes
- Ongoing: Medium/Low items for next sprint

Write the report now."""


# ── Pure structured fallback (no AI required) ─────────────────────────────────

def _structured_report(result: ScanResult) -> str:
    """
    Rule-based Markdown report — works with zero AI setup.
    Clear, prioritized, and actionable without any LLM.
    """
    duration = ""
    if result.completed_at and result.started_at:
        secs = int((result.completed_at - result.started_at).total_seconds())
        duration = f" in {secs}s"

    lines = [
        "# Security Assessment Report",
        "",
        f"**Target:** `{result.target_normalized}`  ",
        f"**Date:** {result.started_at.strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**Completed{duration}**  ",
        f"**Overall Risk:** **{result.risk_level}** (score: {result.risk_score})",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        _executive_summary(result),
        "",
        "---",
        "",
        "## Risk Overview",
        "",
        "| Severity | Count |",
        "|---|---|",
        f"| 🔴 Critical | {result.critical_count} |",
        f"| 🟠 High | {result.high_count} |",
        f"| 🟡 Medium | {result.medium_count} |",
        f"| 🔵 Low | {result.low_count} |",
        f"| ⚪ Informational | {result.info_count} |",
        f"| **Total** | **{len(result.findings)}** |",
        "",
    ]

    if result.technologies_detected:
        lines += [
            f"**Technologies detected:** {', '.join(result.technologies_detected[:6])}",
            "",
        ]

    if result.open_ports:
        port_list = ", ".join(f"`{p.port}/{p.service}`" for p in result.open_ports)
        lines += [f"**Open ports:** {port_list}", ""]

    # ── Findings by severity ───────────────────────────────────────────────────
    severity_order = ["Critical", "High", "Medium", "Low", "Informational"]
    for sev in severity_order:
        group = [f for f in result.sorted_findings() if f.severity.value == sev]
        if not group:
            continue

        emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡",
                 "Low": "🔵", "Informational": "⚪"}.get(sev, "")
        lines += ["---", "", f"## {emoji} {sev} Findings ({len(group)})", ""]

        for f in group:
            lines += [
                f"### [{f.id}] {f.name}",
                "",
                f"| Field | Detail |",
                f"|---|---|",
                f"| **Affected Asset** | `{f.affected_asset}` |",
                f"| **Category** | {f.category} |",
                f"| **Confidence** | {f.confidence} |",
                f"| **Remediation Effort** | {f.remediation_effort.value} |",
                f"| **Fix Priority** | {f.fix_priority} |",
                "",
                f"**Evidence:**  ",
                f"{f.evidence[:300]}",
                "",
                f"**Risk:**  ",
                f"{f.risk_explanation}",
                "",
                f"**Business Impact:**  ",
                f"{f.business_impact}",
                "",
                f"**What an Adversary Could Do:**  ",
                f"{f.attacker_impact}",
                "",
                f"**Recommended Fix:**  ",
                f"{f.recommended_fix}",
                "",
            ]
            if f.validation_steps:
                lines += [f"**Validation:**  ", f"{f.validation_steps}", ""]
            if f.references:
                refs = "  \n".join(f"- {r}" for r in f.references[:3])
                lines += [f"**References:**  ", refs, ""]
            lines.append("")

    # ── Remediation roadmap ───────────────────────────────────────────────────
    lines += ["---", "", "## Remediation Roadmap", ""]

    immediate = [f for f in result.sorted_findings()
                 if f.severity.value in ("Critical", "High") and f.remediation_effort.value == "Low"]
    short_term = [f for f in result.sorted_findings()
                  if f.severity.value in ("Critical", "High", "Medium") and f not in immediate]
    ongoing = [f for f in result.sorted_findings()
               if f.severity.value in ("Medium", "Low") and f not in short_term]

    if immediate:
        lines += ["### Immediate (24–48 hours)", ""]
        for f in immediate:
            lines.append(f"- [ ] **[{f.id}]** {f.name}")
        lines.append("")

    if short_term:
        lines += ["### Short-term (1–2 weeks)", ""]
        for f in short_term[:10]:
            lines.append(f"- [ ] **[{f.id}]** {f.name}")
        lines.append("")

    if ongoing:
        lines += ["### Ongoing / Next Sprint", ""]
        for f in ongoing[:8]:
            lines.append(f"- [ ] **[{f.id}]** {f.name}")
        lines.append("")

    lines += [
        "---",
        "",
        "_Report generated by Security Assessment Bot — authorized use only._",
    ]

    return "\n".join(lines)


def _executive_summary(result: ScanResult) -> str:
    if not result.findings:
        return (
            f"The security scan of `{result.target_normalized}` completed with no issues detected. "
            "The overall risk level is Informational. Continue monitoring and re-scan periodically."
        )

    top_issues = [f.name for f in result.sorted_findings()
                  if f.severity.value in ("Critical", "High")][:3]
    top_str = "; ".join(top_issues) if top_issues else "no Critical or High issues"

    action = "Immediate remediation is required." if result.critical_count else (
        "High-priority issues should be addressed within 1–2 weeks." if result.high_count else
        "Review and remediate medium-priority issues in the next sprint."
    )

    return (
        f"The security scan of `{result.target_normalized}` identified **{len(result.findings)} findings** "
        f"with an overall risk level of **{result.risk_level}** (score: {result.risk_score}). "
        f"Top issues include: {top_str}. {action}"
    )
