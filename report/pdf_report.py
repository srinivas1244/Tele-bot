"""PDF report generation using ReportLab."""
from __future__ import annotations

import os
import re
import textwrap
from urllib.parse import urlparse

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

import config
from scanner.models import ScanResult, Severity


def _safe_filename(target: str) -> str:
    host = urlparse(target).hostname or target
    return re.sub(r"[^a-zA-Z0-9]+", "_", host).strip("_")[:50]

_SEVERITY_COLORS = {
    "Critical": colors.HexColor("#C0392B"),
    "High": colors.HexColor("#E74C3C"),
    "Medium": colors.HexColor("#E67E22"),
    "Low": colors.HexColor("#F1C40F"),
    "Informational": colors.HexColor("#3498DB"),
}

_SEVERITY_BG = {
    "Critical": colors.HexColor("#FADBD8"),
    "High": colors.HexColor("#FDEDEC"),
    "Medium": colors.HexColor("#FDEBD0"),
    "Low": colors.HexColor("#FEF9E7"),
    "Informational": colors.HexColor("#EAF2FB"),
}


def export_pdf(result: ScanResult, ai_report_text: str = "") -> str:
    """Generate a PDF report. Returns the file path."""
    os.makedirs(config.REPORT_DIR, exist_ok=True)
    timestamp = result.started_at.strftime("%Y%m%d_%H%M%S")
    safe_target = _safe_filename(result.target_normalized)
    filename = f"{config.REPORT_DIR}/scan_{safe_target}_{timestamp}.pdf"

    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    styles = _build_styles()
    story = []

    # ── Cover page ────────────────────────────────────────────────────────────
    story.extend(_cover_page(result, styles))
    story.append(PageBreak())

    # ── Executive summary ─────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", styles["Heading1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#2C3E50")))
    story.append(Spacer(1, 4 * mm))
    story.extend(_summary_table(result, styles))
    story.append(Spacer(1, 6 * mm))

    # ── Findings ──────────────────────────────────────────────────────────────
    story.append(Paragraph("Security Findings", styles["Heading1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#2C3E50")))
    story.append(Spacer(1, 4 * mm))

    for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
        group = [f for f in result.sorted_findings() if f.severity.value == sev]
        if not group:
            continue
        story.append(Paragraph(f"{sev} Findings ({len(group)})", styles[f"Sev{sev}"]))
        story.append(Spacer(1, 2 * mm))
        for finding in group:
            story.extend(_finding_block(finding, styles))
            story.append(Spacer(1, 3 * mm))

    # ── AI report (if provided) ───────────────────────────────────────────────
    if ai_report_text:
        story.append(PageBreak())
        story.append(Paragraph("AI-Generated Analysis", styles["Heading1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#2C3E50")))
        story.append(Spacer(1, 4 * mm))
        for line in ai_report_text.split("\n"):
            line = line.strip()
            if not line:
                story.append(Spacer(1, 2 * mm))
            elif line.startswith("## "):
                story.append(Paragraph(line[3:], styles["Heading2"]))
            elif line.startswith("### "):
                story.append(Paragraph(line[4:], styles["Heading3"]))
            elif line.startswith("**") and line.endswith("**"):
                story.append(Paragraph(f"<b>{line[2:-2]}</b>", styles["Normal"]))
            elif line.startswith("- "):
                story.append(Paragraph(f"• {line[2:]}", styles["Bullet"]))
            else:
                story.append(Paragraph(_escape(line), styles["Normal"]))

    doc.build(story, onFirstPage=_add_page_number, onLaterPages=_add_page_number)
    return filename


def _cover_page(result: ScanResult, styles: dict) -> list:
    elements = []
    elements.append(Spacer(1, 30 * mm))
    elements.append(Paragraph("Security Assessment Report", styles["CoverTitle"]))
    elements.append(Spacer(1, 8 * mm))
    elements.append(Paragraph(f"Target: {result.target_normalized}", styles["CoverSub"]))
    elements.append(Spacer(1, 4 * mm))
    elements.append(Paragraph(f"Date: {result.started_at.strftime('%Y-%m-%d')}", styles["CoverSub"]))
    elements.append(Spacer(1, 4 * mm))

    risk_color = _SEVERITY_COLORS.get(result.risk_level, colors.grey)
    elements.append(Paragraph(
        f'Overall Risk Level: <font color="{risk_color.hexval() if hasattr(risk_color, "hexval") else "#333333"}">'
        f'<b>{result.risk_level}</b></font>',
        styles["CoverSub"],
    ))
    elements.append(Spacer(1, 8 * mm))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2C3E50")))
    elements.append(Spacer(1, 4 * mm))
    elements.append(Paragraph(
        "AUTHORIZED SECURITY ASSESSMENT — CONFIDENTIAL",
        styles["CoverDisclaimer"],
    ))
    elements.append(Paragraph(
        "This report was generated by an authorized, non-destructive security scan. "
        "It is intended only for the asset owner or their authorized representatives. "
        "Do not distribute without authorization.",
        styles["Normal"],
    ))
    return elements


def _summary_table(result: ScanResult, styles: dict) -> list:
    data = [
        ["Severity", "Count"],
        ["Critical", str(result.critical_count)],
        ["High", str(result.high_count)],
        ["Medium", str(result.medium_count)],
        ["Low", str(result.low_count)],
        ["Informational", str(result.info_count)],
    ]

    ts = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8F9FA")]),
    ])

    # Color severity rows
    sev_rows = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Informational": 5}
    for sev, row_idx in sev_rows.items():
        bg = _SEVERITY_BG.get(sev, colors.white)
        ts.add("BACKGROUND", (0, row_idx), (-1, row_idx), bg)
        ts.add("TEXTCOLOR", (0, row_idx), (0, row_idx), _SEVERITY_COLORS.get(sev, colors.black))
        ts.add("FONTNAME", (0, row_idx), (0, row_idx), "Helvetica-Bold")

    table = Table(data, colWidths=[80 * mm, 40 * mm])
    table.setStyle(ts)
    return [table]


def _finding_block(finding, styles: dict) -> list:
    elements = []
    sev = finding.severity.value
    bg = _SEVERITY_BG.get(sev, colors.white)
    sev_color = _SEVERITY_COLORS.get(sev, colors.black)

    # Finding header table
    header_data = [[
        f"[{finding.id}] {finding.name}",
        f"Severity: {sev}  |  Effort: {finding.remediation_effort.value}  |  Confidence: {finding.confidence}",
    ]]
    header_table = Table(header_data, colWidths=[100 * mm, 70 * mm])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), bg),
        ("TEXTCOLOR", (0, 0), (0, 0), sev_color),
        ("FONTNAME", (0, 0), (0, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("BOX", (0, 0), (-1, -1), 0.5, sev_color),
    ]))
    elements.append(header_table)

    # Finding details
    rows = [
        ("Affected Asset", finding.affected_asset),
        ("Evidence", finding.evidence[:400]),
        ("Risk Explanation", finding.risk_explanation),
        ("Business Impact", finding.business_impact),
        ("Recommended Fix", finding.recommended_fix[:500]),
        ("Validation Steps", finding.validation_steps[:300]),
    ]
    for label, value in rows:
        if not value:
            continue
        detail_data = [[f"{label}:", _wrap(value, 120)]]
        detail_table = Table(detail_data, colWidths=[35 * mm, 135 * mm])
        detail_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (0, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#DDDDDD")),
        ]))
        elements.append(detail_table)

    if finding.references:
        ref_text = "  |  ".join(finding.references[:3])
        elements.append(Paragraph(f"<i>References: {_escape(ref_text)}</i>", styles["Small"]))

    return elements


def _build_styles() -> dict:
    base = getSampleStyleSheet()
    styles = {
        "Normal": base["Normal"],
        "Heading1": ParagraphStyle("H1", fontSize=14, fontName="Helvetica-Bold",
                                   spaceBefore=6, spaceAfter=4, textColor=colors.HexColor("#2C3E50")),
        "Heading2": ParagraphStyle("H2", fontSize=12, fontName="Helvetica-Bold",
                                   spaceBefore=4, spaceAfter=2, textColor=colors.HexColor("#34495E")),
        "Heading3": ParagraphStyle("H3", fontSize=10, fontName="Helvetica-Bold",
                                   spaceBefore=3, spaceAfter=2),
        "Bullet": ParagraphStyle("Bullet", fontSize=9, leftIndent=10, spaceBefore=1),
        "Small": ParagraphStyle("Small", fontSize=7, textColor=colors.grey, spaceAfter=2),
        "CoverTitle": ParagraphStyle("CoverTitle", fontSize=24, fontName="Helvetica-Bold",
                                     alignment=TA_CENTER, textColor=colors.HexColor("#2C3E50")),
        "CoverSub": ParagraphStyle("CoverSub", fontSize=13, alignment=TA_CENTER,
                                   textColor=colors.HexColor("#555555")),
        "CoverDisclaimer": ParagraphStyle("CoverDisclaimer", fontSize=10, fontName="Helvetica-Bold",
                                          alignment=TA_CENTER, textColor=colors.HexColor("#7F8C8D"),
                                          spaceBefore=4, spaceAfter=2),
        "SevCritical": ParagraphStyle("SevCritical", fontSize=12, fontName="Helvetica-Bold",
                                      textColor=_SEVERITY_COLORS["Critical"]),
        "SevHigh": ParagraphStyle("SevHigh", fontSize=12, fontName="Helvetica-Bold",
                                  textColor=_SEVERITY_COLORS["High"]),
        "SevMedium": ParagraphStyle("SevMedium", fontSize=12, fontName="Helvetica-Bold",
                                    textColor=_SEVERITY_COLORS["Medium"]),
        "SevLow": ParagraphStyle("SevLow", fontSize=12, fontName="Helvetica-Bold",
                                 textColor=_SEVERITY_COLORS["Low"]),
        "SevInformational": ParagraphStyle("SevInformational", fontSize=12, fontName="Helvetica-Bold",
                                           textColor=_SEVERITY_COLORS["Informational"]),
    }
    return styles


def _add_page_number(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.grey)
    canvas.drawString(20 * mm, 10 * mm, "CONFIDENTIAL — Authorized Security Assessment")
    canvas.drawRightString(A4[0] - 20 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _wrap(text: str, width: int) -> str:
    return "\n".join(textwrap.wrap(text, width))


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
