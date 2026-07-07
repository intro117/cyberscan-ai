"""
Generacion de reporte PDF con reportlab (libreria real, sin dependencias
externas de pago). Devuelve bytes listos para servir via FastAPI Response
o subir a S3.
"""
from __future__ import annotations

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

from app.models import ScanResult, Severity

SEVERITY_COLOR = {
    Severity.CRITICAL: colors.HexColor("#B91C1C"),
    Severity.HIGH: colors.HexColor("#EA580C"),
    Severity.MEDIUM: colors.HexColor("#CA8A04"),
    Severity.LOW: colors.HexColor("#2563EB"),
    Severity.INFO: colors.HexColor("#6B7280"),
    Severity.OK: colors.HexColor("#16A34A"),
}


def build_pdf_report(result: ScanResult) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=LETTER,
        topMargin=2 * cm, bottomMargin=2 * cm, leftMargin=2 * cm, rightMargin=2 * cm,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleCustom", parent=styles["Title"], fontSize=22, spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle", parent=styles["Normal"], fontSize=11, textColor=colors.grey,
    )

    story = []
    story.append(Paragraph("CyberScan AI - Reporte de Seguridad", title_style))
    story.append(Paragraph(f"Dominio analizado: {result.domain}", subtitle_style))
    story.append(Paragraph(f"Fecha: {result.scanned_at.strftime('%Y-%m-%d %H:%M UTC')}", subtitle_style))
    story.append(Spacer(1, 0.6 * cm))

    score_style = ParagraphStyle(
        "Score", parent=styles["Heading1"], fontSize=36,
        textColor=_score_color(result.score),
    )
    story.append(Paragraph(f"Security Score: {result.score}/100 (Grado {result.grade})", score_style))
    story.append(Spacer(1, 0.8 * cm))

    story.append(Paragraph("Resumen de hallazgos", styles["Heading2"]))
    table_data = [["Modulo", "Verificacion", "Severidad", "Estado", "Detalle"]]
    for f in result.findings:
        table_data.append([
            f.module, f.check, f.severity.value.upper(),
            "OK" if f.passed else "FALLA", Paragraph(f.detail, styles["BodyText"]),
        ])

    table = Table(table_data, colWidths=[2.2 * cm, 3.2 * cm, 2.2 * cm, 2 * cm, 6.5 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
    ]))
    story.append(table)
    story.append(Spacer(1, 0.8 * cm))

    remediations = [f for f in result.findings if not f.passed and f.remediation]
    if remediations:
        story.append(Paragraph("Plan de remediacion priorizado", styles["Heading2"]))
        for f in sorted(remediations, key=lambda x: list(Severity).index(x.severity)):
            story.append(Paragraph(f"<b>[{f.severity.value.upper()}] {f.check}:</b> {f.remediation}", styles["BodyText"]))
            story.append(Spacer(1, 0.2 * cm))

    doc.build(story)
    return buffer.getvalue()


def _score_color(score: int):
    if score >= 90:
        return colors.HexColor("#16A34A")
    if score >= 75:
        return colors.HexColor("#65A30D")
    if score >= 60:
        return colors.HexColor("#CA8A04")
    if score >= 40:
        return colors.HexColor("#EA580C")
    return colors.HexColor("#B91C1C")
