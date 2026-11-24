import io
import json
import logging
from datetime import datetime, timezone

from flask import Blueprint, jsonify, send_file

from models import db, Scan, Vulnerability, AttackPath

logger = logging.getLogger(__name__)

report_bp = Blueprint("report", __name__, url_prefix="/api/reports")


def _build_scan_payload(scan):
    """Assemble the full scan data dict used by both JSON and PDF reports."""
    vulnerabilities = [v.to_dict() for v in Vulnerability.query.filter_by(scan_id=scan.id).all()]
    attack_paths = [p.to_dict() for p in AttackPath.query.filter_by(scan_id=scan.id).all()]

    payload = scan.to_dict()
    payload["vulnerabilities"] = vulnerabilities
    payload["attack_paths"] = attack_paths
    return payload


@report_bp.route("/<int:scan_id>/json", methods=["GET"])
def download_json(scan_id):
    """Return the full scan data as a downloadable JSON file."""
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    try:
        payload = _build_scan_payload(scan)

        buf = io.BytesIO()
        buf.write(json.dumps(payload, indent=2, default=str).encode("utf-8"))
        buf.seek(0)

        filename = f"sentinel_scan_{scan_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"

        return send_file(
            buf,
            mimetype="application/json",
            as_attachment=True,
            download_name=filename,
        )
    except Exception as exc:
        logger.exception("Failed to generate JSON report for scan %s: %s", scan_id, exc)
        return jsonify({"error": "Failed to generate JSON report"}), 500


@report_bp.route("/<int:scan_id>/pdf", methods=["GET"])
def download_pdf(scan_id):
    """Generate and return a PDF report for the scan."""
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    try:
        payload = _build_scan_payload(scan)

        # Attempt to use the project's own PDF generator
        try:
            from reporter.pdf_generator import ReportGenerator

            generator = ReportGenerator()
            pdf_bytes = generator.generate(payload)
        except ImportError:
            logger.warning("ReportGenerator not available — generating a basic PDF.")
            pdf_bytes = _generate_basic_pdf(payload)

        buf = io.BytesIO(pdf_bytes)
        buf.seek(0)

        filename = f"sentinel_report_{scan_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"

        return send_file(
            buf,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename,
        )
    except Exception as exc:
        logger.exception("Failed to generate PDF report for scan %s: %s", scan_id, exc)
        return jsonify({"error": "Failed to generate PDF report"}), 500


# ---------------------------------------------------------------------------
# Fallback basic PDF generator (used when reporter/ module is not yet built)
# ---------------------------------------------------------------------------

def _generate_basic_pdf(payload: dict) -> bytes:
    """Create a minimal PDF report using ReportLab."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=2 * cm, bottomMargin=2 * cm)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title2", parent=styles["Title"], fontSize=22, textColor=HexColor("#1a1a2e"))
    heading_style = ParagraphStyle("Heading", parent=styles["Heading2"], textColor=HexColor("#16213e"))

    elements = []

    # Title
    elements.append(Paragraph("OWASP Sentinel AI — Scan Report", title_style))
    elements.append(Spacer(1, 0.5 * cm))

    # Summary
    elements.append(Paragraph("Scan Summary", heading_style))
    summary_data = [
        ["Target URL", payload.get("target_url", "N/A")],
        ["Scan Type", payload.get("scan_type", "N/A")],
        ["Status", payload.get("status", "N/A")],
        ["Created", payload.get("created_at", "N/A")],
        ["Completed", payload.get("completed_at", "N/A")],
        ["Total Vulnerabilities", str(payload.get("total_vulnerabilities", 0))],
        ["Critical", str(payload.get("critical_count", 0))],
        ["High", str(payload.get("high_count", 0))],
        ["Medium", str(payload.get("medium_count", 0))],
        ["Low", str(payload.get("low_count", 0))],
        ["Info", str(payload.get("info_count", 0))],
    ]
    table = Table(summary_data, colWidths=[5 * cm, 12 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), HexColor("#e8e8e8")),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 1 * cm))

    # Vulnerabilities
    vulns = payload.get("vulnerabilities", [])
    if vulns:
        elements.append(Paragraph("Vulnerabilities", heading_style))
        for idx, v in enumerate(vulns, 1):
            elements.append(Paragraph(
                f"<b>{idx}. [{v.get('severity', '')}] {v.get('vuln_type', 'Unknown')}</b>",
                styles["Normal"],
            ))
            elements.append(Paragraph(f"URL: {v.get('url', 'N/A')}", styles["Normal"]))
            if v.get("parameter"):
                elements.append(Paragraph(f"Parameter: {v['parameter']}", styles["Normal"]))
            if v.get("description"):
                elements.append(Paragraph(f"Description: {v['description']}", styles["Normal"]))
            if v.get("remediation"):
                elements.append(Paragraph(f"Remediation: {v['remediation']}", styles["Normal"]))
            elements.append(Spacer(1, 0.3 * cm))

    doc.build(elements)
    return buf.getvalue()
