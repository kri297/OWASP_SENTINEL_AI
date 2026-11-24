"""
OWASP Sentinel AI - Professional PDF Security Report Generator

Generates comprehensive, styled PDF vulnerability assessment reports
using ReportLab Platypus with color-coded severity levels, charts,
attack path analysis, and remediation guidance.
"""

import io
import datetime
from typing import List, Dict, Any, Optional

from reportlab.lib import colors
from reportlab.lib.colors import HexColor, Color
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm, cm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    Image,
    Frame,
    PageTemplate,
    BaseDocTemplate,
    NextPageTemplate,
    KeepTogether,
    HRFlowable,
    ListFlowable,
    ListItem,
)
from reportlab.graphics.shapes import Drawing, Rect, String, Line
from reportlab.graphics import renderPDF
from reportlab.pdfgen import canvas as pdfcanvas


class ReportGenerator:
    """
    Professional PDF security report generator for OWASP Sentinel AI.

    Creates comprehensive vulnerability assessment reports with:
    - Cover page with risk rating
    - Executive summary with statistics
    - Detailed vulnerability findings
    - Attack path analysis
    - Remediation guidance
    - Appendices with methodology and references
    """

    # ------------------------------------------------------------------ #
    #  Severity colour scheme
    # ------------------------------------------------------------------ #
    SEVERITY_COLORS = {
        "critical": HexColor("#DC2626"),
        "high": HexColor("#EA580C"),
        "medium": HexColor("#CA8A04"),
        "low": HexColor("#2563EB"),
        "info": HexColor("#6B7280"),
        "informational": HexColor("#6B7280"),
    }

    COLOR_PRIMARY = HexColor("#1E3A5F")
    COLOR_ACCENT = HexColor("#0EA5E9")
    COLOR_BG_LIGHT = HexColor("#F1F5F9")
    COLOR_BG_DARK = HexColor("#1E293B")
    COLOR_TEXT = HexColor("#1E293B")
    COLOR_TEXT_LIGHT = HexColor("#64748B")
    COLOR_WHITE = colors.white
    COLOR_BLACK = colors.black
    COLOR_BORDER = HexColor("#CBD5E1")

    PAGE_WIDTH, PAGE_HEIGHT = A4

    def __init__(
        self,
        scan_data: Optional[Dict[str, Any]] = None,
        vulnerabilities: Optional[List[Dict[str, Any]]] = None,
        attack_paths: Optional[List[Dict[str, Any]]] = None,
        ai_analysis: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialise the report generator.

        Args:
            scan_data: Scan metadata (target_url, scan_id, start_time, config …).
            vulnerabilities: List of vulnerability dictionaries.
            attack_paths: List of attack-path dictionaries.
            ai_analysis: Optional AI-driven analysis/narrative.
        """
        self.scan_data = scan_data or {}
        self.vulnerabilities = vulnerabilities or []
        self.attack_paths = attack_paths or []
        self.ai_analysis = ai_analysis or {}
        self._styles = getSampleStyleSheet()
        self._register_styles()

    # ================================================================== #
    #  Style registration
    # ================================================================== #

    def _register_styles(self):
        """Register all custom paragraph styles used throughout the report."""

        self._styles.add(ParagraphStyle(
            name="CoverTitle",
            fontName="Helvetica-Bold",
            fontSize=28,
            leading=34,
            textColor=self.COLOR_WHITE,
            alignment=TA_CENTER,
            spaceAfter=6,
        ))
        self._styles.add(ParagraphStyle(
            name="CoverSubtitle",
            fontName="Helvetica",
            fontSize=16,
            leading=20,
            textColor=HexColor("#94A3B8"),
            alignment=TA_CENTER,
            spaceAfter=24,
        ))
        self._styles.add(ParagraphStyle(
            name="CoverDetail",
            fontName="Helvetica",
            fontSize=11,
            leading=16,
            textColor=self.COLOR_WHITE,
            alignment=TA_CENTER,
            spaceAfter=4,
        ))
        self._styles.add(ParagraphStyle(
            name="SectionHeading",
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=24,
            textColor=self.COLOR_PRIMARY,
            spaceBefore=18,
            spaceAfter=10,
            borderPadding=(0, 0, 4, 0),
        ))
        self._styles.add(ParagraphStyle(
            name="SubHeading",
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=18,
            textColor=self.COLOR_PRIMARY,
            spaceBefore=12,
            spaceAfter=6,
        ))
        self._styles.add(ParagraphStyle(
            name="BodyText2",
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=self.COLOR_TEXT,
            alignment=TA_JUSTIFY,
            spaceAfter=6,
        ))
        self._styles.add(ParagraphStyle(
            name="SmallText",
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=self.COLOR_TEXT_LIGHT,
        ))
        self._styles.add(ParagraphStyle(
            name="TableHeader",
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=self.COLOR_WHITE,
            alignment=TA_CENTER,
        ))
        self._styles.add(ParagraphStyle(
            name="TableCell",
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=self.COLOR_TEXT,
        ))
        self._styles.add(ParagraphStyle(
            name="TableCellCenter",
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=self.COLOR_TEXT,
            alignment=TA_CENTER,
        ))
        self._styles.add(ParagraphStyle(
            name="TOCEntry",
            fontName="Helvetica",
            fontSize=11,
            leading=18,
            textColor=self.COLOR_PRIMARY,
            leftIndent=12,
        ))
        self._styles.add(ParagraphStyle(
            name="SeverityBadge",
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=self.COLOR_WHITE,
            alignment=TA_CENTER,
        ))
        self._styles.add(ParagraphStyle(
            name="FindingTitle",
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=self.COLOR_PRIMARY,
            spaceBefore=6,
            spaceAfter=4,
        ))
        self._styles.add(ParagraphStyle(
            name="EvidenceText",
            fontName="Courier",
            fontSize=8,
            leading=11,
            textColor=HexColor("#374151"),
            backColor=HexColor("#F3F4F6"),
            borderPadding=6,
            spaceAfter=6,
        ))
        self._styles.add(ParagraphStyle(
            name="Disclaimer",
            fontName="Helvetica-Oblique",
            fontSize=8,
            leading=11,
            textColor=self.COLOR_TEXT_LIGHT,
            alignment=TA_JUSTIFY,
        ))
        self._styles.add(ParagraphStyle(
            name="Confidential",
            fontName="Helvetica-Bold",
            fontSize=48,
            leading=52,
            textColor=HexColor("#DC262633"),
            alignment=TA_CENTER,
        ))

    # ================================================================== #
    #  Helpers
    # ================================================================== #

    def _severity_color(self, severity: str) -> Color:
        """Return the colour mapped to *severity* (case-insensitive)."""
        return self.SEVERITY_COLORS.get(
            (severity or "info").lower(), self.SEVERITY_COLORS["info"]
        )

    def _severity_counts(self) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in self.vulnerabilities:
            sev = (v.get("severity") or "info").lower()
            if sev == "informational":
                sev = "info"
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _overall_risk(self) -> str:
        """Determine the overall risk rating string."""
        counts = self._severity_counts()
        if counts["critical"] > 0:
            return "CRITICAL"
        if counts["high"] > 0:
            return "HIGH"
        if counts["medium"] > 0:
            return "MEDIUM"
        if counts["low"] > 0:
            return "LOW"
        if counts["info"] > 0:
            return "INFORMATIONAL"
        return "NONE"

    @staticmethod
    def _safe(value, default="N/A") -> str:
        """Return *value* converted to string if present, else *default*."""
        if value is not None and str(value).strip() != "":
            return str(value)
        return str(default)

    def _hr(self):
        """Return a styled horizontal rule."""
        return HRFlowable(
            width="100%",
            thickness=1,
            color=self.COLOR_BORDER,
            spaceBefore=6,
            spaceAfter=6,
        )

    def _severity_badge_table(self, severity: str):
        """Return a small Table acting as an inline severity badge."""
        sev = (severity or "info").upper()
        color = self._severity_color(severity)
        badge = Table(
            [[Paragraph(sev, self._styles["SeverityBadge"])]],
            colWidths=[70],
            rowHeights=[18],
        )
        badge.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), color),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROUNDEDCORNERS", [4, 4, 4, 4]),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        return badge

    # ================================================================== #
    #  Chart: severity bar chart
    # ================================================================== #

    def _create_severity_bar_chart(self) -> Drawing:
        """Create a horizontal bar chart showing vulnerability counts by severity."""
        counts = self._severity_counts()
        categories = ["Critical", "High", "Medium", "Low", "Info"]
        severity_keys = ["critical", "high", "medium", "low", "info"]
        values = [counts[k] for k in severity_keys]
        bar_colors = [self._severity_color(k) for k in severity_keys]

        max_val = max(values) if max(values) > 0 else 1
        chart_width = 400
        chart_height = 160
        bar_height = 20
        label_width = 70
        gap = 8

        d = Drawing(chart_width, chart_height)

        # Background
        d.add(Rect(0, 0, chart_width, chart_height, fillColor=self.COLOR_BG_LIGHT,
                    strokeColor=None, rx=4, ry=4))

        y_start = chart_height - 25

        for i, (cat, val, col) in enumerate(zip(categories, values, bar_colors)):
            y = y_start - i * (bar_height + gap)

            # Category label
            d.add(String(8, y + 5, cat, fontName="Helvetica-Bold", fontSize=9,
                         fillColor=self.COLOR_TEXT))

            # Bar
            bar_max_width = chart_width - label_width - 60
            bar_w = (val / max_val) * bar_max_width if max_val > 0 else 0
            bar_w = max(bar_w, 2)  # minimum visible bar

            d.add(Rect(label_width, y, bar_w, bar_height, fillColor=col,
                       strokeColor=None, rx=3, ry=3))

            # Value label
            d.add(String(label_width + bar_w + 6, y + 5, str(val),
                         fontName="Helvetica-Bold", fontSize=9, fillColor=col))

        return d

    # ================================================================== #
    #  Header / Footer callback
    # ================================================================== #

    def _header_footer(self, canvas: pdfcanvas.Canvas, doc):
        """Draw header and footer on every page (except the cover page)."""
        canvas.saveState()
        page_num = doc.page

        if page_num == 1:
            # Cover page – skip normal header/footer
            canvas.restoreState()
            return

        width, height = A4

        # --- Header ---
        canvas.setStrokeColor(self.COLOR_PRIMARY)
        canvas.setLineWidth(1.5)
        canvas.line(40, height - 40, width - 40, height - 40)

        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(self.COLOR_PRIMARY)
        canvas.drawString(40, height - 35, "OWASP Sentinel AI")

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(self.COLOR_TEXT_LIGHT)
        canvas.drawRightString(width - 40, height - 35, "CONFIDENTIAL")

        # --- Footer ---
        canvas.setStrokeColor(self.COLOR_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(40, 45, width - 40, 45)

        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(self.COLOR_TEXT_LIGHT)
        target = self.scan_data.get("target_url", "")
        canvas.drawString(40, 32, f"Target: {target}")
        canvas.drawCentredString(width / 2, 32, f"Page {page_num}")
        scan_date = self.scan_data.get("start_time", self.scan_data.get("scan_date", ""))
        canvas.drawRightString(width - 40, 32, f"Generated: {scan_date}")

        canvas.restoreState()

    # ================================================================== #
    #  Cover Page
    # ================================================================== #

    def _create_cover_page(self, story: list):
        """Add a full-bleed cover page to the story."""

        story.append(Spacer(1, 30))

        # Dark background table for the cover area
        risk = self._overall_risk()
        risk_color = self._severity_color(risk)
        target_url = self._safe(self.scan_data.get("target_url"))
        scan_id = self._safe(self.scan_data.get("scan_id", self.scan_data.get("id")))
        scan_date = self._safe(
            self.scan_data.get("start_time", self.scan_data.get("scan_date"))
        )

        cover_data = [
            [Paragraph("", self._styles["CoverTitle"])],
            [Spacer(1, 20)],
            [Paragraph("OWASP SENTINEL AI", self._styles["CoverTitle"])],
            [Paragraph(
                "Web Vulnerability Assessment Report",
                self._styles["CoverSubtitle"],
            )],
            [Spacer(1, 30)],
            [self._hr()],
            [Spacer(1, 10)],
            [Paragraph(f"<b>Target:</b>  {target_url}", self._styles["CoverDetail"])],
            [Paragraph(f"<b>Scan Date:</b>  {scan_date}", self._styles["CoverDetail"])],
            [Paragraph(f"<b>Scan ID:</b>  {scan_id}", self._styles["CoverDetail"])],
            [Spacer(1, 20)],
        ]

        # Risk rating badge row
        risk_badge = Table(
            [[Paragraph(f"Overall Risk: {risk}", self._styles["SeverityBadge"])]],
            colWidths=[200],
            rowHeights=[28],
        )
        risk_badge.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), risk_color),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROUNDEDCORNERS", [6, 6, 6, 6]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        cover_data.append([risk_badge])
        cover_data.append([Spacer(1, 40)])

        # Confidential watermark text
        cover_data.append([Paragraph("CONFIDENTIAL", ParagraphStyle(
            name="_ConfidentialCover",
            fontName="Helvetica-Bold",
            fontSize=36,
            leading=40,
            textColor=HexColor("#FFFFFF22"),
            alignment=TA_CENTER,
        ))])

        cover_data.append([Spacer(1, 30)])
        cover_data.append([Paragraph(
            f"Report generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            ParagraphStyle(
                name="_CoverFooter",
                fontName="Helvetica",
                fontSize=8,
                textColor=HexColor("#94A3B8"),
                alignment=TA_CENTER,
            ),
        )])

        avail_width = self.PAGE_WIDTH - 80  # 40 margin each side
        cover_table = Table(cover_data, colWidths=[avail_width])
        cover_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), self.COLOR_BG_DARK),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 24),
            ("RIGHTPADDING", (0, 0), (-1, -1), 24),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("ROUNDEDCORNERS", [8, 8, 8, 8]),
        ]))

        story.append(cover_table)
        story.append(PageBreak())

    # ================================================================== #
    #  Table of Contents
    # ================================================================== #

    def _create_table_of_contents(self, story: list):
        """Add an auto-generated table of contents."""
        story.append(Paragraph("Table of Contents", self._styles["SectionHeading"]))
        story.append(self._hr())

        toc_items = [
            ("1.", "Executive Summary"),
            ("2.", "Vulnerability Statistics"),
            ("3.", "Detailed Findings"),
            ("4.", "Attack Path Analysis"),
            ("5.", "Remediation Summary"),
            ("6.", "Appendix"),
        ]

        toc_data = []
        for num, title in toc_items:
            toc_data.append([
                Paragraph(f"<b>{num}</b>", self._styles["TOCEntry"]),
                Paragraph(title, self._styles["TOCEntry"]),
                Paragraph("", self._styles["TOCEntry"]),  # page placeholder
            ])

        toc_table = Table(toc_data, colWidths=[30, 380, 60])
        toc_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LINEBELOW", (0, 0), (-1, -2), 0.5, self.COLOR_BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(toc_table)
        story.append(PageBreak())

    # ================================================================== #
    #  Executive Summary
    # ================================================================== #

    def _create_executive_summary(self, story: list):
        """Add the executive summary section."""
        story.append(Paragraph("1. Executive Summary", self._styles["SectionHeading"]))
        story.append(self._hr())

        # Risk assessment narrative
        risk = self._overall_risk()
        counts = self._severity_counts()
        total = sum(counts.values())
        target = self._safe(self.scan_data.get("target_url"))

        narrative = self.ai_analysis.get("executive_summary", "")
        if not narrative:
            narrative = (
                f"A comprehensive web vulnerability assessment was conducted against "
                f"<b>{target}</b>. The scan identified a total of <b>{total}</b> "
                f"potential security issues across various severity levels. "
                f"The overall risk rating for this assessment is "
                f"<b><font color='{self._severity_color(risk).hexval()}'>{risk}</font></b>."
            )

            if counts["critical"] > 0:
                narrative += (
                    f" <b>{counts['critical']} critical</b> vulnerabilities were detected "
                    "that require immediate remediation to prevent potential exploitation."
                )
            if counts["high"] > 0:
                narrative += (
                    f" Additionally, <b>{counts['high']} high-severity</b> issues were "
                    "identified that should be addressed in the next remediation cycle."
                )

        story.append(Paragraph(narrative, self._styles["BodyText2"]))
        story.append(Spacer(1, 12))

        # Key findings summary table
        story.append(Paragraph("Key Findings by Severity", self._styles["SubHeading"]))

        header = [
            Paragraph("Severity", self._styles["TableHeader"]),
            Paragraph("Count", self._styles["TableHeader"]),
            Paragraph("Percentage", self._styles["TableHeader"]),
        ]
        rows = [header]
        severity_order = ["critical", "high", "medium", "low", "info"]
        for sev in severity_order:
            count = counts.get(sev, 0)
            pct = f"{(count / total * 100):.1f}%" if total > 0 else "0.0%"
            rows.append([
                Paragraph(sev.upper(), ParagraphStyle(
                    name=f"_sev_{sev}",
                    fontName="Helvetica-Bold",
                    fontSize=9,
                    textColor=self.COLOR_WHITE,
                    alignment=TA_CENTER,
                )),
                Paragraph(str(count), self._styles["TableCellCenter"]),
                Paragraph(pct, self._styles["TableCellCenter"]),
            ])

        summary_table = Table(rows, colWidths=[160, 100, 100])
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), self.COLOR_PRIMARY),
            ("TEXTCOLOR", (0, 0), (-1, 0), self.COLOR_WHITE),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, self.COLOR_BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]
        # Colour-code the severity column cells
        for idx, sev in enumerate(severity_order):
            row = idx + 1
            style_cmds.append(("BACKGROUND", (0, row), (0, row), self._severity_color(sev)))

        summary_table.setStyle(TableStyle(style_cmds))
        story.append(summary_table)
        story.append(Spacer(1, 16))

        # Scan scope & methodology
        story.append(Paragraph("Scan Scope &amp; Methodology", self._styles["SubHeading"]))
        scope_items = [
            f"<b>Target URL:</b> {target}",
            f"<b>Scan Type:</b> {self._safe(self.scan_data.get('scan_type', 'Full Scan'))}",
            f"<b>Scanner Version:</b> OWASP Sentinel AI v1.0",
            f"<b>Total Vulnerabilities Found:</b> {total}",
            f"<b>Scan Duration:</b> {self._safe(self.scan_data.get('duration', 'N/A'))}",
        ]
        for item in scope_items:
            story.append(Paragraph(f"• {item}", self._styles["BodyText2"]))

        story.append(PageBreak())

    # ================================================================== #
    #  Vulnerability Statistics
    # ================================================================== #

    def _create_severity_table(self, story: list):
        """Add the vulnerability statistics section with chart."""
        story.append(Paragraph(
            "2. Vulnerability Statistics", self._styles["SectionHeading"]
        ))
        story.append(self._hr())

        counts = self._severity_counts()
        total = sum(counts.values())

        story.append(Paragraph(
            f"The assessment identified <b>{total}</b> potential security issues. "
            "The distribution across severity levels is shown below.",
            self._styles["BodyText2"],
        ))
        story.append(Spacer(1, 12))

        # Summary boxes (mini-cards for each severity)
        severity_order = ["critical", "high", "medium", "low", "info"]
        box_data = []
        for sev in severity_order:
            box_data.append(
                Paragraph(
                    f"<font color='white'><b>{sev.upper()}</b><br/>"
                    f"<font size='16'>{counts[sev]}</font></font>",
                    ParagraphStyle(
                        name=f"_box_{sev}",
                        fontName="Helvetica-Bold",
                        fontSize=9,
                        leading=20,
                        textColor=self.COLOR_WHITE,
                        alignment=TA_CENTER,
                    ),
                )
            )

        box_table = Table([box_data], colWidths=[92] * 5, rowHeights=[55])
        box_style_cmds = [
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("ROUNDEDCORNERS", [4, 4, 4, 4]),
        ]
        for idx, sev in enumerate(severity_order):
            box_style_cmds.append(
                ("BACKGROUND", (idx, 0), (idx, 0), self._severity_color(sev))
            )

        box_table.setStyle(TableStyle(box_style_cmds))
        story.append(box_table)
        story.append(Spacer(1, 20))

        # Bar chart
        story.append(Paragraph("Severity Distribution", self._styles["SubHeading"]))
        chart = self._create_severity_bar_chart()
        story.append(chart)
        story.append(PageBreak())

    # ================================================================== #
    #  Detailed Findings
    # ================================================================== #

    def _create_vulnerability_detail(self, story: list, vuln: Dict[str, Any]):
        """Add a single vulnerability finding card/section."""
        elements: list = []

        severity = (vuln.get("severity") or "info").upper()
        vuln_type = self._safe(vuln.get("type", vuln.get("vulnerability_type", vuln.get("name"))))
        cwe_id = self._safe(vuln.get("cwe_id", vuln.get("cwe")))
        affected_url = self._safe(vuln.get("url", vuln.get("affected_url")))
        parameter = self._safe(vuln.get("parameter", vuln.get("param")))
        evidence = vuln.get("evidence", vuln.get("proof", ""))
        description = self._safe(vuln.get("description"))
        impact = self._safe(vuln.get("impact"))
        remediation = vuln.get("remediation", vuln.get("fix", vuln.get("recommendation", "")))
        owasp_category = self._safe(vuln.get("owasp_category", vuln.get("owasp")))

        # --- Title row with severity badge ---
        badge = self._severity_badge_table(severity)
        title_row = Table(
            [[badge, Paragraph(f"  {vuln_type}", self._styles["FindingTitle"])]],
            colWidths=[80, 390],
        )
        title_row.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ]))
        elements.append(title_row)
        elements.append(Spacer(1, 4))

        # --- Detail fields table ---
        detail_rows = [
            ["CWE ID", cwe_id],
            ["Affected URL", affected_url],
            ["Parameter", parameter],
            ["OWASP Category", owasp_category],
        ]
        detail_data = []
        for label, value in detail_rows:
            detail_data.append([
                Paragraph(f"<b>{label}:</b>", self._styles["TableCell"]),
                Paragraph(str(value), self._styles["TableCell"]),
            ])

        detail_table = Table(detail_data, colWidths=[110, 360])
        detail_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -2), 0.25, self.COLOR_BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (0, -1), 8),
            ("BACKGROUND", (0, 0), (0, -1), self.COLOR_BG_LIGHT),
        ]))
        elements.append(detail_table)
        elements.append(Spacer(1, 6))

        # --- Evidence ---
        if evidence:
            elements.append(Paragraph("<b>Evidence:</b>", self._styles["TableCell"]))
            elements.append(Spacer(1, 2))
            # Escape XML-special characters for ReportLab
            safe_evidence = (
                str(evidence)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            elements.append(Paragraph(safe_evidence, self._styles["EvidenceText"]))
            elements.append(Spacer(1, 4))

        # --- Description ---
        elements.append(Paragraph("<b>Description:</b>", self._styles["TableCell"]))
        elements.append(Paragraph(str(description), self._styles["BodyText2"]))

        # --- Impact ---
        elements.append(Paragraph("<b>Impact:</b>", self._styles["TableCell"]))
        elements.append(Paragraph(str(impact), self._styles["BodyText2"]))

        # --- Remediation ---
        elements.append(Paragraph("<b>Remediation:</b>", self._styles["TableCell"]))
        if isinstance(remediation, list):
            for idx, step in enumerate(remediation, 1):
                elements.append(Paragraph(
                    f"{idx}. {step}", self._styles["BodyText2"]
                ))
        elif isinstance(remediation, str) and remediation:
            # Try splitting on newlines
            steps = [s.strip() for s in remediation.split("\n") if s.strip()]
            if len(steps) > 1:
                for idx, step in enumerate(steps, 1):
                    elements.append(Paragraph(
                        f"{idx}. {step}", self._styles["BodyText2"]
                    ))
            else:
                elements.append(Paragraph(str(remediation), self._styles["BodyText2"]))
        else:
            elements.append(Paragraph(
                "Refer to the remediation summary section for guidance.",
                self._styles["BodyText2"],
            ))

        elements.append(Spacer(1, 4))
        elements.append(self._hr())
        elements.append(Spacer(1, 6))

        # Wrap in KeepTogether to avoid orphaned lines
        story.append(KeepTogether(elements))

    def _create_detailed_findings(self, story: list):
        """Add the detailed findings section with all vulnerabilities."""
        story.append(Paragraph("3. Detailed Findings", self._styles["SectionHeading"]))
        story.append(self._hr())

        if not self.vulnerabilities:
            story.append(Paragraph(
                "No vulnerabilities were identified during this assessment.",
                self._styles["BodyText2"],
            ))
            story.append(PageBreak())
            return

        story.append(Paragraph(
            f"This section provides detailed information on each of the "
            f"<b>{len(self.vulnerabilities)}</b> vulnerabilities identified.",
            self._styles["BodyText2"],
        ))
        story.append(Spacer(1, 10))

        # Sort by severity: critical > high > medium > low > info
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}
        sorted_vulns = sorted(
            self.vulnerabilities,
            key=lambda v: severity_rank.get((v.get("severity") or "info").lower(), 5),
        )

        for vuln in sorted_vulns:
            self._create_vulnerability_detail(story, vuln)

        story.append(PageBreak())

    # ================================================================== #
    #  Attack Path Analysis
    # ================================================================== #

    def _create_attack_paths_section(self, story: list):
        """Add the attack path analysis section."""
        story.append(Paragraph(
            "4. Attack Path Analysis", self._styles["SectionHeading"]
        ))
        story.append(self._hr())

        if not self.attack_paths:
            story.append(Paragraph(
                "No exploitable attack paths were identified during this assessment.",
                self._styles["BodyText2"],
            ))
            story.append(PageBreak())
            return

        story.append(Paragraph(
            f"The following <b>{len(self.attack_paths)}</b> attack paths were "
            "identified, representing potential exploitation chains an adversary "
            "could follow.",
            self._styles["BodyText2"],
        ))
        story.append(Spacer(1, 10))

        for idx, path in enumerate(self.attack_paths, 1):
            elements: list = []

            risk_level = self._safe(path.get("risk_level", path.get("severity", "medium")))
            path_name = self._safe(path.get("name", path.get("title", f"Attack Path {idx}")))
            description = self._safe(path.get("description"))
            steps = path.get("steps", path.get("attack_steps", []))
            related_vulns = path.get("related_vulnerabilities", path.get("vulnerabilities", []))
            impact = self._safe(path.get("impact"))
            likelihood = self._safe(path.get("likelihood"))

            # Header with badge
            badge = self._severity_badge_table(risk_level)
            title_row = Table(
                [[badge, Paragraph(f"  {path_name}", self._styles["FindingTitle"])]],
                colWidths=[80, 390],
            )
            title_row.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ]))
            elements.append(title_row)
            elements.append(Spacer(1, 4))

            # Description
            elements.append(Paragraph(str(description), self._styles["BodyText2"]))
            elements.append(Spacer(1, 6))

            # Steps table
            if steps:
                elements.append(Paragraph(
                    "<b>Attack Flow:</b>", self._styles["TableCell"]
                ))
                step_header = [
                    Paragraph("Step", self._styles["TableHeader"]),
                    Paragraph("Action", self._styles["TableHeader"]),
                    Paragraph("Detail", self._styles["TableHeader"]),
                ]
                step_rows = [step_header]
                for s_idx, step in enumerate(steps, 1):
                    if isinstance(step, dict):
                        action = self._safe(step.get("action", step.get("name", "")))
                        detail = self._safe(step.get("detail", step.get("description", "")))
                    else:
                        action = str(step)
                        detail = ""
                    step_rows.append([
                        Paragraph(str(s_idx), self._styles["TableCellCenter"]),
                        Paragraph(str(action), self._styles["TableCell"]),
                        Paragraph(str(detail), self._styles["TableCell"]),
                    ])

                step_table = Table(step_rows, colWidths=[40, 180, 250])
                step_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), self.COLOR_PRIMARY),
                    ("TEXTCOLOR", (0, 0), (-1, 0), self.COLOR_WHITE),
                    ("GRID", (0, 0), (-1, -1), 0.5, self.COLOR_BORDER),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [self.COLOR_WHITE, self.COLOR_BG_LIGHT]),
                ]))
                elements.append(step_table)
                elements.append(Spacer(1, 6))

            # Related vulnerabilities
            if related_vulns:
                refs = ", ".join(str(v) for v in related_vulns)
                elements.append(Paragraph(
                    f"<b>Related Vulnerabilities:</b> {refs}",
                    self._styles["BodyText2"],
                ))

            # Impact & Likelihood
            il_data = [
                [Paragraph("<b>Impact</b>", self._styles["TableCell"]),
                 Paragraph(str(impact), self._styles["TableCell"])],
                [Paragraph("<b>Likelihood</b>", self._styles["TableCell"]),
                 Paragraph(str(likelihood), self._styles["TableCell"])],
            ]
            il_table = Table(il_data, colWidths=[100, 370])
            il_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), self.COLOR_BG_LIGHT),
                ("GRID", (0, 0), (-1, -1), 0.25, self.COLOR_BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]))
            elements.append(il_table)
            elements.append(Spacer(1, 4))
            elements.append(self._hr())
            elements.append(Spacer(1, 6))

            story.append(KeepTogether(elements))

        story.append(PageBreak())

    # ================================================================== #
    #  Remediation Summary
    # ================================================================== #

    def _create_remediation_summary(self, story: list):
        """Add the prioritised remediation summary section."""
        story.append(Paragraph(
            "5. Remediation Summary", self._styles["SectionHeading"]
        ))
        story.append(self._hr())

        story.append(Paragraph(
            "The following remediation actions are recommended, ordered by priority. "
            "Addressing critical and high-severity items first will yield the greatest "
            "reduction in overall risk.",
            self._styles["BodyText2"],
        ))
        story.append(Spacer(1, 10))

        # --- Quick Wins ---
        story.append(Paragraph("Quick Wins (Immediate Actions)", self._styles["SubHeading"]))

        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}
        sorted_vulns = sorted(
            self.vulnerabilities,
            key=lambda v: severity_rank.get((v.get("severity") or "info").lower(), 5),
        )

        quick_rows = [
            [
                Paragraph("#", self._styles["TableHeader"]),
                Paragraph("Severity", self._styles["TableHeader"]),
                Paragraph("Finding", self._styles["TableHeader"]),
                Paragraph("Effort", self._styles["TableHeader"]),
            ]
        ]
        long_rows = [
            [
                Paragraph("#", self._styles["TableHeader"]),
                Paragraph("Severity", self._styles["TableHeader"]),
                Paragraph("Finding", self._styles["TableHeader"]),
                Paragraph("Effort", self._styles["TableHeader"]),
            ]
        ]

        for idx, vuln in enumerate(sorted_vulns, 1):
            sev = (vuln.get("severity") or "info").lower()
            vuln_name = self._safe(
                vuln.get("type", vuln.get("vulnerability_type", vuln.get("name")))
            )
            effort = vuln.get("effort", "")
            if not effort:
                effort = "High" if sev in ("critical", "high") else "Medium" if sev == "medium" else "Low"

            sev_cell = Paragraph(
                sev.upper(),
                ParagraphStyle(
                    name=f"_rem_sev_{sev}_{idx}",
                    fontName="Helvetica-Bold",
                    fontSize=8,
                    textColor=self.COLOR_WHITE,
                    alignment=TA_CENTER,
                ),
            )
            row = [
                Paragraph(str(idx), self._styles["TableCellCenter"]),
                sev_cell,
                Paragraph(vuln_name, self._styles["TableCell"]),
                Paragraph(effort, self._styles["TableCellCenter"]),
            ]

            if sev in ("critical", "high"):
                quick_rows.append(row)
            else:
                long_rows.append(row)

        col_widths = [30, 80, 290, 70]

        if len(quick_rows) > 1:
            qt = Table(quick_rows, colWidths=col_widths)
            qstyle = [
                ("BACKGROUND", (0, 0), (-1, 0), self.COLOR_PRIMARY),
                ("GRID", (0, 0), (-1, -1), 0.5, self.COLOR_BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [self.COLOR_WHITE, self.COLOR_BG_LIGHT]),
            ]
            for r_idx in range(1, len(quick_rows)):
                sev = (sorted_vulns[r_idx - 1].get("severity") or "info").lower()
                qstyle.append(("BACKGROUND", (1, r_idx), (1, r_idx), self._severity_color(sev)))
            qt.setStyle(TableStyle(qstyle))
            story.append(qt)
        else:
            story.append(Paragraph(
                "No critical or high-severity quick wins identified.",
                self._styles["BodyText2"],
            ))

        story.append(Spacer(1, 16))

        # --- Long-Term Improvements ---
        story.append(Paragraph(
            "Long-Term Improvements", self._styles["SubHeading"]
        ))

        if len(long_rows) > 1:
            lt = Table(long_rows, colWidths=col_widths)
            lstyle = [
                ("BACKGROUND", (0, 0), (-1, 0), self.COLOR_PRIMARY),
                ("GRID", (0, 0), (-1, -1), 0.5, self.COLOR_BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [self.COLOR_WHITE, self.COLOR_BG_LIGHT]),
            ]
            # offset into sorted_vulns for long-term items
            quick_count = len(quick_rows) - 1  # minus header
            for r_idx in range(1, len(long_rows)):
                vuln_idx = quick_count + r_idx - 1
                if vuln_idx < len(sorted_vulns):
                    sev = (sorted_vulns[vuln_idx].get("severity") or "info").lower()
                    lstyle.append(("BACKGROUND", (1, r_idx), (1, r_idx), self._severity_color(sev)))
            lt.setStyle(TableStyle(lstyle))
            story.append(lt)
        else:
            story.append(Paragraph(
                "No lower-severity long-term improvements identified.",
                self._styles["BodyText2"],
            ))

        story.append(Spacer(1, 12))

        # Implementation effort guide
        story.append(Paragraph(
            "Implementation Effort Estimates", self._styles["SubHeading"]
        ))
        effort_data = [
            [Paragraph("<b>Effort Level</b>", self._styles["TableHeader"]),
             Paragraph("<b>Description</b>", self._styles["TableHeader"]),
             Paragraph("<b>Timeline</b>", self._styles["TableHeader"])],
            [Paragraph("Low", self._styles["TableCellCenter"]),
             Paragraph("Simple configuration change or patch", self._styles["TableCell"]),
             Paragraph("1-2 days", self._styles["TableCellCenter"])],
            [Paragraph("Medium", self._styles["TableCellCenter"]),
             Paragraph("Code modification or infrastructure update", self._styles["TableCell"]),
             Paragraph("1-2 weeks", self._styles["TableCellCenter"])],
            [Paragraph("High", self._styles["TableCellCenter"]),
             Paragraph("Architectural change or major refactoring", self._styles["TableCell"]),
             Paragraph("2-4 weeks", self._styles["TableCellCenter"])],
        ]
        effort_table = Table(effort_data, colWidths=[80, 280, 100])
        effort_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), self.COLOR_PRIMARY),
            ("GRID", (0, 0), (-1, -1), 0.5, self.COLOR_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [self.COLOR_WHITE, self.COLOR_BG_LIGHT]),
        ]))
        story.append(effort_table)
        story.append(PageBreak())

    # ================================================================== #
    #  Appendix
    # ================================================================== #

    def _create_appendix(self, story: list):
        """Add the appendix section with methodology and references."""
        story.append(Paragraph("6. Appendix", self._styles["SectionHeading"]))
        story.append(self._hr())

        # --- A. Scan Configuration ---
        story.append(Paragraph(
            "A. Scan Configuration", self._styles["SubHeading"]
        ))

        config = self.scan_data.get("config", self.scan_data.get("configuration", {}))
        if isinstance(config, dict) and config:
            config_rows = [
                [Paragraph("<b>Parameter</b>", self._styles["TableHeader"]),
                 Paragraph("<b>Value</b>", self._styles["TableHeader"])],
            ]
            for key, val in config.items():
                config_rows.append([
                    Paragraph(str(key), self._styles["TableCell"]),
                    Paragraph(str(val), self._styles["TableCell"]),
                ])
        else:
            config_rows = [
                [Paragraph("<b>Parameter</b>", self._styles["TableHeader"]),
                 Paragraph("<b>Value</b>", self._styles["TableHeader"])],
                [Paragraph("Target URL", self._styles["TableCell"]),
                 Paragraph(self._safe(self.scan_data.get("target_url")), self._styles["TableCell"])],
                [Paragraph("Scan ID", self._styles["TableCell"]),
                 Paragraph(self._safe(self.scan_data.get("scan_id", self.scan_data.get("id"))), self._styles["TableCell"])],
                [Paragraph("Scan Type", self._styles["TableCell"]),
                 Paragraph(self._safe(self.scan_data.get("scan_type", "Full Scan")), self._styles["TableCell"])],
                [Paragraph("Start Time", self._styles["TableCell"]),
                 Paragraph(self._safe(self.scan_data.get("start_time")), self._styles["TableCell"])],
                [Paragraph("Duration", self._styles["TableCell"]),
                 Paragraph(self._safe(self.scan_data.get("duration")), self._styles["TableCell"])],
            ]

        config_table = Table(config_rows, colWidths=[180, 290])
        config_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), self.COLOR_PRIMARY),
            ("GRID", (0, 0), (-1, -1), 0.5, self.COLOR_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [self.COLOR_WHITE, self.COLOR_BG_LIGHT]),
        ]))
        story.append(config_table)
        story.append(Spacer(1, 16))

        # --- B. Methodology Notes ---
        story.append(Paragraph("B. Methodology Notes", self._styles["SubHeading"]))
        methodology_text = (
            "This assessment was conducted using OWASP Sentinel AI, an automated "
            "web vulnerability scanner that combines traditional scanning techniques "
            "with AI-powered analysis. The methodology follows the OWASP Testing Guide "
            "v4.2 and includes the following phases:<br/><br/>"
            "<b>1. Reconnaissance:</b> Automated crawling and enumeration of the "
            "target application's attack surface.<br/>"
            "<b>2. Vulnerability Detection:</b> Active and passive testing for common "
            "web vulnerabilities including injection flaws, authentication issues, "
            "cross-site scripting, security misconfigurations, and more.<br/>"
            "<b>3. Attack Path Analysis:</b> AI-powered chaining of individual "
            "vulnerabilities into exploitable attack paths.<br/>"
            "<b>4. Risk Assessment:</b> Severity rating based on CVSS v3.1 scoring "
            "methodology and business-context analysis.<br/>"
            "<b>5. Remediation Planning:</b> Prioritised remediation guidance based "
            "on risk and implementation effort."
        )
        story.append(Paragraph(methodology_text, self._styles["BodyText2"]))
        story.append(Spacer(1, 16))

        # --- C. OWASP Top 10 Reference ---
        story.append(Paragraph(
            "C. OWASP Top 10 (2021) Reference", self._styles["SubHeading"]
        ))
        owasp_data = [
            [Paragraph("<b>ID</b>", self._styles["TableHeader"]),
             Paragraph("<b>Category</b>", self._styles["TableHeader"]),
             Paragraph("<b>Description</b>", self._styles["TableHeader"])],
            [Paragraph("A01", self._styles["TableCellCenter"]),
             Paragraph("Broken Access Control", self._styles["TableCell"]),
             Paragraph("Restrictions on authenticated users are not properly enforced.", self._styles["TableCell"])],
            [Paragraph("A02", self._styles["TableCellCenter"]),
             Paragraph("Cryptographic Failures", self._styles["TableCell"]),
             Paragraph("Failures related to cryptography leading to exposure of sensitive data.", self._styles["TableCell"])],
            [Paragraph("A03", self._styles["TableCellCenter"]),
             Paragraph("Injection", self._styles["TableCell"]),
             Paragraph("User-supplied data is sent to an interpreter as part of a command or query.", self._styles["TableCell"])],
            [Paragraph("A04", self._styles["TableCellCenter"]),
             Paragraph("Insecure Design", self._styles["TableCell"]),
             Paragraph("Missing or ineffective security controls and architecture.", self._styles["TableCell"])],
            [Paragraph("A05", self._styles["TableCellCenter"]),
             Paragraph("Security Misconfiguration", self._styles["TableCell"]),
             Paragraph("Insecure default configurations, incomplete setups, or open cloud storage.", self._styles["TableCell"])],
            [Paragraph("A06", self._styles["TableCellCenter"]),
             Paragraph("Vulnerable Components", self._styles["TableCell"]),
             Paragraph("Using components with known vulnerabilities.", self._styles["TableCell"])],
            [Paragraph("A07", self._styles["TableCellCenter"]),
             Paragraph("Auth Failures", self._styles["TableCell"]),
             Paragraph("Broken authentication and session management.", self._styles["TableCell"])],
            [Paragraph("A08", self._styles["TableCellCenter"]),
             Paragraph("Data Integrity Failures", self._styles["TableCell"]),
             Paragraph("Code and infrastructure lacking integrity verification.", self._styles["TableCell"])],
            [Paragraph("A09", self._styles["TableCellCenter"]),
             Paragraph("Logging & Monitoring", self._styles["TableCell"]),
             Paragraph("Insufficient logging, detection, monitoring, and active response.", self._styles["TableCell"])],
            [Paragraph("A10", self._styles["TableCellCenter"]),
             Paragraph("SSRF", self._styles["TableCell"]),
             Paragraph("Server-Side Request Forgery — fetching a remote resource without validating the URL.", self._styles["TableCell"])],
        ]
        owasp_table = Table(owasp_data, colWidths=[40, 150, 280])
        owasp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), self.COLOR_PRIMARY),
            ("GRID", (0, 0), (-1, -1), 0.5, self.COLOR_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [self.COLOR_WHITE, self.COLOR_BG_LIGHT]),
        ]))
        story.append(owasp_table)
        story.append(Spacer(1, 16))

        # --- D. Disclaimer & Legal Notice ---
        story.append(Paragraph(
            "D. Disclaimer &amp; Legal Notice", self._styles["SubHeading"]
        ))
        disclaimer_text = (
            "This report is provided for informational purposes only and is intended "
            "solely for the authorized recipient(s). The findings presented herein are "
            "based on automated scanning techniques and may contain false positives. "
            "Manual verification of all findings is strongly recommended before "
            "implementing remediation measures.<br/><br/>"
            "OWASP Sentinel AI and its operators make no warranties, expressed or "
            "implied, regarding the completeness or accuracy of the information "
            "contained in this report. This assessment was conducted at a specific "
            "point in time and does not guarantee the security of the target "
            "application against future threats or attacks.<br/><br/>"
            "Unauthorized distribution, reproduction, or use of this report is "
            "strictly prohibited. This report contains sensitive security information "
            "and should be handled in accordance with your organization's data "
            "classification and handling policies.<br/><br/>"
            "The scanning and testing activities described in this report were "
            "performed with proper authorization. Any attempt to reproduce these "
            "tests without authorization may violate applicable laws and regulations."
        )
        story.append(Paragraph(disclaimer_text, self._styles["Disclaimer"]))

    # ================================================================== #
    #  Main generate() method
    # ================================================================== #

    def generate(self, payload: Optional[Dict[str, Any]] = None) -> bytes:
        """
        Generate the complete PDF security report.

        Args:
            payload: Optional scan payload dictionary containing scan_data,
                     vulnerabilities, and attack_paths.

        Returns:
            bytes: Binary content of the generated PDF.
        """
        if payload:
            self.scan_data = payload
            self.vulnerabilities = payload.get("vulnerabilities", self.vulnerabilities)
            self.attack_paths = payload.get("attack_paths", self.attack_paths)
            self.ai_analysis = payload.get("ai_analysis", self.ai_analysis)

        buffer = io.BytesIO()

        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            topMargin=55,
            bottomMargin=55,
            leftMargin=40,
            rightMargin=40,
            title="OWASP Sentinel AI - Vulnerability Assessment Report",
            author="OWASP Sentinel AI",
            subject="Web Vulnerability Assessment Report",
            creator="OWASP Sentinel AI Report Generator",
        )

        story: list = []

        # 1. Cover Page
        self._create_cover_page(story)

        # 2. Table of Contents
        self._create_table_of_contents(story)

        # 3. Executive Summary
        self._create_executive_summary(story)

        # 4. Vulnerability Statistics
        self._create_severity_table(story)

        # 5. Detailed Findings
        self._create_detailed_findings(story)

        # 6. Attack Path Analysis
        self._create_attack_paths_section(story)

        # 7. Remediation Summary
        self._create_remediation_summary(story)

        # 8. Appendix
        self._create_appendix(story)

        # Build the PDF
        doc.build(story, onFirstPage=self._header_footer, onLaterPages=self._header_footer)

        buffer.seek(0)
        return buffer.getvalue()
