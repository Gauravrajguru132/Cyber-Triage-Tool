import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.units import mm
from config import REPORT_FOLDER, PROJECT_INSTITUTION, PROJECT_DEPARTMENT, PROJECT_GUIDE, PROJECT_TEAM

def add_header_footer(canvas, doc):
    canvas.saveState()
    # Header
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(colors.HexColor("#334155"))
    canvas.drawString(15 * mm, 285 * mm, "CYBER TRIAGE TOOL - ADVANCED DIGITAL FORENSIC REPORT")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(195 * mm, 285 * mm, f"CONFIDENTIAL / LAW ENFORCEMENT & SOC USE")
    canvas.setStrokeColor(colors.HexColor("#cbd5e1"))
    canvas.setLineWidth(0.5)
    canvas.line(15 * mm, 282 * mm, 195 * mm, 282 * mm)

    # Footer
    canvas.line(15 * mm, 15 * mm, 195 * mm, 15 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(15 * mm, 11 * mm, f"ADCET CSE (IoT & Cyber Security) | Guide: {PROJECT_GUIDE}")
    canvas.drawRightString(195 * mm, 11 * mm, f"Page {doc.page}")
    canvas.restoreState()

def generate_pdf_report(filename, results, investigator_name="Investigator"):
    """
    Generates a formal, forensic-grade PDF ReportLab document detailing the triage findings.
    """
    os.makedirs(REPORT_FOLDER, exist_ok=True)
    base_name = os.path.splitext(filename)[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"{base_name}_forensic_triage_{timestamp}.pdf"
    report_path = os.path.join(REPORT_FOLDER, report_filename)

    doc = SimpleDocTemplate(
        report_path,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm
    )

    styles = getSampleStyleSheet()

    # Custom Typography Styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        alignment=TA_LEFT,
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=15
    )
    h1_style = ParagraphStyle(
        "H1Section",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=14,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )
    small_style = ParagraphStyle(
        "Small",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#334155")
    )
    small_bold = ParagraphStyle(
        "SmallBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0f172a")
    )
    code_style = ParagraphStyle(
        "CodeText",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0f172a")
    )

    story = []

    # Title & Academic Credentials Banner
    story.append(Paragraph("DIGITAL FORENSIC TRIAGE REPORT", title_style))
    story.append(Paragraph(f"Autonomous Incident Response & AI Threat Prioritization | ADCET Ashta", subtitle_style))

    # Project metadata banner
    team_str = ", ".join([f"{m['name']} ({m['id']})" for m in PROJECT_TEAM])
    meta_banner_data = [
        [Paragraph("<b>Institution:</b>", small_style), Paragraph(PROJECT_INSTITUTION, small_style)],
        [Paragraph("<b>Department:</b>", small_style), Paragraph(PROJECT_DEPARTMENT, small_style)],
        [Paragraph("<b>Project Guide:</b>", small_style), Paragraph(PROJECT_GUIDE, small_style)],
        [Paragraph("<b>Project Team:</b>", small_style), Paragraph(team_str, small_style)],
        [Paragraph("<b>Report Generated:</b>", small_style), Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC+05:30"), small_style)],
    ]
    meta_table = Table(meta_banner_data, colWidths=[35 * mm, 145 * mm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # Section 1: Evidence Metadata & Cryptographic Integrity
    story.append(Paragraph("1. Evidence Identification & Hash Verification", h1_style))
    metadata = results.get("metadata", {})
    evidence_table_data = [
        [Paragraph("<b>Target Filename</b>", small_bold), Paragraph(str(filename), small_style), Paragraph("<b>File Size</b>", small_bold), Paragraph(f"{metadata.get('file_size', 0):,} bytes", small_style)],
        [Paragraph("<b>SHA-256 Hash</b>", small_bold), Paragraph(f"<font name='Courier' size='7'>{metadata.get('sha256', 'N/A')}</font>", small_style), Paragraph("<b>File Type</b>", small_bold), Paragraph(str(metadata.get('file_type', 'UNKNOWN')), small_style)],
        [Paragraph("<b>MD5 Hash</b>", small_bold), Paragraph(f"<font name='Courier' size='7'>{metadata.get('md5', 'N/A')}</font>", small_style), Paragraph("<b>Acquisition Date</b>", small_bold), Paragraph(metadata.get('created_time', 'N/A'), small_style)]
    ]
    ev_table = Table(evidence_table_data, colWidths=[35 * mm, 80 * mm, 25 * mm, 40 * mm])
    ev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ffffff")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ]))
    story.append(ev_table)
    story.append(Spacer(1, 8))

    # Section 2: Executive Summary & AI Risk Assessment
    story.append(Paragraph("2. Executive Summary & AI Risk Assessment", h1_style))
    risk_score = results.get("risk_score", 0)
    risk_level = results.get("risk_level", "Low")
    threat_info = results.get("threat_classification", {})
    ml_info = results.get("ml_anomaly", {})

    # Color coded risk level
    risk_color = "#dc2626" if risk_level == "Critical" else ("#ea580c" if risk_level == "High" else ("#ca8a04" if risk_level == "Medium" else "#16a34a"))
    
    summary_data = [
        [
            Paragraph("<b>Overall Risk Score</b>", small_bold),
            Paragraph(f"<font color='{risk_color}' size='12'><b>{risk_score}/100 ({risk_level.upper()})</b></font>", small_style),
            Paragraph("<b>Primary Threat Vector</b>", small_bold),
            Paragraph(f"<b>{threat_info.get('primary_vector', 'Suspicious Activity')}</b> ({threat_info.get('confidence_pct', 0)}% conf)", small_style)
        ],
        [
            Paragraph("<b>AI Anomaly Status</b>", small_bold),
            Paragraph(f"{ml_info.get('status', 'Normal')} (Score: {ml_info.get('anomaly_score', 0)})", small_style),
            Paragraph("<b>Detected Indicators</b>", small_bold),
            Paragraph(f"{results.get('total_iocs', 0)} IOCs | {results.get('total_findings', 0)} Suspicious Findings", small_style)
        ]
    ]
    sum_table = Table(summary_data, colWidths=[35 * mm, 55 * mm, 35 * mm, 55 * mm])
    sum_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ]))
    story.append(sum_table)
    story.append(Spacer(1, 6))

    story.append(Paragraph(f"<b>Investigative Summary:</b> {results.get('summary', '')}", body_style))
    story.append(Spacer(1, 8))

    # Section 3: MITRE ATT&CK Matrix Mapping
    story.append(Paragraph("3. MITRE ATT&CK Framework Correlation", h1_style))
    mitre_techs = results.get("mitre_mapping", [])
    if mitre_techs:
        mitre_table_data = [
            [Paragraph("<b>Tactic</b>", small_bold), Paragraph("<b>ID</b>", small_bold), Paragraph("<b>Technique Name</b>", small_bold), Paragraph("<b>Trigger / Evidence</b>", small_bold)]
        ]
        for t in mitre_techs[:8]:
            mitre_table_data.append([
                Paragraph(t["tactic_name"], small_style),
                Paragraph(f"<font name='Courier'><b>{t['technique_id']}</b></font>", small_style),
                Paragraph(t["technique_name"], small_style),
                Paragraph(f"<font color='#991b1b'>{t.get('evidence_trigger', 'N/A')}</font>", code_style)
            ])
        m_table = Table(mitre_table_data, colWidths=[35 * mm, 25 * mm, 65 * mm, 55 * mm])
        m_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
            ("PADDING", (0, 0), (-1, -1), 4)
        ]))
        story.append(m_table)
    else:
        story.append(Paragraph("No standard MITRE ATT&CK techniques were triggered.", small_style))
    story.append(Spacer(1, 8))

    # Section 4: Indicators of Compromise (IOCs)
    story.append(Paragraph("4. Key Indicators of Compromise (IOCs)", h1_style))
    iocs = results.get("iocs", {})
    ioc_rows = [
        [Paragraph("<b>Type</b>", small_bold), Paragraph("<b>Extracted Indicator (Defanged)</b>", small_bold), Paragraph("<b>Classification / Context</b>", small_bold)]
    ]
    for ip in iocs.get("ips", [])[:6]:
        ioc_rows.append([Paragraph("IP Address", small_style), Paragraph(ip["defanged"], code_style), Paragraph(ip.get("category", ""), small_style)])
    for url in iocs.get("urls", [])[:4]:
        ioc_rows.append([Paragraph("URL", small_style), Paragraph(url["defanged"][:45], code_style), Paragraph(url.get("protocol", "HTTP"), small_style)])
    for h in iocs.get("hashes", [])[:4]:
        ioc_rows.append([Paragraph(h["type"], small_style), Paragraph(h["value"], code_style), Paragraph("Extracted Hash", small_style)])
    for lol in iocs.get("lolbas_commands", [])[:4]:
        ioc_rows.append([Paragraph("LOLBAS Command", small_style), Paragraph(lol["command"][:45], code_style), Paragraph(lol["severity"], small_style)])

    if len(ioc_rows) > 1:
        ioc_tbl = Table(ioc_rows, colWidths=[30 * mm, 90 * mm, 60 * mm])
        ioc_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
            ("PADDING", (0, 0), (-1, -1), 4)
        ]))
        story.append(ioc_tbl)
    else:
        story.append(Paragraph("No Indicators of Compromise detected.", small_style))
    story.append(Spacer(1, 8))

    # Section 5: Chronological Incident Timeline
    story.append(Paragraph("5. Chronological Incident Timeline", h1_style))
    timeline_events = results.get("timeline", [])
    if timeline_events:
        time_rows = [
            [Paragraph("<b>Timestamp</b>", small_bold), Paragraph("<b>Category</b>", small_bold), Paragraph("<b>Severity</b>", small_bold), Paragraph("<b>Event Snippet</b>", small_bold)]
        ]
        for ev in timeline_events[:8]:
            sev_color = "#dc2626" if ev["severity"] == "Critical" else ("#ea580c" if ev["severity"] == "High" else "#16a34a")
            time_rows.append([
                Paragraph(ev["timestamp"], code_style),
                Paragraph(ev["category"], small_style),
                Paragraph(f"<font color='{sev_color}'><b>{ev['severity']}</b></font>", small_style),
                Paragraph(ev["description"][:50], small_style)
            ])
        t_tbl = Table(time_rows, colWidths=[35 * mm, 40 * mm, 25 * mm, 80 * mm])
        t_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
            ("PADDING", (0, 0), (-1, -1), 4)
        ]))
        story.append(t_tbl)
    else:
        story.append(Paragraph("No structured timestamped events found.", small_style))
    story.append(Spacer(1, 8))

    # Section 6: AI Recommendations & Containment Playbook
    story.append(Paragraph("6. AI Containment Actions & Mitigation Playbook", h1_style))
    recs = results.get("recommendations", {})
    containment_actions = recs.get("containment_actions", [])
    checklist = recs.get("investigation_checklist", [])

    if containment_actions:
        for act in containment_actions[:4]:
            story.append(Paragraph(f"• <b>[{act.get('phase', 'Action')}] ({act.get('urgency', 'High')}):</b> {act.get('action', '')}", small_style))
            story.append(Spacer(1, 2))
    if checklist:
        story.append(Spacer(1, 4))
        story.append(Paragraph("<b>Forensic Checklist:</b>", small_bold))
        for chk in checklist[:4]:
            story.append(Paragraph(f"  [ ] {chk}", small_style))
            story.append(Spacer(1, 2))
    story.append(Spacer(1, 10))

    # Section 7: Chain of Custody & Investigator Sign-off Block
    story.append(KeepTogether([
        Paragraph("7. Chain of Custody & Digital Sign-off", h1_style),
        Paragraph("I hereby certify that the digital evidence described above was processed under strict forensic protocols, and all extracted findings and cryptographic hashes were verified for integrity.", small_style),
        Spacer(1, 8),
        Table([
            [Paragraph("<b>Lead Investigator:</b>", small_bold), Paragraph("___________________________", small_style), Paragraph("<b>Signature:</b>", small_bold), Paragraph("___________________________", small_style)],
            [Paragraph("<b>Project Guide:</b>", small_bold), Paragraph(PROJECT_GUIDE, small_style), Paragraph("<b>Date:</b>", small_bold), Paragraph(datetime.now().strftime("%d-%m-%Y"), small_style)],
            [Paragraph("<b>Verification SHA-256:</b>", small_bold), Paragraph(f"<font name='Courier' size='6'>{metadata.get('sha256', '')[:40]}...</font>", small_style), Paragraph("<b>Integrity Status:</b>", small_bold), Paragraph("<font color='#16a34a'><b>VERIFIED / UNALTERED</b></font>", small_style)]
        ], colWidths=[35 * mm, 55 * mm, 30 * mm, 60 * mm],
        style=[
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("PADDING", (0, 0), (-1, -1), 5)
        ])
    ]))

    doc.build(story, onFirstPage=add_header_footer, onLaterPages=add_header_footer)
    return report_path
