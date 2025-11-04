import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from datetime import datetime

# Paths
# NOTE: Removed hardcoded /mnt/data path for better portability, assuming LOGO_PATH is correct
# based on your environment or the image is optional.
LOGO_PATH = os.path.join(os.getcwd(), "VMAI_Logos-new.PNG") 
REPORTS_DIR = os.path.join(os.getcwd(), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


def _style_sheet():
    """Reusable styles for text elements"""
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="TitleBig", fontSize=20, leading=22, alignment=TA_LEFT,
                              textColor=colors.HexColor("#0d6efd"), spaceAfter=6))
    styles.add(ParagraphStyle(name="Section", fontSize=13, leading=16, alignment=TA_LEFT,
                              textColor=colors.HexColor("#0d6efd"), spaceBefore=10, spaceAfter=4))
    styles.add(ParagraphStyle(name="NormalLeft", fontSize=10.5, leading=14, alignment=TA_LEFT))
    styles.add(ParagraphStyle(name="Muted", fontSize=9, leading=11, alignment=TA_LEFT,
                              textColor=colors.HexColor("#6c757d")))
    return styles


def generate_pdf_report(user_email: str, ai_result: dict):
    """Generate a modern, well-styled PDF report"""
    safe_email_part = (user_email or "user").replace("@", "_at_").replace(".", "_")
    file_name = f"report_{safe_email_part}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    output_path = os.path.join(REPORTS_DIR, file_name)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=22 * mm,
        rightMargin=22 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    styles = _style_sheet()
    flow = []
    
    # --- GET SUMMARY DATA SAFELY (CRITICAL FIX) ---
    # Since summary is now a top-level key containing the scorecard and swot
    summary_data = ai_result.get("summary", {}) 
    
    # Extract data using the correct nested path
    # Use .get() defensively against both 'scorecard' and 'Scorecard' 
    scorecard = summary_data.get("scorecard", summary_data.get("Scorecard"))
    swot = summary_data.get("swot", summary_data.get("Swot")) 
    overview = summary_data.get("overview")
    recs = summary_data.get("recommendations")


    # Header section (Logo + Title)
    if os.path.exists(LOGO_PATH):
        try:
            img = Image(LOGO_PATH, width=110, height=30, kind="proportional")
            img.hAlign = "LEFT"
            flow.append(img)
        except Exception:
            pass

    flow.append(Spacer(1, 4))
    flow.append(Paragraph("<b>Validate My App Idea</b>", styles["TitleBig"]))
    flow.append(Spacer(1, 10))

    # Meta Info
    meta_table_data = [
        [
            Paragraph(f"<b>User:</b> {user_email or 'Unknown'}", styles["NormalLeft"]),
            Paragraph(f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["NormalLeft"])
        ]
    ]
    meta_tbl = Table(meta_table_data, colWidths=[260, 160])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#e7f1ff")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#0d6efd")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    flow.append(meta_tbl)
    flow.append(Spacer(1, 12))

    # Verdict
    verdict = ai_result.get("verdict") or "No Verdict"
    ai_score = ai_result.get("ai_score", "—")

    flow.append(Paragraph("Overall Verdict", styles["Section"]))
    flow.append(Paragraph(f"<b>{verdict}</b>", styles["NormalLeft"]))
    flow.append(Spacer(1, 6))
    flow.append(Paragraph("AI Score", styles["Section"]))
    flow.append(Paragraph(str(ai_score), styles["NormalLeft"]))
    flow.append(Spacer(1, 10))

    # Overview
    if overview:
        flow.append(Paragraph("Overview", styles["Section"]))
        flow.append(Paragraph(overview, styles["NormalLeft"]))
        flow.append(Spacer(1, 10))

    # Suggestions
    suggestions = ai_result.get("suggestions", [])
    if suggestions:
        flow.append(Paragraph("Suggestions", styles["Section"]))
        rows = [[Paragraph(f"• {s}", styles["NormalLeft"])] for s in suggestions]
        tbl = Table(rows, colWidths=[420])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1),
             [colors.HexColor("#f8fbff"), colors.HexColor("#eef5ff")]),
            ("BOX", (0, 0), (-1, -1), 0.25, colors.HexColor("#bcd0f7")),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        flow.append(tbl)
        flow.append(Spacer(1, 12))

    # Scorecard
    # scorecard variable is now correctly extracted from summary_data
    if isinstance(scorecard, dict) and scorecard:
        flow.append(Paragraph("Scorecard", styles["Section"]))
        rows = [["Metric", "Score"]] + [[k, str(v)] for k, v in scorecard.items()]
        tbl = Table(rows, colWidths=[220, 70])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d6efd")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d0e2ff")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#f0f7ff"), colors.HexColor("#e7f1ff")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        flow.append(tbl)
        flow.append(Spacer(1, 12))

    # SWOT
    # swot variable is now correctly extracted from summary_data
    if isinstance(swot, dict) and any(swot.get(k) for k in ("Strengths", "Weaknesses", "Opportunities", "Threats")):
        flow.append(Paragraph("SWOT Analysis", styles["Section"]))
        sw_colors = {
            # Note: We are using capitalized keys for display here, which is fine
            "Strengths": "#0d6efd",
            "Weaknesses": "#198754",
            "Opportunities": "#0d6efd",
            "Threats": "#198754"
        }
        
        # Check both capitalized and lowercase keys for robustness, matching gemini_api.py
        swot_keys_to_check = ["Strengths", "Weaknesses", "Opportunities", "Threats"]
        
        for key in swot_keys_to_check:
            # Check for capitalized key first, then lowercase key
            items = swot.get(key, swot.get(key.lower(), []))
            
            if items:
                flow.append(Paragraph(f"<b><font color='{sw_colors[key]}'>{key}</font></b>", styles["NormalLeft"]))
                sw_rows = [[Paragraph(f"• {i}", styles["NormalLeft"])] for i in items]
                tbl = Table(sw_rows, colWidths=[440])
                tbl.setStyle(TableStyle([
                    ("BOX", (0, 0), (-1, -1), 0.25, colors.HexColor("#bcd0f7")),
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fbff")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ]))
                flow.append(tbl)
                flow.append(Spacer(1, 8))

    # Recommendations
    # recs variable is now correctly extracted from summary_data
    if recs:
        flow.append(Paragraph("Recommendations", styles["Section"]))
        rec_rows = [[Paragraph(f"• {r}", styles["NormalLeft"])] for r in recs]
        tbl = Table(rec_rows, colWidths=[440])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1fdf6")),
            ("BOX", (0, 0), (-1, -1), 0.25, colors.HexColor("#198754")),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        flow.append(tbl)
        flow.append(Spacer(1, 10))

    # Footer
    flow.append(Spacer(1, 24))
    footer = Table([[Paragraph(
        "Generated by: Validate My App Idea • validateMyAppIdea.com",
        styles["Muted"]
    )]])
    footer.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER")
    ]))
    flow.append(footer)

    doc.build(flow)
    return output_path