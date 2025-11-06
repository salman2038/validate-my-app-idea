import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT

# --- Directories ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "..", "data", "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


# --- Styles ---
def _get_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="Heading",
        fontSize=16,
        leading=18,
        textColor=colors.HexColor("#0d6efd"),
        spaceAfter=10,
        alignment=TA_LEFT
    ))
    styles.add(ParagraphStyle(
        name="Body",
        fontSize=11,
        leading=14,
        alignment=TA_LEFT
    ))
    return styles


# --- Main PDF Generator ---
def generate_pdf(data: dict):
    """
    Create a simple PDF report from AI evaluation data.
    Returns: full path to the generated PDF file.
    """
    styles = _get_styles()

    # Create file name
    user_email = data.get("user_email", "unknown_user")
    safe_email = user_email.replace("@", "_at_").replace(".", "_")
    file_name = f"report_{safe_email}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf_path = os.path.join(REPORTS_DIR, file_name)

    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    story = []

    # --- Header ---
    story.append(Paragraph("Validate My App Idea — AI Report", styles["Heading"]))
    story.append(Paragraph(f"Generated for: <b>{user_email}</b>", styles["Body"]))
    story.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Body"]))
    story.append(Spacer(1, 12))

    # --- Verdict & Score ---
    story.append(Paragraph(f"<b>Verdict:</b> {data.get('verdict', 'N/A')}", styles["Body"]))
    story.append(Paragraph(f"<b>AI Score:</b> {data.get('ai_score', '0')}", styles["Body"]))
    story.append(Spacer(1, 12))

    # --- Summary ---
    summary = data.get("summary", {})
    if summary:
        story.append(Paragraph("<b>Summary:</b>", styles["Heading"]))
        for key, value in summary.items():
            story.append(Paragraph(f"• <b>{key}</b>: {value}", styles["Body"]))
        story.append(Spacer(1, 10))

    # --- Suggestions ---
    suggestions = data.get("suggestions", [])
    if suggestions:
        story.append(Paragraph("<b>Suggestions:</b>", styles["Heading"]))
        for s in suggestions:
            story.append(Paragraph(f"• {s}", styles["Body"]))

    # --- Build PDF ---
    doc.build(story)
    return pdf_path
