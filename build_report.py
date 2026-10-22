"""
Build script — generates docs/Project_Report.pdf using ReportLab.
Run once: py build_report.py
This file is NOT part of the application; app.py is the sole application file.
"""

import os
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

os.makedirs("docs", exist_ok=True)

# ── Colour palette ────────────────────────────────────────────────────────────
C_DARK    = colors.HexColor("#1f2328")
C_MUTED   = colors.HexColor("#57606a")
C_ACCENT  = colors.HexColor("#3b82d4")
C_SURFACE = colors.HexColor("#f7f8fa")
C_BORDER  = colors.HexColor("#e5e7eb")
C_RED_BG  = colors.HexColor("#fee2e2")
C_RED_FG  = colors.HexColor("#b91c1c")
C_YEL_BG  = colors.HexColor("#fef3c7")
C_YEL_FG  = colors.HexColor("#92400e")
C_GRN_BG  = colors.HexColor("#d1fae5")
C_GRN_FG  = colors.HexColor("#065f46")
C_HEAD_BG = colors.HexColor("#e8edf3")
C_WHITE   = colors.white

PAGE_W, PAGE_H = A4
MARGIN = 2.2 * cm

# ── Styles ────────────────────────────────────────────────────────────────────
base = getSampleStyleSheet()

def style(name, parent="Normal", **kw):
    s = ParagraphStyle(name, parent=base[parent])
    for k, v in kw.items():
        setattr(s, k, v)
    return s

S_TITLE    = style("ReportTitle",    fontSize=26, leading=32, textColor=C_DARK,
                   alignment=TA_CENTER, spaceAfter=6, fontName="Helvetica-Bold")
S_SUBTITLE = style("Subtitle",       fontSize=13, leading=18, textColor=C_MUTED,
                   alignment=TA_CENTER, spaceAfter=4)
S_META     = style("Meta",           fontSize=10, leading=14, textColor=C_MUTED,
                   alignment=TA_CENTER, spaceAfter=18)
S_H1       = style("H1",             fontSize=15, leading=20, textColor=C_DARK,
                   fontName="Helvetica-Bold", spaceBefore=18, spaceAfter=6)
S_H2       = style("H2",             fontSize=12, leading=16, textColor=C_ACCENT,
                   fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=4)
S_BODY     = style("Body",           fontSize=10, leading=15, textColor=C_DARK,
                   alignment=TA_JUSTIFY, spaceAfter=6)
S_BULLET   = style("Bullet",         fontSize=10, leading=15, textColor=C_DARK,
                   leftIndent=14, firstLineIndent=0, spaceAfter=3,
                   bulletIndent=4)
S_CALLOUT  = style("Callout",        fontSize=9.5, leading=14,
                   textColor=colors.HexColor("#78350f"),
                   backColor=colors.HexColor("#fffbeb"),
                   borderPadding=(6, 8, 6, 8), spaceAfter=8)
S_TH       = style("TH", fontSize=9, leading=13, textColor=C_DARK,
                   fontName="Helvetica-Bold", alignment=TA_LEFT)
S_TD       = style("TD", fontSize=9, leading=13, textColor=C_DARK,
                   alignment=TA_LEFT)
S_FOOTER   = style("Footer", fontSize=8, leading=11, textColor=C_MUTED,
                   alignment=TA_CENTER)

def h1(text):
    return [Paragraph(text, S_H1), HRFlowable(width="100%", thickness=0.5,
            color=C_BORDER, spaceAfter=4)]

def h2(text):
    return [Paragraph(text, S_H2)]

def body(text):
    return Paragraph(text, S_BODY)

def bullet(text):
    return Paragraph(f"• &nbsp; {text}", S_BULLET)

def sp(h=6):
    return Spacer(1, h)

def callout(text):
    return Paragraph(f"<b>⚠ Ethical Use:</b> {text}", S_CALLOUT)

def table(data, col_widths, row_styles=None):
    page_inner = PAGE_W - 2 * MARGIN
    if col_widths == "auto":
        col_widths = [page_inner / len(data[0])] * len(data[0])
    else:
        # scale proportionally to page width
        total = sum(col_widths)
        col_widths = [w / total * page_inner for w in col_widths]

    # wrap every cell string in a Paragraph
    wrapped = []
    for i, row in enumerate(data):
        s = S_TH if i == 0 else S_TD
        wrapped.append([Paragraph(str(c), s) for c in row])

    t = Table(wrapped, colWidths=col_widths, repeatRows=1)
    base_style = [
        ("BACKGROUND",  (0, 0), (-1, 0),  C_HEAD_BG),
        ("GRID",        (0, 0), (-1, -1), 0.4, C_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_SURFACE]),
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0,0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",(0, 0), (-1, -1), 6),
    ]
    if row_styles:
        base_style.extend(row_styles)
    t.setStyle(TableStyle(base_style))
    return t

# ── Page template with footer ─────────────────────────────────────────────────
def on_page(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(C_MUTED)
    canvas.drawCentredString(PAGE_W / 2, 1.2 * cm,
        "Automated Web Security Scanner  ·  Project Report  ·  Passive checks only")
    canvas.drawRightString(PAGE_W - MARGIN, 1.2 * cm, f"Page {doc.page}")
    canvas.restoreState()

# ── Document ──────────────────────────────────────────────────────────────────
doc = SimpleDocTemplate(
    "docs/Project_Report.pdf",
    pagesize=A4,
    leftMargin=MARGIN, rightMargin=MARGIN,
    topMargin=2 * cm, bottomMargin=2 * cm,
    title="Automated Web Security Scanner — Project Report",
    author="Cybersecurity Project",
)

story = []

# ── Cover ─────────────────────────────────────────────────────────────────────
story.append(Spacer(1, 1.8 * cm))
story.append(Paragraph("🔐 Automated Web Security Scanner", S_TITLE))
story.append(Paragraph("Project Report — Cybersecurity Project", S_SUBTITLE))
story.append(Paragraph(
    "Language: Python 3.10+  &nbsp;|&nbsp;  Framework: Streamlit  "
    "&nbsp;|&nbsp;  Approach: Passive / Read-only", S_META))
story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceAfter=10))
story.append(Spacer(1, 0.6 * cm))

# cover meta table
cover_data = [
    ["Project Type", "Cybersecurity Tool",   "Key Libraries", "requests, urllib.parse"],
    ["Language",     "Python 3.10+",         "Deployment",    "Local (localhost:8501)"],
    ["Framework",    "Streamlit",            "Scan Type",     "Passive / Read-only"],
]
inner_w = PAGE_W - 2 * MARGIN
cw = [inner_w * 0.18, inner_w * 0.32, inner_w * 0.18, inner_w * 0.32]
cov_rows = []
for row in cover_data:
    cov_rows.append([
        Paragraph(f"<b>{row[0]}</b>", S_TD),
        Paragraph(row[1], S_TD),
        Paragraph(f"<b>{row[2]}</b>", S_TD),
        Paragraph(row[3], S_TD),
    ])
ct = Table(cov_rows, colWidths=cw)
ct.setStyle(TableStyle([
    ("BACKGROUND",   (0,0), (-1,-1), C_SURFACE),
    ("GRID",         (0,0), (-1,-1), 0.4, C_BORDER),
    ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ("TOPPADDING",   (0,0), (-1,-1), 6),
    ("BOTTOMPADDING",(0,0), (-1,-1), 6),
    ("LEFTPADDING",  (0,0), (-1,-1), 8),
    ("RIGHTPADDING", (0,0), (-1,-1), 8),
]))
story.append(ct)
story.append(Spacer(1, 1.2 * cm))
story.append(PageBreak())

# ── 1. Introduction ───────────────────────────────────────────────────────────
story += h1("1. Introduction")
story.append(body(
    "Web application security is a growing concern in modern software development. "
    "Many common vulnerabilities — including Cross-Site Scripting (XSS), clickjacking, "
    "and man-in-the-middle attacks — can be significantly mitigated through the correct "
    "configuration of HTTP security response headers. Yet misconfigured or missing headers "
    "remain one of the most frequently observed weaknesses in real-world web applications."
))
story.append(body(
    "This project implements an <b>Automated Web Security Scanner</b>: an interactive tool "
    "that allows a developer or security professional to assess the HTTP security posture of "
    "a web server they own or control. The tool performs entirely passive, non-intrusive "
    "checks — it reads response headers and reports findings with severity ratings and "
    "remediation guidance, without sending any attack payloads or attempting to exploit "
    "vulnerabilities."
))
story.append(callout(
    "This tool is designed exclusively for use against websites the operator owns or has "
    "explicit written permission to assess. Scanning third-party websites without permission "
    "may be illegal and is strictly outside the intended scope of this project."
))

# ── 2. Objectives ─────────────────────────────────────────────────────────────
story += h1("2. Objectives")
for obj in [
    "Build a single-file Python application (<b>app.py</b>) covering both scanner logic and dashboard UI",
    "Perform passive HTTP security header checks against a user-supplied URL",
    "Detect missing or misconfigured security headers: CSP, HSTS, X-Content-Type-Options, X-Frame-Options",
    "Perform a basic CORS configuration check by reading the Access-Control-Allow-Origin header",
    "Classify each finding with a severity level (High / Medium / Pass)",
    "Provide clear explanations and actionable remediation advice for each finding",
    "Implement robust input validation and error handling (timeouts, SSL errors, connection failures)",
    "Present results through a professional, user-friendly Streamlit dashboard",
]:
    story.append(bullet(obj))
story.append(sp())

# ── 3. Technologies Used ──────────────────────────────────────────────────────
story += h1("3. Technologies Used")
story.append(table(
    [
        ["Technology", "Version", "Role"],
        ["Python", "3.10+", "Core programming language"],
        ["Streamlit", "≥ 1.35.0", "Web dashboard framework — renders the interactive UI"],
        ["Requests", "≥ 2.32.0", "HTTP GET requests to retrieve response headers from the target"],
        ["urllib.parse", "Standard library", "URL parsing and scheme validation before any network call"],
    ],
    [0.22, 0.20, 0.58],
))
story.append(sp())

# ── 4. System Architecture ────────────────────────────────────────────────────
story += h1("4. System Architecture")
story.append(body(
    "The entire application is contained within a single file, <b>app.py</b>, organised "
    "into three logical sections that follow a clean data-flow pipeline:"
))
story += h2("4.1 Section Breakdown")
story.append(table(
    [
        ["Section", "Contents"],
        ["Section 1 — Constants & Templates",
         "REQUEST_TIMEOUT (10 s) and the SECURITY_HEADERS dictionary, which centralises "
         "header names, failure explanations, remediation text, and default severity for "
         "each of the four required headers."],
        ["Section 2 — Scanner Engine",
         "Pure functions: validate_url(), check_https(), fetch_response(), "
         "check_security_headers(), check_cors(), and run_scan(). "
         "No Streamlit imports — fully testable in isolation."],
        ["Section 3 — Streamlit Dashboard",
         "render_finding_card() and main(). Handles all UI layout, user interaction, "
         "spinner, metrics row, and finding cards."],
    ],
    [0.30, 0.70],
))

story += h2("4.2 Data Flow")
for i, step in enumerate([
    "User enters a URL and clicks Run Scan",
    "validate_url() checks scheme and hostname — halts on invalid input",
    "check_https() evaluates the URL scheme without a network call",
    "fetch_response() issues one GET request with a 10-second timeout and follows redirects",
    "check_security_headers() iterates over all four required headers",
    "check_cors() reads the Access-Control-Allow-Origin header value",
    "run_scan() assembles all findings into a flat list of dicts",
    "The dashboard counts severities, renders summary metrics, sorts findings, and displays expander cards",
], 1):
    story.append(Paragraph(f"{i}.&nbsp; {step}", S_BULLET))
story.append(sp())

# ── 5. Security Checks ────────────────────────────────────────────────────────
story += h1("5. Implemented Security Checks")

checks = [
    ("5.1 HTTPS Usage", "HIGH",
     "Inspects the URL scheme using urllib.parse.urlparse(). If the scheme is http, the "
     "finding is rated High — plain HTTP traffic is unencrypted and susceptible to "
     "man-in-the-middle (MITM) interception. No network request is required for this check."),
    ("5.2 Content-Security-Policy (CSP)", "HIGH",
     "Checks for the presence of the Content-Security-Policy response header. CSP allows a "
     "server to declare trusted content sources, significantly reducing the attack surface "
     "for Cross-Site Scripting (XSS) and data-injection attacks. Absence is rated High."),
    ("5.3 Strict-Transport-Security (HSTS)", "HIGH",
     "Checks for the Strict-Transport-Security header. HSTS instructs browsers to "
     "communicate with the site exclusively over HTTPS, preventing SSL-stripping attacks "
     "and accidental HTTP connections. Absence is rated High."),
    ("5.4 X-Content-Type-Options", "MEDIUM",
     "Checks for the X-Content-Type-Options: nosniff header. Without it, some browsers "
     "perform MIME-type sniffing, which can allow an attacker to cause a text file to be "
     "interpreted as JavaScript. Absence is rated Medium."),
    ("5.5 X-Frame-Options", "MEDIUM",
     "Checks for the X-Frame-Options header, which prevents the page from being embedded "
     "in an iframe on a different domain. Its absence makes the site vulnerable to "
     "clickjacking. Absence is rated Medium."),
    ("5.6 CORS Configuration", "MEDIUM",
     "Passively reads the Access-Control-Allow-Origin (ACAO) header. If the value is * "
     "(wildcard), the finding is rated Medium — any third-party website can read responses "
     "from this endpoint. A specific origin value or absence of the header both receive a Pass."),
]

for title, sev, desc in checks:
    story += h2(title)
    sev_color = C_RED_FG if sev == "HIGH" else C_YEL_FG
    sev_bg    = C_RED_BG if sev == "HIGH" else C_YEL_BG
    sev_label = "🔴 High" if sev == "HIGH" else "⚠ Medium"
    story.append(Paragraph(
        f'<font color="#{sev_color.hexval()[2:]}"><b>Severity if missing: {sev_label}</b></font>',
        style("SevLine", fontSize=9, leading=13, spaceAfter=3)
    ))
    story.append(body(desc))

story.append(PageBreak())

# ── 6. Input Validation & Error Handling ─────────────────────────────────────
story += h1("6. Input Validation & Error Handling")
story += h2("6.1 Input Validation")
story.append(body(
    "Before any network call is made, <b>validate_url()</b> uses "
    "<b>urllib.parse.urlparse()</b> to verify: (1) the URL is non-empty, "
    "(2) the scheme is strictly <b>http</b> or <b>https</b>, and "
    "(3) a valid hostname is present. Invalid input is rejected with a descriptive "
    "error message rendered via st.error(), and execution halts with st.stop()."
))
story += h2("6.2 Network Error Handling")
story.append(body(
    "The fetch_response() function wraps requests.get() in a try/except block "
    "covering four exception classes:"
))
story.append(table(
    [
        ["Exception", "Cause", "User-facing Message"],
        ["requests.exceptions.Timeout",
         "Server did not respond within 10 seconds",
         "Timeout message with the configured timeout value"],
        ["requests.exceptions.SSLError",
         "Invalid or expired TLS certificate",
         "SSL error with the exception detail"],
        ["requests.exceptions.ConnectionError",
         "DNS failure, refused connection, or network unreachable",
         "Connection error with the exception detail"],
        ["requests.exceptions.RequestException",
         "Any other requests-level failure",
         "Generic request failure message"],
    ],
    [0.36, 0.34, 0.30],
))
story.append(body(
    "On error, a High-severity finding is added to the results list instead of "
    "raising an unhandled exception. The user sees a clear message within the normal scan results UI."
))
story.append(sp())

# ── 7. Dashboard Design ───────────────────────────────────────────────────────
story += h1("7. Dashboard Design")
story.append(body(
    "The Streamlit dashboard is structured into five areas. Finding cards are ordered by "
    "severity (failures first, then warnings, then passes). FAIL and WARN cards are "
    "auto-expanded so the most critical issues are immediately visible."
))
story.append(table(
    [
        ["Area", "Streamlit Component", "Purpose"],
        ["Header",        "st.title, st.caption",           "Project title and ethical-use disclaimer"],
        ["Sidebar",       "st.text_input, st.button",       "URL entry, scan trigger, checks list, ethical-use warning"],
        ["Pre-scan Info", "st.columns, st.markdown",        "Tool description, severity legend, usage instructions"],
        ["Results",       "st.metric, st.expander",         "Summary counts (total/pass/warn/fail) + per-finding cards"],
        ["Footer",        "st.caption",                     "Responsible-use reminder"],
    ],
    [0.20, 0.30, 0.50],
))
story.append(sp())

# ── 8. Severity Model ─────────────────────────────────────────────────────────
story += h1("8. Severity Model")
sev_data = [
    ["Status", "Severity", "Meaning", "UI Behaviour"],
    ["FAIL",   "High",     "Missing or misconfigured control with direct security impact",
     "Red badge — card auto-expanded"],
    ["WARN",   "Medium",   "Configuration that increases risk but may be intentional",
     "Orange badge — card auto-expanded"],
    ["PASS",   "Informational", "Control is present and configured",
     "Green badge — card collapsed"],
]
sev_row_styles = [
    ("BACKGROUND", (0,1), (-1,1), C_RED_BG),
    ("BACKGROUND", (0,2), (-1,2), C_YEL_BG),
    ("BACKGROUND", (0,3), (-1,3), C_GRN_BG),
]
story.append(table(sev_data, [0.12, 0.16, 0.44, 0.28], row_styles=sev_row_styles))
story.append(sp())

# ── 9. Finding Data Model ─────────────────────────────────────────────────────
story += h1("9. Finding Data Model")
story.append(body(
    "Each finding is represented as a plain Python dict with four keys, "
    "providing a consistent, predictable structure across all checks:"
))
story.append(table(
    [
        ["Key", "Type", "Example Value"],
        ["check",       "str", "\"Content-Security-Policy (CSP)\""],
        ["status",      "str", "\"FAIL\" | \"WARN\" | \"PASS\""],
        ["explanation", "str", "Human-readable description of what was found and why it matters"],
        ["remediation", "str", "Concrete, actionable fix instruction"],
    ],
    [0.22, 0.14, 0.64],
))
story.append(sp())

# ── 10. Limitations ───────────────────────────────────────────────────────────
story += h1("10. Limitations")
for lim in [
    "<b>Header presence only:</b> The tool checks for the existence of headers, not the "
    "correctness of their values (e.g., it does not validate whether a CSP policy is "
    "restrictive or overly permissive).",
    "<b>Single endpoint:</b> Headers are checked on the single URL provided. Other pages "
    "or API endpoints on the same server may have different header configurations.",
    "<b>No authentication:</b> The scanner makes unauthenticated requests; headers that "
    "only apply behind a login are not assessed.",
    "<b>No active testing:</b> By design, no payloads are injected and no active "
    "exploitation attempts are made — this is a feature, not a gap.",
    "<b>Firewall sensitivity:</b> Some servers may block or alter responses to requests "
    "from automated user agents.",
]:
    story.append(bullet(lim))
story.append(sp())

# ── 11. Future Improvements ───────────────────────────────────────────────────
story += h1("11. Potential Future Improvements")
for imp in [
    "CSP policy strength analysis (detecting <i>unsafe-inline</i> or <i>unsafe-eval</i> directives)",
    "HSTS max-age value validation (flagging values below the recommended 31,536,000 seconds)",
    "Cookie security attribute checks (Secure, HttpOnly, SameSite)",
    "Referrer-Policy and Permissions-Policy header checks",
    "Exportable scan report (PDF or JSON download)",
    "Multi-URL batch scanning",
]:
    story.append(bullet(imp))
story.append(sp())

# ── 12. Conclusion ────────────────────────────────────────────────────────────
story += h1("12. Conclusion")
story.append(body(
    "The Automated Web Security Scanner successfully meets all defined objectives. "
    "It provides a passive, safe, and user-friendly tool for identifying common HTTP "
    "security header misconfigurations. The application is built entirely within a single "
    "Python file, uses only two third-party libraries, and produces clear, actionable "
    "output that a developer can act on immediately."
))
story.append(body(
    "The project demonstrates practical application of cybersecurity concepts — including "
    "transport security, content injection defences, framing attacks, and CORS — within a "
    "real, working tool. Its passive-only design ensures it can be used responsibly and "
    "legally on targets the operator controls."
))

# ── Build ─────────────────────────────────────────────────────────────────────
doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
print("PDF written to docs/Project_Report.pdf")
