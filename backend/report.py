"""
report.py -- turn a stored scan into a professional PDF (reportlab, pure-Python).

build_report(scan) -> bytes   where scan is the dict returned by db.get_scan().

Scan kinds:
    'audit'      -> SAST findings report
    'ai_report'  -> SAST findings report WITH the AI remediation under each finding
    'recon'      -> DAST report (open ports, banners, CVEs, directories)

A finding renders its AI fix only if it carries a 'remediation' dict, so the
same function produces both the fast (no-AI) report and the AI-remediated one.
"""

import io
import re
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

INK = colors.HexColor("#12121C")
DIM = colors.HexColor("#5B5B72")
LINE = colors.HexColor("#D8D8E4")
HIGH = colors.HexColor("#E23150")
MED = colors.HexColor("#E0952A")
LOW = colors.HexColor("#1E9BD7")
VIOLET = colors.HexColor("#7B4DFF")
CODE_BG = colors.HexColor("#F3F3F8")

SEV_COLOR = {"HIGH": HIGH, "MEDIUM": MED, "LOW": LOW, "INFO": LOW}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("Brand", parent=ss["Title"], fontName="Helvetica-Bold",
                          fontSize=20, textColor=INK, spaceAfter=2, leading=24))
    ss.add(ParagraphStyle("Sub", parent=ss["Normal"], fontName="Helvetica",
                          fontSize=9, textColor=DIM, spaceAfter=1))
    ss.add(ParagraphStyle("H2", parent=ss["Heading2"], fontName="Helvetica-Bold",
                          fontSize=12, textColor=INK, spaceBefore=14, spaceAfter=6))
    ss.add(ParagraphStyle("Body", parent=ss["Normal"], fontName="Helvetica",
                          fontSize=9, textColor=INK, leading=13, alignment=TA_LEFT))
    ss.add(ParagraphStyle("Meta", parent=ss["Normal"], fontName="Helvetica",
                          fontSize=8, textColor=DIM, leading=11))
    ss.add(ParagraphStyle("FindTitle", parent=ss["Normal"], fontName="Helvetica-Bold",
                          fontSize=10, textColor=INK, spaceAfter=1))
    ss.add(ParagraphStyle("RemLabel", parent=ss["Normal"], fontName="Helvetica-Bold",
                          fontSize=8.5, textColor=VIOLET, spaceBefore=5, spaceAfter=2,
                          leading=11))
    ss.add(ParagraphStyle("CodeBlk", parent=ss["Normal"], fontName="Courier",
                          fontSize=7.5, textColor=colors.HexColor("#26263A"), leading=10,
                          backColor=CODE_BG, borderPadding=5, leftIndent=2, rightIndent=2))
    ss.add(ParagraphStyle("Ctx", parent=ss["Normal"], fontName="Courier",
                          fontSize=7, textColor=colors.HexColor("#3A3A4A"), leading=9.5))
    ss.add(ParagraphStyle("CtxFlag", parent=ss["Normal"], fontName="Courier-Bold",
                          fontSize=7, textColor=colors.HexColor("#B0122B"), leading=9.5))
    return ss


def _p(text: Any, style) -> Paragraph:
    s = "" if text is None else str(text)
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return Paragraph(s, style)


def _code_block(text: Any, ss) -> Paragraph:
    """Render code preserving indentation and line breaks, still wrappable."""
    out = []
    for ln in (str(text) if text else "").split("\n"):
        stripped = ln.lstrip(" ")
        indent = len(ln) - len(stripped)
        esc = stripped.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        out.append("&nbsp;" * indent + esc)
    return Paragraph("<br/>".join(out) or "&nbsp;", ss["CodeBlk"])


# light backgrounds for the code snapshot (print-friendly versions of the UI)
CTX_BG = colors.HexColor("#F7F7FB")
CTX_FLAG_BG = colors.HexColor("#FCE4E8")


def _ctx_line(line: str, ss, flagged: bool) -> Paragraph:
    stripped = line.lstrip(" ")
    indent = len(line) - len(stripped)
    esc = stripped.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    txt = "&nbsp;" * indent + esc
    return Paragraph(txt or "&nbsp;", ss["CtxFlag"] if flagged else ss["Ctx"])


def _context_block(context: Any, ss) -> Table:
    """Render the code snapshot; the flagged line (marked '>>') gets a red row."""
    lines = str(context).split("\n")
    rows, extra = [], []
    for idx, ln in enumerate(lines):
        flagged = bool(re.match(r"^\s*\d+\s*>>", ln))
        rows.append([_ctx_line(ln, ss, flagged)])
        if flagged:
            extra.append(("BACKGROUND", (0, idx), (0, idx), CTX_FLAG_BG))
            extra.append(("LINEBEFORE", (0, idx), (0, idx), 2, HIGH))
    t = Table(rows, colWidths=[None])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CTX_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 0.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ] + extra))
    return t


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(DIM)
    canvas.drawString(18 * mm, 12 * mm, "Vuln-Mapper  \u00b7  Authorized security testing only")
    canvas.drawRightString(A4[0] - 18 * mm, 12 * mm, f"Page {doc.page}")
    canvas.setStrokeColor(LINE)
    canvas.line(18 * mm, 15 * mm, A4[0] - 18 * mm, 15 * mm)
    canvas.restoreState()


def build_report(scan: Dict[str, Any]) -> bytes:
    ss = _styles()
    story: List[Any] = []

    kind = scan.get("kind", "recon")
    label = scan.get("label", "")
    created = scan.get("created_at", "")
    result = scan.get("result") or {}

    story.append(_p("Vuln-Mapper Security Report", ss["Brand"]))
    if kind == "ai_report":
        kind_label = "AI-Remediated Code Audit (SAST)"
    elif kind == "audit":
        kind_label = "Static Code Audit (SAST)"
    else:
        kind_label = "Infrastructure Recon (DAST)"
    story.append(_p(kind_label, ss["Sub"]))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1, color=LINE))
    story.append(Spacer(1, 8))

    meta = [
        [_p("Target", ss["Meta"]), _p(label, ss["Body"])],
        [_p("Scan ID", ss["Meta"]), _p(scan.get("id", ""), ss["Body"])],
        [_p("Generated", ss["Meta"]), _p(created.replace("T", " "), ss["Body"])],
    ]
    mt = Table(meta, colWidths=[28 * mm, None])
    mt.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(mt)

    if kind in ("audit", "ai_report"):
        _audit_body(story, ss, result)
    else:
        _recon_body(story, ss, result)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=22 * mm,
        title="Vuln-Mapper Report",
    )
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()


def _sev_chip(sev: str) -> Table:
    sev = (sev or "").upper()
    col = SEV_COLOR.get(sev, LOW)
    t = Table([[sev or "-"]], colWidths=[18 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), col),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _audit_body(story, ss, result):
    summary = result.get("summary", {}) or {}
    findings = result.get("findings", []) or []

    story.append(_p("Executive Summary", ss["H2"]))
    cells = [
        [_p(str(summary.get("total", 0)), ss["Brand"]),
         _p(str(summary.get("high", 0)), ss["Brand"]),
         _p(str(summary.get("medium", 0)), ss["Brand"]),
         _p(str(summary.get("low", 0)), ss["Brand"])],
        [_p("Total", ss["Meta"]), _p("High", ss["Meta"]),
         _p("Medium", ss["Meta"]), _p("Low", ss["Meta"])],
    ]
    st = Table(cells, colWidths=[None] * 4)
    st.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TEXTCOLOR", (1, 0), (1, 0), HIGH),
        ("TEXTCOLOR", (2, 0), (2, 0), MED),
        ("TEXTCOLOR", (3, 0), (3, 0), LOW),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(st)

    story.append(_p("Findings", ss["H2"]))
    if not findings:
        story.append(_p("No issues were found in the scanned source.", ss["Body"]))
        return

    for i, f in enumerate(findings, 1):
        head = Table(
            [[_sev_chip(f.get("severity", "")),
              _p(f"{i}. {f.get('title') or f.get('rule_id') or 'finding'}", ss["FindTitle"])]],
            colWidths=[20 * mm, None],
        )
        head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                  ("LEFTPADDING", (1, 0), (1, 0), 6)]))
        story.append(Spacer(1, 6))
        story.append(head)

        loc = f"{f.get('file','')}:{f.get('line','')}   \u00b7   {f.get('tool','')}"
        if f.get("cwe"):
            loc += f"   \u00b7   {f.get('cwe')}"
        story.append(_p(loc, ss["Meta"]))
        if f.get("message"):
            story.append(_p(f.get("message"), ss["Body"]))

        # --- code snapshot with the vulnerable line highlighted ---
        if f.get("context"):
            story.append(Spacer(1, 3))
            story.append(_context_block(f.get("context"), ss))

        # --- AI remediation, only if attached ---
        rem = f.get("remediation")
        if rem:
            story.append(_p("Root cause", ss["RemLabel"]))
            story.append(_p(rem.get("root_cause", ""), ss["Body"]))
            story.append(_p("How it's exploited", ss["RemLabel"]))
            story.append(_p(rem.get("attack_mechanics", ""), ss["Body"]))
            story.append(_p("Secure fix", ss["RemLabel"]))
            story.append(_code_block(rem.get("secure_code", ""), ss))

        story.append(HRFlowable(width="100%", thickness=0.4, color=LINE, spaceBefore=6, spaceAfter=0))


def _recon_body(story, ss, result):
    recon = result.get("recon", []) or []
    directories = result.get("directories", []) or []

    story.append(_p("Executive Summary", ss["H2"]))
    story.append(_p(
        f"{len(recon)} open port(s) discovered; {len(directories)} exposed director"
        f"{'y' if len(directories) == 1 else 'ies'} found.",
        ss["Body"]))

    story.append(_p("Open Ports & Services", ss["H2"]))
    if not recon:
        story.append(_p("No open ports were discovered.", ss["Body"]))
    for res in recon:
        story.append(Spacer(1, 4))
        story.append(_p(f"Port {res.get('port','')}  \u00b7  {res.get('service_banner','')}", ss["FindTitle"]))
        vulns = res.get("vulnerabilities", []) or []
        if not vulns:
            story.append(_p("No CVEs matched, or version hidden.", ss["Meta"]))
        elif vulns[0].get("error"):
            story.append(_p(f"CVE lookup: {vulns[0]['error']}", ss["Meta"]))
        else:
            for v in vulns:
                story.append(_p(f"{v.get('cve_id','')}  -  {v.get('summary','')}", ss["Body"]))
        story.append(HRFlowable(width="100%", thickness=0.4, color=LINE, spaceBefore=4, spaceAfter=0))

    if directories:
        story.append(_p("Exposed Directories", ss["H2"]))
        rows = [[_p("Path", ss["Meta"]), _p("Status", ss["Meta"])]]
        for d in directories:
            rows.append([_p(d.get("directory", ""), ss["Body"]), _p(str(d.get("status", "")), ss["Body"])])
        dt = Table(rows, colWidths=[None, 24 * mm])
        dt.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.5, LINE),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE),
            ("BACKGROUND", (0, 0), (-1, 0), CODE_BG),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(dt)