"""
Risk Reporter — generates .xlsx reports from structured findings.
Now includes CVE reference URLs in a dedicated column.
"""
import os
from datetime import datetime

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

C_DARK_NAVY = "1F2937"
C_RED       = "DC2626";  C_LIGHT_RED = "FEE2E2"
C_ORANGE    = "EA580C";  C_LIGHT_ORG = "FED7AA"
C_YELLOW    = "D97706";  C_LIGHT_YEL = "FEF3C7"
C_GREEN     = "16A34A";  C_LIGHT_GRN = "DCFCE7"
C_BLUE      = "2563EB";  C_LIGHT_BLU = "DBEAFE"
C_WHITE     = "FFFFFF"

SEV_CONFIG = {
    "Critical":      (C_RED,    C_LIGHT_RED, "🔴"),
    "High":          (C_ORANGE, C_LIGHT_ORG, "🟠"),
    "Medium":        (C_YELLOW, C_LIGHT_YEL, "🟡"),
    "Low":           (C_GREEN,  C_LIGHT_GRN, "🟢"),
    "Informational": (C_BLUE,   C_LIGHT_BLU, "ℹ️"),
}
SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

def _border():
    s = Side(style="thin", color="D1D5DB")
    return Border(left=s, right=s, top=s, bottom=s)

def _hdr(ws, row, col, value, bg=C_DARK_NAVY, fg=C_WHITE):
    c = ws.cell(row=row, column=col, value=value)
    c.font = Font(name="Arial", bold=True, color=fg, size=9)
    c.fill = PatternFill("solid", start_color=bg)
    c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    c.border = _border()
    return c

def _cell(ws, row, col, value, bg=C_WHITE, bold=False,
          color="111827", align="left", wrap=True):
    c = ws.cell(row=row, column=col, value=value)
    c.font = Font(name="Arial", bold=bold, color=color, size=9)
    c.fill = PatternFill("solid", start_color=bg)
    c.alignment = Alignment(horizontal=align, vertical="center", wrap_text=wrap)
    c.border = _border()
    return c

def _title(ws, text, cols, bg=C_DARK_NAVY):
    ws.merge_cells(f"A1:{get_column_letter(cols)}1")
    c = ws["A1"]
    c.value = text
    c.font = Font(name="Arial", bold=True, size=13, color=C_WHITE)
    c.fill = PatternFill("solid", start_color=bg)
    c.alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[1].height = 28

def _cve_refs_text(cve_refs: list) -> str:
    """Format CVE refs as 'CVE-XXXX-XXXX → https://nvd...' lines."""
    if not cve_refs:
        return "None"
    lines = []
    for ref in cve_refs:
        cid = ref.get("id", "")
        url = ref.get("url", f"https://nvd.nist.gov/vuln/detail/{cid}")
        lines.append(f"{cid}\n{url}")
    return "\n\n".join(lines)

# ── Dashboard ─────────────────────────────────────────────────────────────────
def _dashboard(wb, findings, target, generated):
    ws = wb.active
    ws.title = "Dashboard"
    ws.sheet_view.showGridLines = False

    ws.merge_cells("A1:H1")
    c = ws["A1"]
    c.value = f"Vulnerability Assessment Report — {target}"
    c.font = Font(name="Arial", bold=True, size=16, color=C_WHITE)
    c.fill = PatternFill("solid", start_color=C_DARK_NAVY)
    c.alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[1].height = 36

    ws.merge_cells("A2:H2")
    c = ws["A2"]
    c.value = f"Generated: {generated}   |   Framework: LLM-VA (3-Phase Hybrid RAG)"
    c.font = Font(name="Arial", size=9, color="6B7280")
    c.alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[2].height = 18

    counts       = {s: 0 for s in SEV_CONFIG}
    exploit_count = 0
    for f in findings:
        sev = f.get("severity", "Informational")
        if sev in counts: counts[sev] += 1
        if f.get("has_exploit"): exploit_count += 1

    cards = [
        ("Services Analysed", str(len(findings)),      C_DARK_NAVY),
        ("Critical",          str(counts["Critical"]), C_RED),
        ("High",              str(counts["High"]),      C_ORANGE),
        ("Medium",            str(counts["Medium"]),    C_YELLOW),
        ("Low",               str(counts["Low"]),       C_GREEN),
        ("Informational",     str(counts["Informational"]), C_BLUE),
        ("Public Exploits",   str(exploit_count),       "DC2626"),
    ]
    for i, (label, val, bg) in enumerate(cards, 1):
        for r, h in zip((4,5,6), (16,32,8)): ws.row_dimensions[r].height = h
        lc = ws.cell(row=4, column=i, value=label)
        lc.font = Font(name="Arial", size=8, bold=True, color=C_WHITE)
        lc.fill = PatternFill("solid", start_color=bg)
        lc.alignment = Alignment(horizontal="center", vertical="center")
        vc = ws.cell(row=5, column=i, value=val)
        vc.font = Font(name="Arial", size=22, bold=True, color=C_WHITE)
        vc.fill = PatternFill("solid", start_color=bg)
        vc.alignment = Alignment(horizontal="center", vertical="center")

    ws.row_dimensions[7].height = 10
    for i, h in enumerate(["Severity","Count","% of Total"], 1):
        _hdr(ws, 8, i, h)
    ws.row_dimensions[8].height = 20
    total = len(findings) or 1
    for row, sev in enumerate(SEV_ORDER, 9):
        color, bg, _ = SEV_CONFIG[sev]
        _cell(ws, row, 1, sev, bg=bg, bold=True, color=color, align="center")
        _cell(ws, row, 2, counts[sev], align="center")
        pct = ws.cell(row=row, column=3)
        pct.value = f"=B{row}/{total}"
        pct.number_format = "0.0%"
        pct.font = Font(name="Arial", size=9)
        pct.alignment = Alignment(horizontal="center")
        pct.border = _border()
        ws.row_dimensions[row].height = 18

    for i, w in enumerate([22,10,12,12,12,14,14,14], 1):
        ws.column_dimensions[get_column_letter(i)].width = w

# ── Service Inventory ─────────────────────────────────────────────────────────
def _inventory(wb, findings):
    ws = wb.create_sheet("Service Inventory")
    ws.sheet_view.showGridLines = False
    ws.freeze_panes = "A3"
    _title(ws, "Service Inventory — All Open Ports", 8)

    hdrs = ["Port","Service / Version","Severity","CVSS",
            "CVE(s)","CVE References (NVD)","Public Exploit","LLM Analysis"]
    for i, h in enumerate(hdrs, 1): _hdr(ws, 2, i, h)
    ws.row_dimensions[2].height = 22

    order = {s:i for i,s in enumerate(SEV_ORDER)}
    sorted_f = sorted(findings,
                      key=lambda x: order.get(x.get("severity","Informational"), 99))

    for r, f in enumerate(sorted_f, 3):
        sev = f.get("severity","Informational")
        color, bg, emoji = SEV_CONFIG.get(sev, (C_BLUE, C_WHITE, ""))
        cvss     = f.get("cvss","N/A")
        cve_refs = _cve_refs_text(f.get("cve_refs", []))

        _cell(ws, r, 1, f.get("port","?"), align="center")
        _cell(ws, r, 2, f.get("service",""))
        _cell(ws, r, 3, f"{emoji} {sev}", bg=bg, bold=True, color=color, align="center")
        _cell(ws, r, 4, str(cvss), align="center")
        _cell(ws, r, 5, f.get("cves","None"))
        _cell(ws, r, 6, cve_refs, bg=C_LIGHT_BLU, wrap=True)
        exp = "Yes" if f.get("has_exploit") else "No"
        exp_bg = C_LIGHT_RED if exp=="Yes" else C_WHITE
        _cell(ws, r, 7, exp, bg=exp_bg, align="center")
        _cell(ws, r, 8, f.get("analysis",""), wrap=True)
        ws.row_dimensions[r].height = 22

    for i, w in enumerate([7,28,16,9,35,40,13,65], 1):
        ws.column_dimensions[get_column_letter(i)].width = w

# ── Critical & High ───────────────────────────────────────────────────────────
def _findings(wb, findings):
    ws = wb.create_sheet("Critical & High Findings")
    ws.sheet_view.showGridLines = False
    ws.freeze_panes = "A3"
    _title(ws, "Critical & High Risk Findings", 7, bg=C_RED)

    hdrs = ["Port","Service","Severity","CVSS","CVE(s)","CVE References","Analysis"]
    for i, h in enumerate(hdrs, 1): _hdr(ws, 2, i, h)
    ws.row_dimensions[2].height = 22

    r = 3
    order = {s:i for i,s in enumerate(SEV_ORDER)}
    for f in sorted(findings, key=lambda x: order.get(x.get("severity","Informational"),99)):
        if f.get("severity") not in ("Critical","High"):
            continue
        sev = f["severity"]
        color, bg, emoji = SEV_CONFIG[sev]
        cve_refs = _cve_refs_text(f.get("cve_refs", []))
        _cell(ws, r, 1, f.get("port","?"), align="center")
        _cell(ws, r, 2, f.get("service",""))
        _cell(ws, r, 3, f"{emoji} {sev}", bg=bg, bold=True, color=color, align="center")
        _cell(ws, r, 4, str(f.get("cvss","N/A")), align="center")
        _cell(ws, r, 5, f.get("cves","None"))
        _cell(ws, r, 6, cve_refs, bg=C_LIGHT_BLU, wrap=True)
        _cell(ws, r, 7, f.get("analysis",""), wrap=True)
        ws.row_dimensions[r].height = 22
        r += 1

    for i, w in enumerate([7,28,16,9,35,40,65], 1):
        ws.column_dimensions[get_column_letter(i)].width = w

# ── Remediation ───────────────────────────────────────────────────────────────
def _remediation(wb, findings):
    ws = wb.create_sheet("Remediation Plan")
    ws.sheet_view.showGridLines = False
    ws.freeze_panes = "A3"
    _title(ws, "Remediation Plan", 5, bg=C_GREEN)

    hdrs = ["Port","Service","Severity","Recommended Actions","CVE References"]
    for i, h in enumerate(hdrs, 1): _hdr(ws, 2, i, h)
    ws.row_dimensions[2].height = 22

    r = 3
    order = {s:i for i,s in enumerate(SEV_ORDER)}
    for f in sorted(findings, key=lambda x: order.get(x.get("severity","Informational"),99)):
        rem = f.get("remediation","")
        if not rem or f.get("severity") == "Informational":
            continue
        sev = f.get("severity","Informational")
        color, bg, emoji = SEV_CONFIG.get(sev, (C_BLUE,C_WHITE,""))
        steps = [s.strip() for s in rem.replace("|","\n").splitlines() if s.strip()]
        steps_text = "\n".join(f"• {s}" for s in steps)
        cve_refs = _cve_refs_text(f.get("cve_refs", []))

        _cell(ws, r, 1, f.get("port","?"), align="center")
        _cell(ws, r, 2, f.get("service",""))
        _cell(ws, r, 3, f"{emoji} {sev}", bg=bg, bold=True, color=color, align="center")
        _cell(ws, r, 4, steps_text, bg=C_LIGHT_GRN, wrap=True)
        _cell(ws, r, 5, cve_refs, bg=C_LIGHT_BLU, wrap=True)
        ws.row_dimensions[r].height = max(35, 18*len(steps))
        r += 1

    for i, w in enumerate([7,28,16,80,40], 1):
        ws.column_dimensions[get_column_letter(i)].width = w

# ── Public API ────────────────────────────────────────────────────────────────
class RiskReporter:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def save_report(self, report_name: str, findings: list,
                    cve_sources: dict = None, target: str = "") -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename  = f"{report_name}_report_{timestamp}.xlsx"
        filepath  = os.path.join(self.output_dir, filename)
        generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        wb = Workbook()
        _dashboard(wb, findings, target or report_name, generated)
        _inventory(wb, findings)
        _findings(wb, findings)
        _remediation(wb, findings)
        wb.save(filepath)
        return filepath