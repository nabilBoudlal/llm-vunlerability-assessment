"""
Risk Reporter — generates .xlsx reports from structured findings.
v3 — adds CISA KEV column, multi-source CVE badges, actively_exploited flag.
"""
import os
from datetime import datetime

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# ── Palette ───────────────────────────────────────────────────────────────────
C_DARK_NAVY = "1F2937"
C_RED       = "DC2626";  C_LIGHT_RED = "FEE2E2"
C_ORANGE    = "EA580C";  C_LIGHT_ORG = "FED7AA"
C_YELLOW    = "D97706";  C_LIGHT_YEL = "FEF3C7"
C_GREEN     = "16A34A";  C_LIGHT_GRN = "DCFCE7"
C_BLUE      = "2563EB";  C_LIGHT_BLU = "DBEAFE"
C_PURPLE    = "7C3AED";  C_LIGHT_PUR = "EDE9FE"
C_WHITE     = "FFFFFF"
C_KEV_BG    = "FFF1F2"   # soft red tint for KEV-positive rows

SEV_CONFIG = {
    "Critical":      (C_RED,    C_LIGHT_RED, "🔴"),
    "High":          (C_ORANGE, C_LIGHT_ORG, "🟠"),
    "Medium":        (C_YELLOW, C_LIGHT_YEL, "🟡"),
    "Low":           (C_GREEN,  C_LIGHT_GRN, "🟢"),
    "Informational": (C_BLUE,   C_LIGHT_BLU, "ℹ️"),
}
SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

SOURCE_BADGE = {
    "nvd":       "NVD",
    "osv":       "OSV",
    "circl":     "CIRCL",
    "exploitdb": "EDB",
    "cisa_kev":  "KEV",
}

# ── Style helpers ─────────────────────────────────────────────────────────────
def _border():
    s = Side(style="thin", color="D1D5DB")
    return Border(left=s, right=s, top=s, bottom=s)

def _hdr(ws, row, col, value, bg=C_DARK_NAVY, fg=C_WHITE):
    c = ws.cell(row=row, column=col, value=value)
    c.font      = Font(name="Arial", bold=True, color=fg, size=9)
    c.fill      = PatternFill("solid", start_color=bg)
    c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    c.border    = _border()
    return c

def _cell(ws, row, col, value, bg=C_WHITE, bold=False,
          color="111827", align="left", wrap=True):
    c = ws.cell(row=row, column=col, value=value)
    c.font      = Font(name="Arial", bold=bold, color=color, size=9)
    c.fill      = PatternFill("solid", start_color=bg)
    c.alignment = Alignment(horizontal=align, vertical="center", wrap_text=wrap)
    c.border    = _border()
    return c

def _title(ws, text, cols, bg=C_DARK_NAVY):
    ws.merge_cells(f"A1:{get_column_letter(cols)}1")
    c       = ws["A1"]
    c.value = text
    c.font  = Font(name="Arial", bold=True, size=13, color=C_WHITE)
    c.fill  = PatternFill("solid", start_color=bg)
    c.alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[1].height = 28

# ── CVE reference formatting ──────────────────────────────────────────────────
def _cve_refs_text(cve_refs: list) -> str:
    """
    Format CVE refs as multi-line text:
        CVE-XXXX-XXXX  [NVD | CIRCL]  🚨KEV
        https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXX
    """
    if not cve_refs:
        return "None"
    lines = []
    for ref in cve_refs:
        cid     = ref.get("id", "")
        url     = ref.get("url", f"https://nvd.nist.gov/vuln/detail/{cid}")
        sources = ref.get("sources", [])
        kev     = ref.get("actively_exploited", False)

        badge_str = ""
        if sources:
            badges = [SOURCE_BADGE.get(s, s.upper()) for s in sources]
            badge_str = "  [" + " | ".join(badges) + "]"
        kev_str = "  🚨KEV" if kev else ""

        lines.append(f"{cid}{badge_str}{kev_str}\n{url}")
    return "\n\n".join(lines)


def _build_cve_refs(cves_cited: list, cve_sources: dict) -> list:
    """
    Build a list of cve_ref dicts from cited CVE IDs and the global cve_sources map.
    Each dict: {id, url, cvss, sources, has_exploit, actively_exploited}
    """
    refs = []
    for cid in (cves_cited or []):
        src = (cve_sources or {}).get(cid, {})
        refs.append({
            "id":                cid,
            "url":               f"https://nvd.nist.gov/vuln/detail/{cid}",
            "cvss":              src.get("cvss", "N/A"),
            "sources":           src.get("sources", []),
            "has_exploit":       src.get("has_exploit", False),
            "actively_exploited": src.get("actively_exploited", False),
        })
    return refs


# ── Dashboard ─────────────────────────────────────────────────────────────────
def _dashboard(wb, findings, target, generated):
    ws = wb.active
    ws.title = "Dashboard"
    ws.sheet_view.showGridLines = False

    ws.merge_cells("A1:I1")
    c       = ws["A1"]
    c.value = f"Vulnerability Assessment Report — {target}"
    c.font  = Font(name="Arial", bold=True, size=16, color=C_WHITE)
    c.fill  = PatternFill("solid", start_color=C_DARK_NAVY)
    c.alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[1].height = 36

    ws.merge_cells("A2:I2")
    c       = ws["A2"]
    c.value = (f"Generated: {generated}   |   "
               f"Framework: LLM-VA (3-Phase Hybrid RAG)   |   "
               f"Sources: NVD · OSV · Exploit-DB · CIRCL · CISA KEV")
    c.font  = Font(name="Arial", size=9, color="6B7280")
    c.alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[2].height = 18

    counts        = {s: 0 for s in SEV_CONFIG}
    exploit_count = 0
    kev_count     = 0
    for f in findings:
        sev = f.get("severity", "Informational")
        if sev in counts:
            counts[sev] += 1
        if f.get("has_exploit"):
            exploit_count += 1
        if f.get("actively_exploited"):
            kev_count += 1

    cards = [
        ("Services Analysed", str(len(findings)),          C_DARK_NAVY),
        ("Critical",          str(counts["Critical"]),     C_RED),
        ("High",              str(counts["High"]),          C_ORANGE),
        ("Medium",            str(counts["Medium"]),        C_YELLOW),
        ("Low",               str(counts["Low"]),           C_GREEN),
        ("Informational",     str(counts["Informational"]), C_BLUE),
        ("Public Exploits",   str(exploit_count),           "DC2626"),
        ("CISA KEV",          str(kev_count),               C_PURPLE),
    ]
    for r in (4, 5, 6):
        ws.row_dimensions[r].height = 16 if r == 4 else (32 if r == 5 else 8)

    for i, (label, val, bg) in enumerate(cards, 1):
        lc       = ws.cell(row=4, column=i, value=label)
        lc.font  = Font(name="Arial", size=8, bold=True, color=C_WHITE)
        lc.fill  = PatternFill("solid", start_color=bg)
        lc.alignment = Alignment(horizontal="center", vertical="center")
        vc       = ws.cell(row=5, column=i, value=val)
        vc.font  = Font(name="Arial", size=22, bold=True, color=C_WHITE)
        vc.fill  = PatternFill("solid", start_color=bg)
        vc.alignment = Alignment(horizontal="center", vertical="center")

    # KEV note
    ws.merge_cells("A7:I7")
    note        = ws["A7"]
    note.value  = ("⚠️  CISA KEV = vulnerabilities confirmed actively exploited in the wild "
                   "(CISA Known Exploited Vulnerabilities Catalog). Prioritise these immediately.")
    note.font   = Font(name="Arial", size=8, italic=True, color="7C3AED")
    note.fill   = PatternFill("solid", start_color=C_LIGHT_PUR)
    note.alignment = Alignment(horizontal="left", vertical="center")
    ws.row_dimensions[7].height = 16

    # Severity breakdown table
    for i, h in enumerate(["Severity", "Count", "% of Total"], 1):
        _hdr(ws, 9, i, h)
    ws.row_dimensions[9].height = 20
    total = len(findings) or 1
    for row_off, sev in enumerate(SEV_ORDER, 10):
        color, bg, _ = SEV_CONFIG[sev]
        _cell(ws, row_off, 1, sev,  bg=bg, bold=True, color=color, align="center")
        _cell(ws, row_off, 2, counts[sev], align="center")
        pct = ws.cell(row=row_off, column=3)
        pct.value  = f"=B{row_off}/{total}"
        pct.number_format = "0.0%"
        pct.font   = Font(name="Arial", size=9)
        pct.alignment = Alignment(horizontal="center")
        pct.border = _border()
        ws.row_dimensions[row_off].height = 18

    for i, w in enumerate([22, 10, 12, 12, 12, 14, 14, 14, 14], 1):
        ws.column_dimensions[get_column_letter(i)].width = w


# ── Service Inventory ─────────────────────────────────────────────────────────
def _inventory(wb, findings, cve_sources):
    ws = wb.create_sheet("Service Inventory")
    ws.sheet_view.showGridLines = False
    ws.freeze_panes = "A3"
    _title(ws, "Service Inventory — All Open Ports", 9)

    hdrs = ["Port", "Service / Version", "Severity", "CVSS",
            "CVE(s)", "CVE References & Sources", "Public Exploit",
            "CISA KEV", "LLM Analysis"]
    for i, h in enumerate(hdrs, 1):
        _hdr(ws, 2, i, h)
    ws.row_dimensions[2].height = 22

    order    = {s: i for i, s in enumerate(SEV_ORDER)}
    sorted_f = sorted(findings,
                      key=lambda x: order.get(x.get("severity", "Informational"), 99))

    for r, f in enumerate(sorted_f, 3):
        sev        = f.get("severity", "Informational")
        color, bg, emoji = SEV_CONFIG.get(sev, (C_BLUE, C_WHITE, ""))
        kev        = f.get("actively_exploited", False)
        row_bg     = C_KEV_BG if kev else bg

        cves_cited = [c.strip() for c in f.get("cves", "").split(",") if c.strip() and c.strip() != "None"]
        cve_refs   = _build_cve_refs(cves_cited, cve_sources)
        refs_text  = _cve_refs_text(cve_refs)

        _cell(ws, r, 1, f.get("port", "?"),     align="center")
        _cell(ws, r, 2, f.get("service", ""))
        _cell(ws, r, 3, f"{emoji} {sev}",        bg=bg, bold=True, color=color, align="center")
        _cell(ws, r, 4, str(f.get("cvss", "N/A")), align="center")
        _cell(ws, r, 5, f.get("cves", "None"))
        _cell(ws, r, 6, refs_text,               bg=C_LIGHT_BLU, wrap=True)

        exp    = "✅ Yes" if f.get("has_exploit") else "No"
        exp_bg = C_LIGHT_RED if f.get("has_exploit") else C_WHITE
        _cell(ws, r, 7, exp, bg=exp_bg, align="center")

        kev_val = "🚨 YES" if kev else "—"
        kev_bg  = C_LIGHT_PUR if kev else C_WHITE
        kev_col = "7C3AED" if kev else "9CA3AF"
        _cell(ws, r, 8, kev_val, bg=kev_bg, bold=kev, color=kev_col, align="center")

        _cell(ws, r, 9, f.get("analysis", ""), wrap=True)
        ws.row_dimensions[r].height = 22

    for i, w in enumerate([7, 28, 16, 9, 35, 44, 13, 12, 65], 1):
        ws.column_dimensions[get_column_letter(i)].width = w


# ── Critical & High ───────────────────────────────────────────────────────────
def _findings(wb, findings, cve_sources):
    ws = wb.create_sheet("Critical & High Findings")
    ws.sheet_view.showGridLines = False
    ws.freeze_panes = "A3"
    _title(ws, "Critical & High Risk Findings", 8, bg=C_RED)

    hdrs = ["Port", "Service", "Severity", "CVSS",
            "CVE(s)", "CVE References & Sources", "CISA KEV", "Analysis"]
    for i, h in enumerate(hdrs, 1):
        _hdr(ws, 2, i, h)
    ws.row_dimensions[2].height = 22

    order = {s: i for i, s in enumerate(SEV_ORDER)}
    r     = 3
    for f in sorted(findings, key=lambda x: order.get(x.get("severity", "Informational"), 99)):
        if f.get("severity") not in ("Critical", "High"):
            continue
        sev             = f["severity"]
        color, bg, emoji = SEV_CONFIG[sev]
        kev             = f.get("actively_exploited", False)

        cves_cited = [c.strip() for c in f.get("cves", "").split(",") if c.strip() and c.strip() != "None"]
        cve_refs   = _build_cve_refs(cves_cited, cve_sources)
        refs_text  = _cve_refs_text(cve_refs)

        _cell(ws, r, 1, f.get("port", "?"),        align="center")
        _cell(ws, r, 2, f.get("service", ""))
        _cell(ws, r, 3, f"{emoji} {sev}",           bg=bg, bold=True, color=color, align="center")
        _cell(ws, r, 4, str(f.get("cvss", "N/A")),  align="center")
        _cell(ws, r, 5, f.get("cves", "None"))
        _cell(ws, r, 6, refs_text,                  bg=C_LIGHT_BLU, wrap=True)

        kev_val = "🚨 YES" if kev else "—"
        kev_bg  = C_LIGHT_PUR if kev else C_WHITE
        kev_col = "7C3AED" if kev else "9CA3AF"
        _cell(ws, r, 7, kev_val, bg=kev_bg, bold=kev, color=kev_col, align="center")

        _cell(ws, r, 8, f.get("analysis", ""), wrap=True)
        ws.row_dimensions[r].height = 22
        r += 1

    for i, w in enumerate([7, 28, 16, 9, 35, 44, 12, 65], 1):
        ws.column_dimensions[get_column_letter(i)].width = w


# ── Remediation ───────────────────────────────────────────────────────────────
def _remediation(wb, findings, cve_sources):
    ws = wb.create_sheet("Remediation Plan")
    ws.sheet_view.showGridLines = False
    ws.freeze_panes = "A3"
    _title(ws, "Remediation Plan", 6, bg=C_GREEN)

    hdrs = ["Port", "Service", "Severity", "CISA KEV",
            "Recommended Actions", "CVE References"]
    for i, h in enumerate(hdrs, 1):
        _hdr(ws, 2, i, h)
    ws.row_dimensions[2].height = 22

    r     = 3
    order = {s: i for i, s in enumerate(SEV_ORDER)}
    for f in sorted(findings, key=lambda x: order.get(x.get("severity", "Informational"), 99)):
        rem = f.get("remediation", "")
        if not rem or f.get("severity") == "Informational":
            continue
        sev             = f.get("severity", "Informational")
        color, bg, emoji = SEV_CONFIG.get(sev, (C_BLUE, C_WHITE, ""))
        kev             = f.get("actively_exploited", False)

        steps      = [s.strip() for s in rem.replace("|", "\n").splitlines() if s.strip()]
        steps_text = "\n".join(f"• {s}" for s in steps)

        cves_cited = [c.strip() for c in f.get("cves", "").split(",") if c.strip() and c.strip() != "None"]
        cve_refs   = _build_cve_refs(cves_cited, cve_sources)
        refs_text  = _cve_refs_text(cve_refs)

        _cell(ws, r, 1, f.get("port", "?"), align="center")
        _cell(ws, r, 2, f.get("service", ""))
        _cell(ws, r, 3, f"{emoji} {sev}", bg=bg, bold=True, color=color, align="center")

        kev_val = "🚨 PRIORITISE" if kev else "—"
        kev_bg  = C_LIGHT_PUR if kev else C_WHITE
        kev_col = "7C3AED" if kev else "9CA3AF"
        _cell(ws, r, 4, kev_val, bg=kev_bg, bold=kev, color=kev_col, align="center")

        _cell(ws, r, 5, steps_text, bg=C_LIGHT_GRN, wrap=True)
        _cell(ws, r, 6, refs_text,  bg=C_LIGHT_BLU, wrap=True)
        ws.row_dimensions[r].height = max(35, 18 * len(steps))
        r += 1

    for i, w in enumerate([7, 28, 16, 16, 80, 44], 1):
        ws.column_dimensions[get_column_letter(i)].width = w


# ── CISA KEV Sheet ────────────────────────────────────────────────────────────
def _kev_sheet(wb, findings, cve_sources):
    """Dedicated sheet listing all KEV-flagged CVEs found in this assessment."""
    kev_rows = []
    for f in findings:
        cves_cited = [c.strip() for c in f.get("cves", "").split(",")
                      if c.strip() and c.strip() != "None"]
        for cid in cves_cited:
            src = (cve_sources or {}).get(cid, {})
            if src.get("actively_exploited"):
                kev_rows.append({
                    "port":    f.get("port", "?"),
                    "service": f.get("service", ""),
                    "cve":     cid,
                    "cvss":    src.get("cvss", "N/A"),
                    "desc":    src.get("description", ""),
                    "url":     f"https://nvd.nist.gov/vuln/detail/{cid}",
                })

    if not kev_rows:
        return  # skip sheet if no KEV findings

    ws = wb.create_sheet("CISA KEV Alerts")
    ws.sheet_view.showGridLines = False
    ws.freeze_panes = "A3"
    _title(ws, "⚠️  CISA KEV — Actively Exploited Vulnerabilities", 6, bg=C_PURPLE)

    ws.merge_cells("A2:F2")
    note       = ws["A2"]
    note.value = ("These CVEs are listed in the CISA Known Exploited Vulnerabilities (KEV) Catalog, "
                  "meaning they have been observed being actively exploited in real-world attacks. "
                  "Remediate immediately per CISA guidance (https://www.cisa.gov/known-exploited-vulnerabilities-catalog).")
    note.font  = Font(name="Arial", size=8, italic=True, color="5B21B6")
    note.fill  = PatternFill("solid", start_color=C_LIGHT_PUR)
    note.alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
    ws.row_dimensions[2].height = 28

    hdrs = ["Port", "Service", "CVE ID", "CVSS", "Description", "NVD Reference"]
    for i, h in enumerate(hdrs, 1):
        _hdr(ws, 3, i, h, bg=C_PURPLE)
    ws.row_dimensions[3].height = 22

    for r_off, row in enumerate(kev_rows, 4):
        _cell(ws, r_off, 1, row["port"],    align="center")
        _cell(ws, r_off, 2, row["service"])
        _cell(ws, r_off, 3, row["cve"],     bg=C_LIGHT_PUR, bold=True, color="5B21B6", align="center")
        _cell(ws, r_off, 4, str(row["cvss"]), align="center")
        _cell(ws, r_off, 5, row["desc"],    wrap=True)
        _cell(ws, r_off, 6, row["url"],     bg=C_LIGHT_BLU, wrap=True)
        ws.row_dimensions[r_off].height = 22

    for i, w in enumerate([7, 28, 20, 9, 70, 55], 1):
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

        # Enrich findings with KEV/exploit flags from cve_sources
        for f in findings:
            cves_cited = [c.strip() for c in f.get("cves", "").split(",")
                          if c.strip() and c.strip() != "None"]
            if not f.get("actively_exploited") and cve_sources:
                f["actively_exploited"] = any(
                    cve_sources.get(c, {}).get("actively_exploited") for c in cves_cited
                )
            if not f.get("has_exploit") and cve_sources:
                f["has_exploit"] = any(
                    cve_sources.get(c, {}).get("has_exploit") for c in cves_cited
                )

        wb = Workbook()
        _dashboard(wb, findings, target or report_name, generated)
        _inventory(wb, findings, cve_sources)
        _findings(wb, findings, cve_sources)
        _remediation(wb, findings, cve_sources)
        _kev_sheet(wb, findings, cve_sources)
        wb.save(filepath)
        return filepath