"""
Vulnerability Summarizer Module
Focuses on identifying and prioritizing weaknesses as defined by NIST SP 800-115.
Part of WP3 - Task 3.1
"""
from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate


# Severity → emoji badge mapping (matches professional VA tool conventions)
_SEVERITY_ICON = {
    "Critical":      "🔴",
    "High":          "🟠",
    "Medium":        "🟡",
    "Low":           "🟢",
    "Informational": "ℹ️",
}

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


class VulnerabilitySummarizer:
    def __init__(self, model_name="qwen3:8b", vector_store=None):
        self.llm          = OllamaLLM(model=model_name, temperature=0.0, verbose=False)
        self.vector_store = vector_store

    # ------------------------------------------------------------------
    # Per-service analysis  (called once per open port)
    # ------------------------------------------------------------------

    def analyze_single_service(self, finding, context):
        service_val = finding.get("service", "Unknown")
        version_val = finding.get("version", "n/a")
        port_val    = finding.get("port", "unk")
        product_val = finding.get("product", "")

        template = """\
[SYSTEM]: You are a Cybersecurity Expert conducting a Vulnerability Assessment \
following NIST SP 800-115 guidelines.

[CONTEXT FROM KNOWLEDGE BASE]:
{context}

[TARGET SERVICE]:
  Service : {service} ({product})
  Version : {version}
  Port    : {port}

[TASK]: Analyze this specific service based ONLY on the provided context.

IMPORTANT RULES:
1. ALWAYS scan the context for lines starting with "ID: CVE-" and list EVERY
   CVE ID you find in CVE_IDS — even if a POLICY_ALERT is also present.
2. A service may have BOTH a policy violation AND CVE-based vulnerabilities.
   Report ALL — do not pick only one type.
3. If a POLICY_ALERT is present, set HAS_POLICY_ALERT: Yes and describe it.
4. If the target is Linux, ignore Windows-specific vulnerabilities.
5. If the service is purely diagnostic with no relevant context,
   set RISK_LEVEL to Informational.
6. EXCLUDE any CVE whose description clearly refers to a completely different
   product from the one being analysed (e.g. a "PHP Toolkit" CVE when the
   service is FTP, or a "Samba" CVE when the service is NFS standalone).
   Only include CVEs that directly mention the product/service name or a
   closely related dependency.

[OUTPUT — use EXACTLY this format, fill every field]:
PORT: {port}
SERVICE: {service} {version}
RISK_LEVEL: <Critical|High|Medium|Low|Informational>
HAS_POLICY_ALERT: <Yes|No>
POLICY_DESCRIPTION: <one sentence describing the policy violation, or "None">
CVE_IDS: <comma-separated CVE IDs from context, or "None">
ANALYSIS: <2-3 sentences covering both policy and CVE risks>
REMEDIATION: <one concrete specific action — NOT just "update to latest version">
"""
        prompt = PromptTemplate(
            input_variables=["context", "service", "product", "version", "port"],
            template=template,
        )
        chain = prompt | self.llm
        return chain.invoke({
            "context":  context if context else "No context available.",
            "service":  service_val,
            "product":  product_val,
            "version":  version_val,
            "port":     port_val,
        })

    # ------------------------------------------------------------------
    # Final report consolidation
    #
    # KEY DESIGN: Sections 0-3 are built 100% in Python from parsed data.
    # The LLM is called ONCE, only to write Section 4 bullet points.
    # ------------------------------------------------------------------

    def consolidate_report(self, target: str, detailed_findings: list,
                           cve_sources: dict = None) -> str:
        if cve_sources is None:
            cve_sources = {}

        # ── Parse all per-service LLM blocks ──────────────────────────
        parsed = [_parse_finding_block(b) for b in detailed_findings]
        parsed = [p for p in parsed if p]

        # ── Helper functions ──────────────────────────────────────────

        def _best_cvss(cve_ids_str: str) -> str:
            """Return highest CVSS score from a comma-separated CVE list."""
            if cve_ids_str.lower() == "none":
                return "N/A"
            best, best_f = "N/A", 0.0
            for cve in cve_ids_str.split(","):
                info = cve_sources.get(cve.strip(), {})
                score = info.get("cvss", "N/A") if isinstance(info, dict) else "N/A"
                try:
                    f = float(score)
                    if f > best_f:
                        best_f, best = f, score
                except (ValueError, TypeError):
                    pass
            return best

        def _has_exploit(cve_ids_str: str) -> bool:
            for cve in cve_ids_str.split(","):
                info = cve_sources.get(cve.strip(), {})
                if isinstance(info, dict) and info.get("exploit", False):
                    return True
            return False

        def _icon(risk: str) -> str:
            return _SEVERITY_ICON.get(risk, "•")

        # ── Section 0 — Executive Summary ─────────────────────────────
        counts = {s: 0 for s in _SEVERITY_ORDER}
        for e in parsed:
            counts[e["risk_level"]] = counts.get(e["risk_level"], 0) + 1
        policy_count  = sum(1 for e in parsed if e["has_policy_alert"])
        exploit_count = sum(
            1 for e in parsed
            if e["cve_ids"].lower() != "none" and _has_exploit(e["cve_ids"])
        )

        exec_summary = (
            f"| Metric | Count |\n"
            f"|--------|-------|\n"
            f"| **Services Analysed** | {len(parsed)} |\n"
            f"| 🔴 Critical | {counts['Critical']} |\n"
            f"| 🟠 High | {counts['High']} |\n"
            f"| 🟡 Medium | {counts['Medium']} |\n"
            f"| 🟢 Low | {counts['Low']} |\n"
            f"| ℹ️ Informational | {counts['Informational']} |\n"
            f"| ⚠️ Policy Violations | {policy_count} |\n"
            f"| 💥 Public Exploits Available | {exploit_count} |"
        )

        # ── Section 1 — Critical & High findings (card style) ─────────
        critical_high = [
            e for e in parsed
            if e["risk_level"] in ("Critical", "High")
            and e["cve_ids"].lower() != "none"
        ]

        sec1_blocks = []
        for e in critical_high:
            cvss    = _best_cvss(e["cve_ids"])
            exploit = _has_exploit(e["cve_ids"])
            icon    = _icon(e["risk_level"])

            block = (
                f"### {icon} Port {e['port']} — {e['service']}\n\n"
                f"| Property | Value |\n"
                f"|----------|-------|\n"
                f"| **Severity** | **{e['risk_level']}** |\n"
                f"| **CVE(s)** | {e['cve_ids']} |\n"
                f"| **CVSS Base Score** | {cvss} |\n"
                f"| **Public Exploit** | {'⚠️ Yes — exploit publicly available' if exploit else 'Not confirmed'} |\n"
                f"| **Policy Violation** | {'Yes' if e['has_policy_alert'] else 'No'} |\n\n"
                f"**Analysis:** {e['analysis']}\n"
            )
            sec1_blocks.append(block)

        section1 = (
            "\n---\n\n".join(sec1_blocks)
            if sec1_blocks
            else "_No Critical or High findings with associated CVEs._"
        )

        # ── Section 2 — Service Inventory (Markdown table) ────────────
        table_header = (
            "| Port | Service | Severity | CVSS | CVEs | Policy | Exploit |\n"
            "|------|---------|----------|------|------|--------|---------|"
        )
        table_rows = []
        for e in parsed:
            cvss        = _best_cvss(e["cve_ids"])
            policy_flag = "⚠️" if e["has_policy_alert"] else ""
            exploit_flag= "💥" if e["cve_ids"].lower() != "none" and _has_exploit(e["cve_ids"]) else ""
            icon        = _icon(e["risk_level"])
            table_rows.append(
                f"| {e['port']} | {e['service']} | {icon} {e['risk_level']} "
                f"| {cvss} | {e['cve_ids']} | {policy_flag} | {exploit_flag} |"
            )

        section2 = table_header + "\n" + "\n".join(table_rows)

        # ── Section 3 — Policy Violations ─────────────────────────────
        policy_findings = [e for e in parsed if e["has_policy_alert"]]
        sec3_blocks = []
        for e in policy_findings:
            icon = _icon(e["risk_level"])
            sec3_blocks.append(
                f"**{icon} Port {e['port']} — {e['service']}** &nbsp; "
                f"`{e['risk_level']}`\n\n"
                f"> {e['policy_description']}"
            )
        section3 = (
            "\n\n".join(sec3_blocks)
            if sec3_blocks
            else "_No policy violations identified._"
        )

        # ── Section 4 — LLM Remediation Plan ──────────────────────────
        seen, unique_rem = set(), []
        priority_order = (
            [e for e in parsed if e["risk_level"] == "Critical"] +
            [e for e in parsed if e["risk_level"] == "High"] +
            [e for e in parsed if e["risk_level"] not in ("Critical", "High")]
        )
        for e in priority_order:
            key = e["remediation"].strip().lower()[:80]
            if key and key not in seen:
                seen.add(key)
                unique_rem.append(e)

        rem_input_lines = []
        for e in unique_rem:
            cve_part  = f" ({e['cve_ids']})" if e["cve_ids"].lower() != "none" else ""
            cvss_part = f" [CVSS: {_best_cvss(e['cve_ids'])}]" if e["cve_ids"].lower() != "none" else ""
            rem_input_lines.append(
                f"Port {e['port']} | {e['service']}{cve_part}{cvss_part} | "
                f"Risk: {e['risk_level']} | Draft action: {e['remediation']}"
            )
        rem_input  = "\n".join(rem_input_lines)
        n_services = len(unique_rem)

        template = """\
[SYSTEM]: You are a Senior Security Consultant writing a remediation plan.

[TASK]: For each service below, write a concise remediation block in Markdown.
Format EXACTLY like this example:

**Port 21 | ProFTPD 1.3.1** `High` `CVSS: 7.5`
* Replace ProFTPD with SFTP (OpenSSH subsystem) and disable anonymous login.
* Apply patch for CVE-2010-3867 or upgrade to ProFTPD >= 1.3.3c.

Rules:
- Be specific: name exact protocol, version number, config option, or CVE patch.
- Never write just "update to latest version" — always say what to update and why.
- Include the severity badge and CVSS in the heading if available.
- Maximum 2 bullet points per service.
- CRITICAL: Output ONLY blocks for the {n_services} services listed below.
  Do NOT add, invent, or include any service not explicitly in the list.
  Your output must have exactly {n_services} blocks — no more, no less.
- No introduction, no summary, no conclusion.

[SERVICES TO REMEDIATE]:
{rem_input}
"""
        prompt   = PromptTemplate(
            input_variables=["rem_input", "n_services"],
            template=template,
        )
        chain    = prompt | self.llm
        section4 = chain.invoke({"rem_input": rem_input, "n_services": n_services})

        # ── Assemble final report ──────────────────────────────────────
        report = (
            f"## Executive Summary\n\n"
            f"{exec_summary}\n\n"
            f"---\n\n"
            f"## 1. Critical & High Findings\n\n"
            f"{section1}\n\n"
            f"---\n\n"
            f"## 2. Service Inventory\n\n"
            f"{section2}\n\n"
            f"---\n\n"
            f"## 3. Policy & Configuration Violations\n\n"
            f"{section3}\n\n"
            f"---\n\n"
            f"## 4. Remediation Plan\n\n"
            f"{section4.strip()}\n"
        )
        return report


# ---------------------------------------------------------------------------
# Helper — parse a single per-service LLM block into a structured dict
# ---------------------------------------------------------------------------

def _parse_finding_block(block: str) -> dict | None:
    fields = {
        "port":               "unk",
        "service":            "Unknown",
        "risk_level":         "Informational",
        "has_policy_alert":   False,
        "policy_description": "None",
        "cve_ids":            "None",
        "analysis":           "",
        "remediation":        "",
    }

    key_map = {
        "PORT":               "port",
        "SERVICE":            "service",
        "RISK_LEVEL":         "risk_level",
        "HAS_POLICY_ALERT":   "has_policy_alert",
        "POLICY_DESCRIPTION": "policy_description",
        "CVE_IDS":            "cve_ids",
        "ANALYSIS":           "analysis",
        "REMEDIATION":        "remediation",
    }

    current_key = None
    buffer      = []

    for line in block.splitlines():
        matched = False
        for prefix, field in key_map.items():
            if line.startswith(f"{prefix}:"):
                if current_key:
                    fields[current_key] = " ".join(buffer).strip()
                current_key = field
                buffer = [line[len(prefix) + 1:].strip()]
                matched = True
                break
        if not matched and current_key:
            buffer.append(line.strip())

    if current_key:
        fields[current_key] = " ".join(buffer).strip()

    raw_hpa = str(fields["has_policy_alert"]).strip().lower()
    fields["has_policy_alert"] = raw_hpa in ("yes", "true", "1")

    if not fields["analysis"] and fields["cve_ids"] == "None":
        return None

    return fields