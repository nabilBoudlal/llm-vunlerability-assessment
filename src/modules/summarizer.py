"""
Vulnerability Summarizer Module
Focuses on identifying and prioritizing weaknesses as defined by NIST SP 800-115.
Part of WP3 - Task 3.1
"""
from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate


class VulnerabilitySummarizer:
    def __init__(self, model_name="llama3:8b", vector_store=None):
        self.llm = OllamaLLM(model=model_name, temperature=0.0)
        self.vector_store = vector_store

    # ------------------------------------------------------------------
    # Per-service analysis
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
    # KEY DESIGN: Sections 1-3 are built 100% in Python from parsed data.
    # The LLM is called ONCE, only to write Section 4 bullet points.
    # Python then concatenates everything — the LLM cannot overwrite or
    # omit sections regardless of how it responds.
    # ------------------------------------------------------------------

    def consolidate_report(self, target: str, detailed_findings: list) -> str:

        # ── 1. Parse all per-service blocks ───────────────────────────
        parsed = []
        for block in detailed_findings:
            entry = _parse_finding_block(block)
            if entry:
                parsed.append(entry)

        # ── 2. Section 2 — complete service inventory ──────────────────
        inventory_lines = []
        for e in parsed:
            inventory_lines.append(
                f"  - Port {e['port']:>5} | {e['service']:<35} | "
                f"Risk: {e['risk_level']:<14} | CVEs: {e['cve_ids']}"
            )
        section2 = (
            "\n".join(inventory_lines) if inventory_lines else "  None detected."
        )

        # ── 3. Section 1 — Critical/High services with CVEs ────────────
        cve_findings = [
            e for e in parsed
            if e["risk_level"] in ("Critical", "High")
            and e["cve_ids"].lower() != "none"
        ]
        sec1_blocks = []
        for e in cve_findings:
            sec1_blocks.append(
                f"• **Port {e['port']} — {e['service']}**\n"
                f"  CVEs: {e['cve_ids']}\n"
                f"  {e['analysis']}"
            )
        section1 = "\n\n".join(sec1_blocks) if sec1_blocks else "None identified."

        # ── 4. Section 3 — policy violations ───────────────────────────
        policy_findings = [e for e in parsed if e["has_policy_alert"]]
        sec3_blocks = []
        for e in policy_findings:
            sec3_blocks.append(
                f"• **Port {e['port']} — {e['service']}**\n"
                f"  {e['policy_description']}"
            )
        section3 = (
            "\n\n".join(sec3_blocks) if sec3_blocks
            else "No policy violations identified."
        )

        # ── 5. LLM generates ONLY Section 4 bullet text ────────────────
        # Deduplicate by first 80 chars of remediation text
        seen       = set()
        unique_rem = []
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
            cve_part = f" ({e['cve_ids']})" if e["cve_ids"].lower() != "none" else ""
            rem_input_lines.append(
                f"Port {e['port']} | {e['service']}{cve_part} | "
                f"Risk: {e['risk_level']} | Draft action: {e['remediation']}"
            )
        rem_input = "\n".join(rem_input_lines)

        template = """\
[SYSTEM]: You are a Senior Security Consultant writing a remediation plan.

[TASK]: For each service below, write a short remediation block in Markdown.
Format EXACTLY like this example:

**Port 21 | vsftpd 2.3.4**
* Replace vsftpd with SFTP (OpenSSH subsystem) and disable anonymous login.
* Apply CVE-2011-2523 patch or upgrade to vsftpd >= 3.0.5.

Rules:
- Be specific. Name the exact protocol, version, config option, or patch.
- Never write just "update to latest version" — always say what to update and why.
- Maximum 2 bullet points per service.
- CRITICAL: Output ONLY blocks for the {n_services} services listed below.
  Do NOT add, invent, or include any service not explicitly in the list.
  Your output must have exactly {{n_services}} blocks — no more, no less.
- No introduction, no summary, no conclusion.

[SERVICES TO REMEDIATE]:
{rem_input}
"""
        n_services = len(unique_rem)
        prompt  = PromptTemplate(
            input_variables=["rem_input", "n_services"],
            template=template,
        )
        chain   = prompt | self.llm
        section4 = chain.invoke({"rem_input": rem_input, "n_services": n_services})

        # ── 6. Python assembles the complete report ─────────────────────
        # The LLM output is placed ONLY in section 4.
        # Sections 1-3 are written directly — never touched by the LLM.
        report = (
            f"# Assessment Report: {target}\n\n"
            f"## 1. Critical Exploits\n\n"
            f"{section1}\n\n"
            f"## 2. Service Inventory\n\n"
            f"{section2}\n\n"
            f"## 3. Policy & Configuration Issues\n\n"
            f"{section3}\n\n"
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

    # Normalise has_policy_alert to bool
    raw_hpa = str(fields["has_policy_alert"]).strip().lower()
    fields["has_policy_alert"] = raw_hpa in ("yes", "true", "1")

    if not fields["analysis"] and fields["cve_ids"] == "None":
        return None

    return fields