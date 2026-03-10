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
    # Per-service analysis (unchanged logic, slightly cleaner prompt)
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
- If a POLICY_ALERT is present in the context, treat it as HIGH priority.
- If the target is Linux, ignore Windows-specific vulnerabilities.
- If the service is diagnostic (Ping, Traceroute, SYN scanner) and the context \
contains unrelated CVEs, report: "Informational: No vulnerability found".

[OUTPUT — use EXACTLY this format, fill every field]:
PORT: {port}
SERVICE: {service} {version}
RISK_LEVEL: <Critical|High|Medium|Low|Informational>
VULN_TYPE: <CVE-based|Protocol Risk|Policy Violation|Informational>
CVE_IDS: <comma-separated CVE IDs from context, or "None">
ANALYSIS: <2-3 sentences: what the vulnerability is, why it matters on this port>
REMEDIATION: <one concrete action>
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
    # ------------------------------------------------------------------

    def consolidate_report(self, target: str, detailed_findings: list[str]) -> str:
        """
        Build the final report by pre-parsing the per-service analyses
        and injecting them into a tightly constrained prompt.

        Pre-parsing happens in Python (deterministic), so the LLM only
        needs to write prose — it never has to figure out ports or CVE IDs.
        """
        # ── 1. Parse each finding block into a structured dict ─────────────
        parsed = []
        for block in detailed_findings:
            entry = _parse_finding_block(block)
            if entry:
                parsed.append(entry)

        # ── 2. Build a deterministic service inventory (no LLM needed) ─────
        inventory_lines = []
        for e in parsed:
            inventory_lines.append(
                f"  - Port {e['port']:>5} | {e['service']:<35} | "
                f"Risk: {e['risk_level']:<14} | CVEs: {e['cve_ids']}"
            )
        service_inventory = "\n".join(inventory_lines) if inventory_lines else "  None detected."

        # ── 3. Separate criticals from the rest ────────────────────────────
        criticals = [e for e in parsed if e["risk_level"] in ("Critical", "High")]
        others    = [e for e in parsed if e["risk_level"] not in ("Critical", "High")]

        def _entry_block(e):
            return (
                f"Port {e['port']} | {e['service']}\n"
                f"  Risk      : {e['risk_level']}\n"
                f"  CVEs      : {e['cve_ids']}\n"
                f"  Analysis  : {e['analysis']}\n"
                f"  Remediation: {e['remediation']}"
            )

        critical_blocks = "\n\n".join(_entry_block(e) for e in criticals) or "None identified."
        other_blocks    = "\n\n".join(_entry_block(e) for e in others)    or "None."

        # ── 4. Strict consolidation prompt ─────────────────────────────────
        template = """\
[SYSTEM]: You are a Senior Security Consultant writing a professional \
Vulnerability Assessment Report.

[TARGET IP]: {target}

[PRE-ANALYSED FINDINGS — Critical/High]:
{critical_blocks}

[PRE-ANALYSED FINDINGS — Medium/Low/Informational]:
{other_blocks}

[TASK]: Write the final report using EXACTLY the structure below.
STRICT RULES:
  - Copy port numbers EXACTLY as shown in the findings above — never write "port not specified".
  - List every CVE ID exactly as given. Do not invent new ones.
  - The Service Inventory section must be copied VERBATIM from the table provided.
  - Do not merge or reorder sections.
  - Write in professional English.

---

# Assessment Report: {target}

## 1. Critical Exploits
List each Critical/High finding as a bullet. Include: service name, port, \
CVE IDs, and one-sentence impact.

## 2. Service Inventory
(Copy this table verbatim — do not modify it)
{service_inventory}

## 3. Policy & Configuration Issues
List any POLICY_ALERT or protocol-level risk findings (e.g. Telnet, unencrypted services). \
If none, write: "No policy violations identified."

## 4. Remediation Plan
Number each action. Format: **Service (port XX)** — action. Include CVE IDs.
Order: Critical first, then High, Medium, Low.
"""
        prompt = PromptTemplate(
            input_variables=[
                "target", "critical_blocks", "other_blocks",
                "service_inventory",
            ],
            template=template,
        )
        chain = prompt | self.llm
        return chain.invoke({
            "target":            target,
            "critical_blocks":   critical_blocks,
            "other_blocks":      other_blocks,
            "service_inventory": service_inventory,
        })


# ---------------------------------------------------------------------------
# Helper — parse a per-service analysis block into a dict
# ---------------------------------------------------------------------------

def _parse_finding_block(block: str) -> dict | None:
    """
    Extract structured fields from the fixed-format output of
    analyze_single_service().

    Expected fields: PORT, SERVICE, RISK_LEVEL, VULN_TYPE, CVE_IDS,
                     ANALYSIS, REMEDIATION
    """
    fields = {
        "port":        "unk",
        "service":     "Unknown",
        "risk_level":  "Informational",
        "vuln_type":   "Unknown",
        "cve_ids":     "None",
        "analysis":    "",
        "remediation": "",
    }

    key_map = {
        "PORT":        "port",
        "SERVICE":     "service",
        "RISK_LEVEL":  "risk_level",
        "VULN_TYPE":   "vuln_type",
        "CVE_IDS":     "cve_ids",
        "ANALYSIS":    "analysis",
        "REMEDIATION": "remediation",
    }

    current_key = None
    buffer      = []

    for line in block.splitlines():
        matched = False
        for prefix, field in key_map.items():
            if line.startswith(f"{prefix}:"):
                # Save previous buffer
                if current_key:
                    fields[current_key] = " ".join(buffer).strip()
                current_key = field
                buffer = [line[len(prefix) + 1:].strip()]
                matched = True
                break
        if not matched and current_key:
            buffer.append(line.strip())

    # Flush last field
    if current_key:
        fields[current_key] = " ".join(buffer).strip()

    # Discard completely empty blocks
    if not fields["analysis"] and not fields["cve_ids"]:
        return None

    return fields