"""
Vulnerability Summarizer Module.
Performs granular per-service analysis and final report consolidation.

Aligned with NIST SP 800-115 — Part of WP3, Task 3.1.

Key improvements over previous version:
- 'product' and 'version_confidence' are now explicit prompt inputs.
  The model is strictly forbidden from inventing version numbers when
  version_confidence is "low".
- CVE citation is restricted to entries explicitly present in the
  retrieved context — the model must never recall CVEs from parametric memory.
- Cross-service contamination is blocked: the model cannot assign a CVE
  or version string from one service to another.
- consolidate_report now carries an explicit instruction to list only
  services present in the provided analyses, preventing the model from
  hallucinating services that were never detected by the scanner.
- OS-aware filtering: Windows-specific CVEs are ignored for Linux hosts.
- Diagnostic / informational services are handled gracefully.
"""

from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate


class VulnerabilitySummarizer:

    def __init__(self, model_name: str = "llama3:8b", vector_store=None):
        self.llm = OllamaLLM(model=model_name, temperature=0.0)
        self.vector_store = vector_store

    # ------------------------------------------------------------------
    # Per-service analysis
    # ------------------------------------------------------------------

    def analyze_single_service(self, finding: dict, context: str) -> str:
        """
        Produces a structured vulnerability analysis for a single service.

        The prompt enforces four hard constraints:
          1. Version must come from the scanner — never invented.
          2. CVEs must come from the provided context — never from memory.
          3. CVEs must belong to this specific service — no cross-service leakage.
          4. If context contains no relevant data, report Informational.
        """

        service_name       = finding.get('service', 'Unknown')
        product_name       = finding.get('product', '') or service_name
        version_val        = finding.get('version', 'n/a')
        port_val           = finding.get('port', 'unk')
        version_confidence = finding.get('version_confidence', 'low')
        tunnel             = finding.get('tunnel', '')
        extra_description  = finding.get('description', '')

        # Build a human-readable service label for the prompt.
        # e.g. "Dovecot imapd (ssl) on port 993"
        tunnel_label = f" ({tunnel})" if tunnel else ""
        service_label = f"{product_name}{tunnel_label} on port {port_val}"

        template = """
[SYSTEM]: You are a senior Cybersecurity Expert performing a Vulnerability Assessment \
following NIST SP 800-115. Your analysis must be factual, concise, and strictly grounded \
in the evidence provided below.

[RETRIEVED CONTEXT]:
{context}

[SCANNER SCRIPT OUTPUT]:
{extra_description}

[SERVICE UNDER ANALYSIS]:
- Protocol name : {service}
- Product name  : {product}
- Version       : {version}
- Port          : {port}
- Version confidence: {version_confidence}
- Tunnel/encryption : {tunnel}

════════════════════════════════════════════════
HARD RULES — violations make the report useless:
════════════════════════════════════════════════
RULE 1 — VERSION: If version_confidence is "low", the scanner did not detect a version.
  → You MUST write "not detected by scanner" for the version field.
  → You MUST NOT invent, guess, or infer any version number.

RULE 2 — CVE GROUNDING: You may only cite CVEs that appear verbatim in the
  [RETRIEVED CONTEXT] section above.
  → Never recall CVEs from your training data or parametric memory.
  → If the context contains no CVEs for this service, write:
    "No CVEs found in retrieved context for this service."

RULE 3 — NO CROSS-SERVICE CONTAMINATION: The CVEs in the context may have been
  retrieved for different software. Only use CVEs whose description explicitly
  mentions {product} or a closely related component.
  → Do NOT assign Apache CVEs to Postfix, Dovecot CVEs to ProFTPD, etc.

RULE 4 — OS SCOPE: The target is a Linux system. Ignore any CVE or finding that
  is Windows-specific.

RULE 5 — DIAGNOSTIC TOOLS: If this service is a diagnostic or scanning tool
  (ping, traceroute, SYN scanner) with no matching CVEs in context, report:
  "Informational: No vulnerability found."
════════════════════════════════════════════════

[OUTPUT FORMAT — use exactly these fields]:
- Risk Level        : (Critical / High / Medium / Low / Informational)
- Product           : (value from "Product name" above — do not change it)
- Version           : (value from scanner, or "not detected by scanner")
- Vulnerability Type: (CVE | Protocol Risk | Policy Violation | Informational)
- CVEs              : (list only CVEs from [RETRIEVED CONTEXT], or "None found in context")
- Analysis          : (2–4 sentences; grounded in retrieved context and scanner output only)
"""

        prompt = PromptTemplate(
            input_variables=[
                "context", "extra_description",
                "service", "product", "version", "port",
                "version_confidence", "tunnel"
            ],
            template=template
        )

        chain = prompt | self.llm

        return chain.invoke({
            "context":            context if context else "No context available.",
            "extra_description":  extra_description if extra_description else "No script output.",
            "service":            service_name,
            "product":            product_name,
            "version":            version_val,
            "port":               port_val,
            "version_confidence": version_confidence,
            "tunnel":             tunnel if tunnel else "none"
        })

    # ------------------------------------------------------------------
    # Final report consolidation
    # ------------------------------------------------------------------

    def consolidate_report(
        self,
        target: str,
        detailed_findings: list[str],
        findings_metadata: list[dict] | None = None,
        policy_section: str = "",
        inventory_section: str = ""
    ) -> str:
        """
        Assembles the final Vulnerability Assessment Report.

        Sections 2 (Service Inventory) and 3 (Policy Issues) are built
        deterministically in main.py and injected verbatim — the LLM
        is only responsible for sections 1 (Critical Exploits) and
        4 (Remediation Plan), which require actual analytical reasoning.

        This split prevents context-window truncation on large scans and
        eliminates hallucination in the structured data sections.

        Parameters
        ----------
        target            : target IP address
        detailed_findings : per-service analysis strings from analyze_single_service
        findings_metadata : structured metadata list (product, version, port, tunnel)
        policy_section    : pre-built section 3 string (deterministic)
        inventory_section : pre-built section 2 markdown table (deterministic)
        """

        findings_text = "\n\n---\n\n".join(detailed_findings)

        # Build a compact port map: "vsftpd → port 21, OpenSSH → port 22, ..."
        # Injected into the prompt so the LLM never has to guess port numbers.
        if findings_metadata:
            port_map_lines = []
            for m in findings_metadata:
                product = (m.get('product') or m.get('service', 'Unknown'))
                port    = m.get('port', '?')
                tunnel  = m.get('tunnel', '')
                enc     = " (SSL/TLS)" if tunnel == 'ssl' else ""
                port_map_lines.append(f"  {product}{enc} → port {port}")
            port_map = "\n".join(port_map_lines)
        else:
            port_map = "  No port map available."

        # Fallback defaults if pre-built sections are missing
        sec2 = inventory_section if inventory_section else "_Service inventory not available._"
        sec3 = policy_section    if policy_section    else "_No policy violations identified._"

        # --- LLM call: sections 1 and 4 only ---
        template = """
[SYSTEM]: You are a senior Security Consultant finalizing a Vulnerability Assessment Report \
for target {target}. Sections 2 and 3 are already written. Your task is ONLY to write \
sections 1 and 4 based on the per-service analyses below.

[PORT REFERENCE — use these port numbers verbatim in every entry]:
{port_map}

[PER-SERVICE ANALYSES]:
{findings_text}

════════════════════════════════════════════
RULES:
════════════════════════════════════════════
- Only cite CVEs that appear verbatim in the analyses above. Never add CVEs from memory.
- Only reference services listed in [PORT REFERENCE] above.
- Section 1: list services with Risk Level High or Critical, their CVEs and a one-line description.
  If none exist, write "No critical exploits identified."
- Section 4: ordered by priority Critical → High → Medium → Low.
  Each entry MUST use the port number from [PORT REFERENCE] in this exact format:
  "N. **Product name** (port NNN) — specific action. CVEs: CVE-XXXX-YYYY, ..."
  The port number is always available in [PORT REFERENCE] — never write "port not specified".
════════════════════════════════════════════

Write ONLY the following two sections. Start immediately with "## 1." — no preamble.

## 1. Critical Exploits

## 4. Remediation Plan
"""

        prompt = PromptTemplate(
            input_variables=["target", "port_map", "findings_text"],
            template=template
        )
        chain      = prompt | self.llm
        llm_output = chain.invoke({
            "target":        target,
            "port_map":      port_map,
            "findings_text": findings_text
        })

        # Strip any LLM preamble before the first section header.
        import re
        llm_output = re.sub(r'^.*?(?=##\s*1\.)', '', llm_output, flags=re.DOTALL).strip()

        # --- Assemble final report ---
        report = f"# Assessment Report: {target}\n\n"
        report += llm_output.strip()
        report += f"\n\n## 2. Service Inventory\n\n{sec2}\n"
        report += f"\n## 3. Policy & Configuration Issues\n\n{sec3}\n"

        return report