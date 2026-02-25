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

    def analyze_single_service(self, finding, context):
        template = """
        [SYSTEM]: You are a Professional Security Auditor.
        [CONTEXT]: {context}
        [SERVICE]: {service} {version} on port {port}

        [TASK]: Evaluate the security of the service using the provided context.
        
        [INSTRUCTIONS]:
        1. If the context contains a 'POLICY_ALERT', you MUST report the protocol risk (e.g. cleartext, unauthenticated) even if no CVE is found.
        2. If specific CVEs are found in the context, describe their impact and exploitation risk.
        3. Prioritize findings: Critical (Backdoors/No Auth), High (Cleartext/RCE), Medium (Outdated), Low (Info).
        4. Target OS is Linux. Discard any Windows-only context (e.g. MailEnable).

        [OUTPUT FORMAT]:
        - Risk Level: 
        - Vulnerability Type: (CVE or Protocol Risk)
        - Technical Analysis: 
        """
        prompt = PromptTemplate(
            input_variables=["context", "service", "version", "port"], 
            template=template
        )
        port_value = finding.get('portid') or finding.get('port') or "Unknown"
        
        chain = prompt | self.llm
        return chain.invoke({
            "context": context if context else "No specific context found.",
            "service": finding['service'],
            "version": finding['version'],
            "port": port_value
        })

    def consolidate_report(self, target, detailed_findings):
        findings_text = "\n\n".join(detailed_findings)
        template = """
        [SYSTEM]: You are a Cybersecurity Consultant. 
        [TARGET]: {target}
        [ANALYSES]: {findings_text}

        [TASK]: Consolidate the analyses into a formal Report.
        [REQUIRED STRUCTURE]:
        # Detailed Vulnerability Assessment: {target}
        ## 1. Critical Exploits (RCE/Backdoors/Unauthenticated)
        ## 2. Full Service Inventory & Analysis (Include a summary table)
        ## 3. Configuration & Security Policy Issues (Cleartext protocols, etc.)
        ## 4. Prioritized Remediation Plan
        """
        prompt = PromptTemplate(input_variables=["target", "findings_text"], template=template)
        chain = prompt | self.llm
        return chain.invoke({"target": target, "findings_text": findings_text})