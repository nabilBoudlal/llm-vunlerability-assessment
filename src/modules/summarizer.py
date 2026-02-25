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
        
        service_val = finding.get('service', 'Unknown')
        version_val = finding.get('version', 'n/a')
        port_val = finding.get('port', 'unk')

        template = """
        [SYSTEM]: You are a Cybersecurity Expert.
        [CONTEXT]: {context}
        [SERVICE]: {service} {version} on port {port}

        [TASK]: Analyze the service based ONLY on the provided context and your knowledge of security policies.
        If a POLICY_ALERT is present in the context, prioritize it.
        If the target is Linux, ignore Windows-specific vulnerabilities.

        [STRICT RULE]: If the service is a diagnostic tool (e.g., Ping, Traceroute, SYN scanner) 
        and the context contains CVEs for unrelated software (like Sendmail or BSD), 
        ignore the CVEs and report 'Informational: No vulnerability found'.

        [OUTPUT FORMAT]:
        - Risk Level: (Critical/High/Medium/Low)
        - Vulnerability Type: (CVE or Protocol Risk)
        - Analysis: (Brief technical explanation)
        """
        
        prompt = PromptTemplate(
            input_variables=["context", "service", "version", "port"], 
            template=template
        )
        
        chain = prompt | self.llm
        return chain.invoke({
            "context": context if context else "No context available.",
            "service": service_val,
            "version": version_val,
            "port": port_val
        })

    def consolidate_report(self, target, detailed_findings):
        """
        Crea il report finale unificando le analisi singole.
        """
        findings_text = "\n\n".join(detailed_findings)
        
        template = """
        [SYSTEM]: Senior Security Consultant.
        [TARGET IP]: {target}
        [ANALYSES]: {findings_text}

        [TASK]: Professional Vulnerability Assessment Report.
        [STRUCTURE]:
        # Assessment Report: {target}
        ## 1. Critical Exploits
        ## 2. Service Inventory
        ## 3. Policy & Configuration Issues
        ## 4. Remediation Plan
        """
        
        prompt = PromptTemplate(input_variables=["target", "findings_text"], template=template)
        chain = prompt | self.llm
        return chain.invoke({"target": target, "findings_text": findings_text})