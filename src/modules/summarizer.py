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
        extra_info_val = finding.get('description', 'No extra script data.')

        template = """
        [SYSTEM]: You are a Senior Cybersecurity Expert following NIST SP 800-115 guidelines.
        [CONTEXT]: {context}
        [SERVICE DATA]: Service: {service}, Version: {version}, Port: {port}
        [NMAP SCRIPTS]: {extra_info}

        [TASK]: Analyze the service based ONLY on the provided context and security policies.Use the [NMAP SCRIPTS] to identify specific vulnerabilities.
        
        [INTELLIGENT PRIORITIZATION TASK]:
        1. ANALYZE REACHABILITY: Does this service provide a path to sensitive data (e.g., databases) found in the context?
        2. THEORETICAL PoC: Briefly describe the logical steps an attacker would take to exploit this.
        3. CONTEXTUAL RISK: Adjust the priority based on the OS (Linux) and the role of the service.

        [STRICT RULE]: If the service is a diagnostic tool (e.g., Ping, Traceroute, SYN scanner) 
        and the context contains CVEs for unrelated software, ignore them and report 'Informational'.

        [OUTPUT FORMAT]:
        - Risk Level: (Critical/High/Medium/Low)
        - Vulnerability Type: (CVE or Protocol Risk)
        - Theoretical Attack Path: (3 short steps)
        - Technical Analysis: (Brief technical explanation with contextual priority)
        """
        
        prompt = PromptTemplate(
            input_variables=["context", "extra_info", "service", "version", "port"], 
            template=template
        )
        
        chain = prompt | self.llm
        return chain.invoke({
            "context": context if context else "No context available.",
            "extra_info": extra_info_val,
            "service": service_val,
            "version": version_val,
            "port": port_val
        })

    def consolidate_report(self, target, detailed_findings):
        """
        Crea il report finale assicurandosi che OGNI servizio analizzato 
        venga incluso nel documento finale.
        """
        # Creiamo una stringa numerata per ogni analisi per non perderne nessuna
        findings_text = ""
        for i, find in enumerate(detailed_findings, 1):
            findings_text += f"--- ANALYSIS {i} ---\n{find}\n\n"
        
        template = """
        [SYSTEM]: Sei un Senior Security Consultant. Devi redigere il report finale.
        [TARGET IP]: {target}
        [ANALYSES]: {findings_text}

        [TASK]: Genera un Vulnerability Assessment Report professionale.
        [STRICT RULE]: Devi includere nel report OGNI servizio presente nelle ANALYSES (es. Apache, MySQL, PostgreSQL, ecc.). Non tralasciare nulla.

        [STRUCTURE]:
        # Assessment Report: {target}
        ## 1. Critical Exploits (Elenca qui le CVE trovate per OGNI servizio)
        ## 2. Service Inventory (Elenca porte e versioni di tutti i servizi rilevati)
        ## 3. Policy & Configuration Issues (Mancanza SSL, versioni EOL, ecc.)
        ## 4. Remediation Plan (Azioni correttive per ogni vulnerabilità)
        """
        
        prompt = PromptTemplate(input_variables=["target", "findings_text"], template=template)
        chain = prompt | self.llm
        return chain.invoke({"target": target, "findings_text": findings_text})