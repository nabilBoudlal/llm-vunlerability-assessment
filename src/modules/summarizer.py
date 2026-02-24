"""
Vulnerability Summarizer Module
Focuses on identifying and prioritizing weaknesses as defined by NIST SP 800-115.
Part of WP3 - Task 3.1
"""
from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate


class VulnerabilitySummarizer:
    def __init__(self, model_name="llama3:8b", vector_store=None):
        self.llm = OllamaLLM(model=model_name, temperature=0.1)
        self.vector_store = vector_store # The local database manager

    def generate_enhanced_report(self, standardized_data):
        """
        Generates a report using retrieved context from the Vector Store.
        """
        source = standardized_data['source']
        target = standardized_data['target']
        findings = standardized_data['findings']
        
        # 1. Context Retrieval: Search for each finding in the vector database
        context_info = ""
        if self.vector_store:
            for finding in findings:
                query = f"{finding['service']} {finding['version']}"
                context_info += self.vector_store.search_context(query) + "\n"

        # 2. Augmented Prompt Engineering
        template = """
        [SYSTEM]: You are a Penetration Testing Specialist. The target is a known vulnerable host. 
        Do not be brief. You must analyze EVERY service provided in the findings.

        [CONTEXT FROM NVD]: {context}

        [FINDINGS]: {findings}

        [TASK]: For each identified service, search for critical vulnerabilities (RCE, Backdoors, Default Credentials). 
        If a service is known to be vulnerable (like vsftpd 2.3.4 or UnrealIRCd), you MUST highlight the specific exploit even if not fully detailed in the context.

        [REQUIRED STRUCTURE]:
        # Detailed Vulnerability Assessment: {target}
        ## 1. Critical Exploits (RCE/Backdoors)
        ## 2. Service-Specific Analysis (Detailed list of all ports)
        ## 3. Configuration & Legacy Issues
        ## 4. Prioritized Remediation Plan
        """
        
        prompt = PromptTemplate(
            input_variables=["source", "target", "findings", "context"], 
            template=template
        )
        
        chain = prompt | self.llm
        return chain.invoke({
            "source": source,
            "target": target,
            "findings": str(findings),
            "context": context_info if context_info else "No additional context found."
        })
    
    def analyze_unified_findings(self, standardized_data):
        """
        Generic analysis of security findings regardless of the source tool.
        """
        template = """
        [SYSTEM]: You are an Advanced Security Orchestrator.
        [TASK]: Review the security findings from {source} for target {target}.
        
        [FINDINGS]: {findings}
        
        [INSTRUCTIONS]:
        1. Summarize the overall security posture of this target.
        2. Identify the most critical risk found.
        3. Provide a step-by-step remediation plan.
        4. Use a professional, executive tone.
        """
        prompt = PromptTemplate(input_variables=["source", "target", "findings"], template=template)
        chain = prompt | self.llm
        
        return chain.invoke({
            "source": standardized_data['source'],
            "target": standardized_data['target'],
            "findings": str(standardized_data['findings'])
        })