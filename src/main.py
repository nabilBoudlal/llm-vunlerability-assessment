"""
LLM-VA — 3-Phase Hybrid RAG Vulnerability Assessment
"""
import os
from dotenv import load_dotenv
from src.agent.va_agent import VAAgent
from src.modules.reporter import RiskReporter

load_dotenv()

INPUT_FILE = "data/network_scan.xml"
MODEL      = os.getenv("VA_MODEL", "qwen3:8b")

def main():
    agent    = VAAgent(model_name=MODEL, verbose=True)
    reporter = RiskReporter()

    findings, cve_sources, target = agent.run(INPUT_FILE)

    if not findings:
        print("[-] No findings to report.")
        return

    report_name = f"{target.replace('.','_')}_assessment"
    save_path   = reporter.save_report(
        report_name, findings, cve_sources, target=target
    )
    print(f"\n[+] Report saved to: {save_path}")

if __name__ == "__main__":
    main()