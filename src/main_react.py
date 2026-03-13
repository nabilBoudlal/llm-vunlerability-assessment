"""
main_react.py — entry point for the ReAct agent

Usage:
  python -m src.main_react                          # default: data/network_scan.xml
  python -m src.main_react data/scan_windows_server.xml
  python -m src.main_react data/scan_ics_gateway.xml

Output: same Excel report format as main.py, saved to reports/
"""
import os
import sys
from dotenv import load_dotenv

load_dotenv()


def main():
    scan_file = sys.argv[1] if len(sys.argv) > 1 else "data/network_scan.xml"

    if not os.path.exists(scan_file):
        print(f"[!] Scan file not found: {scan_file}")
        sys.exit(1)

    from src.modules.va_agent_react import VAAgentReAct
    from src.modules.reporter import RiskReporter

    # Model — start with llama3.1:8b, change here to test larger models
    model = os.getenv("VA_MODEL", "llama3.1:8b")
    print(f"[*] Model: {model}")
    print(f"[*] Scan:  {scan_file}")

    agent    = VAAgentReAct(model_name=model, verbose=True)
    reporter = RiskReporter()

    findings, cve_sources, target = agent.run(scan_file)

    if findings:
        report_name = f"{target.replace('.', '_')}_react_assessment"
        path = reporter.save_report(report_name, findings, cve_sources)
        print(f"\n[+] Report saved: {path}")
    else:
        print("[-] No findings produced.")


if __name__ == "__main__":
    main()