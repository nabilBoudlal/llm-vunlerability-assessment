import os
import json
from dotenv import load_dotenv

from src.utils.parsers import ParserFactory
from src.utils.hybrid_nvd_api import HybridCVEDownloader   # ← replaces NVDDownloader
from src.utils.vectore_store import VectorStoreManager
from src.modules.summarizer import VulnerabilitySummarizer
from src.modules.reporter import RiskReporter
from src.modules.cve_agent import CVEResearchAgent

load_dotenv()


def main():
    input_file = "data/test2.xml"

    api_key    = os.getenv("NVD_API_KEY")
    vsm        = VectorStoreManager()
    downloader = HybridCVEDownloader(api_key=api_key)   # ← hybrid downloader
    summarizer = VulnerabilitySummarizer(model_name="llama3:8b", vector_store=vsm)
    reporter   = RiskReporter()

    # ------------------------------------------------------------------
    # 1. Load local security policies
    # ------------------------------------------------------------------
    try:
        with open("data/security_policies.json", "r") as f:
            policies = json.load(f)
    except FileNotFoundError:
        print("[!] Warning: data/security_policies.json not found. Using empty policies.")
        policies = []

    # ------------------------------------------------------------------
    # 2. Parse scan results
    #    NmapXMLParser now also extracts CPE data per finding.
    # ------------------------------------------------------------------
    print(f"[*] Reading scan results from: {input_file}")
    hosts_data = ParserFactory.get_parser(input_file)

    # ------------------------------------------------------------------
    # 3. Autonomous CVE Research
    #    Path A — CPE-based (CIRCL → NVD-CPE → NVD-KW) for Nmap findings
    #    Path B — LLM keyword queries for CPE-less findings (Nessus CSV)
    # ------------------------------------------------------------------
    print("[*] Launching CVEResearchAgent...")
    agent = CVEResearchAgent(nvd_downloader=downloader, model_name="llama3:8b")
    cve_texts, cve_references = agent.research(
        hosts_data, api_key_present=bool(api_key)
    )

    # ------------------------------------------------------------------
    # 4. Build vector store context (CVEs + policy alerts)
    # ------------------------------------------------------------------
    all_context_data = list(cve_texts)
    noise = ["tcpwrapped", "unknown"]

    for host in hosts_data:
        for finding in host["findings"]:
            s_name = finding.get("service", finding.get("name", "Unknown")).lower()
            if any(n in s_name for n in noise):
                continue
            for p in policies:
                if s_name in p.get("services", []):
                    policy_msg = (
                        f"POLICY_ALERT: {p['category']} | Service: {s_name} | "
                        f"Risk: {p['risk']} | {p['description']}"
                    )
                    all_context_data.append(policy_msg)

    if all_context_data:
        vsm.initialize_db(all_context_data)
        print(f"[+] Vector Database updated with {len(all_context_data)} entries.")
    else:
        print("[!] No CVE/policy data collected — vector store will be empty.")

    # ------------------------------------------------------------------
    # 5. Granular per-host analysis
    # ------------------------------------------------------------------
    for host in hosts_data:
        target_ip = host["target"]
        print(f"[*] Starting deep analysis for host: {target_ip}")
        detailed_findings = []
        seen_findings = set()

        for finding in host["findings"]:
            s_name = finding.get("service", finding.get("name", "Unknown"))
            port   = finding.get("port", finding.get("item", "unk"))
            find_id = f"{s_name}-{port}"

            if find_id in seen_findings or any(n in s_name.lower() for n in noise):
                continue
            seen_findings.add(find_id)

            # Build the vector-store search query
            if finding.get("cve", "N/A") != "N/A":
                search_query = finding["cve"]
            elif finding.get("cpe_list"):
                cpe = finding["cpe_list"][0]
                search_query = (
                    f"{cpe['vendor']} {cpe['product']} {cpe.get('version', '')}".strip()
                )
            else:
                search_query = f"{s_name} {finding.get('version', '')}".strip()

            print(f"    > Analyzing {s_name} (port {port})...")
            specific_context  = vsm.search_context(search_query, k=5)
            service_analysis  = summarizer.analyze_single_service(finding, specific_context)
            detailed_findings.append(service_analysis)

        # ------------------------------------------------------------------
        # 6. Consolidate and save (CVE references appended automatically)
        # ------------------------------------------------------------------
        if detailed_findings:
            print(f"[*] Consolidating final report for {target_ip}...")
            final_report = summarizer.consolidate_report(target_ip, detailed_findings)
            report_name  = f"{target_ip.replace('.', '_')}_final_assessment"
            save_path    = reporter.save_report(
                report_name,
                final_report,
                cve_references=cve_references,
            )
            print(f"[+] Report saved to: {save_path}")
        else:
            print(f"[-] No significant findings to report for {target_ip}")


if __name__ == "__main__":
    main()