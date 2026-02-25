import os
import time
import json
from dotenv import load_dotenv

from src.utils.parsers import ParserFactory
from src.utils.nvd_api import NVDDownloader
from src.utils.vectore_store import VectorStoreManager
from src.modules.summarizer import VulnerabilitySummarizer
from src.modules.reporter import RiskReporter

load_dotenv()

def main():
    #input_file = "data/nessus_test.csv" 
    input_file = "data/meta3_network_scan.xml" 

    api_key = os.getenv("NVD_API_KEY")
    vsm = VectorStoreManager()
    downloader = NVDDownloader(api_key=api_key)
    summarizer = VulnerabilitySummarizer(model_name="llama3:8b", vector_store=vsm)
    reporter = RiskReporter()

    # 1. Caricamento Policy di Sicurezza Locali
    try:
        with open("data/security_policies.json", "r") as f:
            policies = json.load(f)
    except FileNotFoundError:
        print("[!] Warning: data/security_policies.json not found. Using empty policies.")
        policies = []

    # 2. PARSING
    print(f"[*] Reading scan results from: {input_file}")
    hosts_data = ParserFactory.get_parser(input_file)

    # 3. HYBRID RAG ENRICHMENT
    all_context_data = []
    unique_services = set()
    noise = ["tcpwrapped", "unknown"]

    for host in hosts_data:
        for finding in host['findings']:

            s_name = finding.get('service', finding.get('name', 'Unknown')).lower()
            
            if any(n in s_name for n in noise): 
                continue
            
            #Policy Alert
            for p in policies:
                if s_name in p['services']:
                    policy_msg = f"POLICY_ALERT: {p['category']} | Service: {s_name} | Risk: {p['risk']} | {p['description']}"
                    all_context_data.append(policy_msg)

            # Definizione della query per NVD (Priorità alla CVE se presente nel report Nessus)
            if 'cve' in finding and finding['cve'] != 'N/A':
                query = finding['cve']
            else:
                version = finding.get('version', 'n/a')
                query = f"{s_name} {version}" if version != 'n/a' else s_name
            
            unique_services.add(query)

    print(f"[*] Found {len(unique_services)} relevant unique services/CVEs. Fetching NVD data...")
    
    for service in unique_services:

        if "bindshell" in service.lower(): continue 
        
        print(f"    > Querying: {service}")
        cves = downloader.fetch_by_keyword(service)
        all_context_data.extend(cves)
        
        # Rate limiting per NVD API
        time.sleep(6 if api_key else 30)

    if all_context_data:
        vsm.initialize_db(all_context_data)
        print(f"[+] Vector Database updated with {len(all_context_data)} entries.")

    # 4. ANALISI GRANULARE E REPORTING
    for host in hosts_data:
        target_ip = host['target']
        print(f"[*] Starting deep analysis for host: {target_ip}")
        detailed_findings = []
        
        # Set per evitare duplicati nello stesso report
        seen_findings = set()

        for finding in host['findings']:

            s_name = finding.get('service', finding.get('name', 'Unknown'))
            port = finding.get('item', finding.get('port', 'unk'))
            find_id = f"{s_name}-{port}"

            if find_id in seen_findings or any(n in s_name.lower() for n in noise):
                continue
            
            seen_findings.add(find_id)
            
            # Query di ricerca nel Vector Store
            search_query = finding.get('cve') if 'cve' in finding and finding['cve'] != 'N/A' else f"{s_name} {finding.get('version', '')}"
            print(f"    > Analyzing {s_name}...")

            specific_context = vsm.search_context(search_query, k=5)
            service_analysis = summarizer.analyze_single_service(finding, specific_context)
            detailed_findings.append(service_analysis)

        # 5. CONSOLIDAMENTO
        if detailed_findings:
            print(f"[*] Consolidating final report for {target_ip}...")
            final_report = summarizer.consolidate_report(target_ip, detailed_findings)
            
            report_name = f"{target_ip.replace('.', '_')}_final_assessment"
            save_path = reporter.save_report(report_name, final_report)
            print(f"[+] Success! Final report saved to: {save_path}")
        else:
            print(f"[-] No significant findings to report for {target_ip}")

if __name__ == "__main__":
    main()