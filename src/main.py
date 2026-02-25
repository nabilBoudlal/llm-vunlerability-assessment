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
    input_file = "data/network_scan.xml"
    api_key = os.getenv("NVD_API_KEY")
    vsm = VectorStoreManager()
    downloader = NVDDownloader(api_key=api_key)
    summarizer = VulnerabilitySummarizer(model_name="llama3:8b", vector_store=vsm)
    reporter = RiskReporter()

    # 1. Caricamento Policy di Sicurezza
    with open("data/security_policies.json", "r") as f:
        policies = json.load(f)

    # 2. PARSING
    print(f"[*] Reading scan results from: {input_file}")
    hosts_data = ParserFactory.get_parser(input_file)

    # 3. HYBRID RAG ENRICHMENT
    all_context_data = []
    unique_services = set()
    noise = ["tcpwrapped", "unknown"]

    for host in hosts_data:
        for finding in host['findings']:
            s_name = finding['service'].lower()
            if any(n in s_name for n in noise): continue
            
            # Aggiunta Policy se il servizio è a rischio noto
            for p in policies:
                if s_name in p['services']:
                    all_context_data.append(f"POLICY_ALERT: {p['category']} | Service: {s_name} | Risk: {p['risk']} | {p['description']}")

            query = f"{finding['service']} {finding['version']}" if finding['version'] != 'n/a' else finding['service']
            unique_services.add(query)

    print(f"[*] Fetching NVD data for {len(unique_services)} services...")
    for service in unique_services:
        # Salta query NVD per servizi puramente logici (già coperti da policy)
        if "bindshell" in service.lower(): continue 
        
        print(f"    > Querying: {service}")
        cves = downloader.fetch_by_keyword(service)
        all_context_data.extend(cves)
        time.sleep(6 if api_key else 30)

    if all_context_data:
        vsm.initialize_db(all_context_data)

    # 4. ANALISI E REPORTING
    for host in hosts_data:
        target_ip = host['target']
        print(f"[*] Analyzing host: {target_ip}")
        detailed_findings = []
        
        # Uso un set per evitare di analizzare lo stesso servizio/porta più volte (evita duplicati nel report)
        seen_findings = set()

        for finding in host['findings']:
            find_id = f"{finding['service']}-{finding.get('portid', 'unk')}"
            if find_id in seen_findings or any(n in finding['service'].lower() for n in noise):
                continue
            
            seen_findings.add(find_id)
            service_query = f"{finding['service']} {finding['version']}"
            print(f"    > Analyzing {service_query}...")
            
            context = vsm.search_context(service_query, k=5)
            analysis = summarizer.analyze_single_service(finding, context)
            detailed_findings.append(analysis)

        if detailed_findings:
            print(f"[*] Finalizing report for {target_ip}...")
            report = summarizer.consolidate_report(target_ip, detailed_findings)
            save_path = reporter.save_report(f"{target_ip.replace('.', '_')}_final", report)
            print(f"[+] Success! Saved to: {save_path}")

if __name__ == "__main__":
    main()