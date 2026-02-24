import os
import time
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
    
    # 1. Parsing: Estrarre dati dal report (Nmap o altri)
    print(f"--- Standardizing Input from {input_file} ---")
    hosts_data = ParserFactory.get_parser(input_file)
    
    # 2. Intelligence Gathering: Trovare servizi unici per il RAG
    services_found = set()
    for host in hosts_data:
        for finding in host['findings']:
            query = f"{finding['service']} {finding['version']}".strip()
            if query and "unknown" not in query:
                services_found.add(query)

    # 3. Dynamic RAG: Scaricare solo ciò che serve
    downloader = NVDDownloader(api_key=api_key)
    vsm = VectorStoreManager()
    all_context = []
    
    for service in services_found:
        print(f"[*] Live fetching CVEs for: {service}")
        results = downloader.fetch_by_keyword(service) # Usa il metodo con keywordSearch
        all_context.extend(results)
        time.sleep(6 if api_key else 30) # Rispetta i limiti NIST

    # 4. Inizializzazione Knowledge Base temporanea
    if all_context:
        vsm.initialize_db(all_context)
    
   # 5. Reporting with Host Aggregation
    summarizer = VulnerabilitySummarizer(model_name="llama3:8b", vector_store=vsm)
    reporter = RiskReporter()

    # Create a dictionary to merge findings by IP
    aggregated_hosts = {}
    for host in hosts_data:
        ip = host['target']
        if ip not in aggregated_hosts:
            aggregated_hosts[ip] = {
                "source": host['source'],
                "target": ip,
                "findings": []
            }
        aggregated_hosts[ip]["findings"].extend(host['findings'])

    # Process each unique host only once
    for ip, data in aggregated_hosts.items():
        print(f"[*] Analyzing target: {ip} with aggregated RAG enrichment...")
        analysis = summarizer.generate_enhanced_report(data)
        
        report_name = f"{ip.replace('.', '_')}_final_assessment"
        report_path = reporter.save_report(report_name, analysis)
        print(f"[+] Final Consolidated Report generated: {report_path}")

if __name__ == "__main__":
    main()