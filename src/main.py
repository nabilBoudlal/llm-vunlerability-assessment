import os
import time
import json
import shutil
from dotenv import load_dotenv

from src.utils.parsers import ParserFactory
from src.utils.nvd_api import NVDDownloader
from src.utils.vectore_store import VectorStoreManager
from src.modules.summarizer import VulnerabilitySummarizer
from src.modules.reporter import RiskReporter

load_dotenv()

def main():
    # Configurazione file input
    input_file = "data/rollback_test.xml" 
    
    # 0. PULIZIA AMBIENTE
    # Elimina il vecchio DB per evitare "inquinamento" da scansioni precedenti
    if os.path.exists("./vector_db"):
        shutil.rmtree("./vector_db")
        print("[*] Vector DB rimosso per una nuova analisi pulita.")

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

    # 3. HYBRID RAG ENRICHMENT (Con Metadati)
    all_texts = []
    all_metadatas = []
    unique_services = set()
    noise = ["tcpwrapped", "unknown"]

    # Identificazione servizi unici per il download CVE
    for host in hosts_data:
        for finding in host['findings']:
            s_name = finding.get('service', 'Unknown').lower()
            if any(n in s_name for n in noise): 
                continue
            
            version = finding.get('version', 'n/a')
            query = f"{s_name} {version}" if version != 'n/a' else s_name
            unique_services.add(query)

    print(f"[*] Found {len(unique_services)} unique services. Fetching NVD data...")
    
    for service in unique_services:
        if "bindshell" in service.lower(): continue 
        
        print(f"    > Querying NVD for: {service}")
        cves = downloader.fetch_by_keyword(service)
        
        # Etichettiamo ogni testo con il nome del servizio per il filtraggio semantico
        for cve_text in cves:
            all_texts.append(cve_text)
            # Salviamo il nome base del servizio (es. 'http' da 'http 2.4.41')
            all_metadatas.append({"service": service.split()[0].lower()})
        
        time.sleep(6 if api_key else 30)

    # Inizializzazione DB con Metadati
    if all_texts:
        vsm.initialize_db(all_texts, all_metadatas)
        print(f"[+] Vector Database updated with {len(all_texts)} entries.")

    # 4. ANALISI GRANULARE E REPORTING
    for host in hosts_data:
        target_ip = host['target']
        print(f"[*] Starting deep analysis for host: {target_ip}")
        detailed_findings = []
        seen_findings = set()

        for finding in host['findings']:
            s_name = finding.get('service', 'Unknown')
            port = finding.get('port', 'unk')
            version = finding.get('version', 'n/a')
            find_id = f"{s_name}-{port}"

            if find_id in seen_findings or any(n in s_name.lower() for n in noise):
                continue
            
            seen_findings.add(find_id)
            
            # Query di ricerca filtrata per servizio (Metadata Filtering)
            search_query = f"{s_name} {version}"
            print(f"    > Analyzing {s_name} on port {port}...")

            # Recupero contesto specifico per il servizio attuale
            specific_context = vsm.search_context(search_query, service_name=s_name, k=10)
            
            # Analisi che include i dati degli script di Nmap (description)
            service_analysis = summarizer.analyze_single_service(finding, specific_context)
            detailed_findings.append(service_analysis)

        # 5. CONSOLIDAMENTO FINALE
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