"""
LLM-VA — Main orchestrator
Hybrid RAG-based Vulnerability Assessment framework.
"""
import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv

from src.utils.parsers import ParserFactory
from src.utils.multi_source_api import MultiSourceCVEDownloader
from src.utils.vectore_store import VectorStoreManager
from src.modules.cve_agent import CVEResearchAgent
from src.modules.summarizer import VulnerabilitySummarizer
from src.modules.reporter import RiskReporter

load_dotenv()

# ── Configuration ─────────────────────────────────────────────────────────────
INPUT_FILE   = "data/network_scan.xml"
MODEL_NAME   = "qwen3:8b"
NOISE        = {"tcpwrapped", "unknown"}
MAX_WORKERS  = 4   # parallel LLM calls — raise to 6 if GPU VRAM allows

# ── Helpers ───────────────────────────────────────────────────────────────────

def _dual_search(vsm: VectorStoreManager, finding: dict, k: int = 5) -> str:
    """Two ChromaDB queries per service, merged and deduplicated."""
    product = finding.get("product", finding.get("service", ""))
    version = finding.get("version", "")
    service = finding.get("service", "")

    q1 = f"{product} {version}".strip()
    q2 = service.strip()

    seen_docs, merged = set(), []
    for query in filter(None, [q1, q2]):
        try:
            docs = vsm.db.similarity_search(query, k=k)
            for doc in docs:
                if doc.page_content not in seen_docs:
                    seen_docs.add(doc.page_content)
                    merged.append(doc.page_content)
        except Exception:
            pass
    return "\n".join(merged) if merged else ""


def _inject_policies(policies: list, service_name: str) -> list:
    """Return policy alert strings that match this service name."""
    sname = service_name.lower()
    alerts = []
    for p in policies:
        if any(sname == svc.lower() for svc in p.get("services", [])):
            alerts.append(
                f"POLICY_ALERT: {p['category']} | Service: {sname} "
                f"| Risk: {p['risk']} | {p['description']}"
            )
    return alerts


def _analyse_finding(args: tuple) -> tuple:
    """
    Worker function — runs in a thread.
    Returns (port, analysis_text) so results can be sorted by port.
    """
    finding, policies, vsm, summarizer, index = args

    port    = str(finding.get("port", "unk"))
    s_name  = finding.get("service", "Unknown")
    product = finding.get("product", s_name)

    policy_alerts = _inject_policies(policies, s_name)

    context = _dual_search(vsm, finding, k=5)
    if policy_alerts:
        context = "\n".join(policy_alerts) + "\n\n" + context

    analysis = summarizer.analyze_single_service(finding, context)

    return (index, port, product, analysis)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    # 1. Load security policies
    try:
        with open("data/security_policies.json", "r") as f:
            policies = json.load(f)
        print(f"[*] Loaded {len(policies)} security policies.")
    except FileNotFoundError:
        print("[!] Warning: data/security_policies.json not found.")
        policies = []

    # 2. Parse scan results
    print(f"[*] Reading scan results from: {INPUT_FILE}")
    hosts_data = ParserFactory.get_parser(INPUT_FILE)

    # 3. CVE Research Agent (Stage 1-3)
    api_key    = os.getenv("NVD_API_KEY")
    downloader = MultiSourceCVEDownloader(nvd_api_key=api_key)
    vsm        = VectorStoreManager()
    agent      = CVEResearchAgent(downloader=downloader, model_name=MODEL_NAME)

    print("[*] Launching CVEResearchAgent...")
    rag_texts, cve_sources = agent.research(hosts_data)

    if rag_texts:
        vsm.initialize_db(rag_texts)
        print(f"[+] Vector Database updated with {len(rag_texts)} CVE entries.")
    else:
        print("[!] No CVE data retrieved — vector DB empty.")

    # 4. Per-service parallel analysis
    summarizer = VulnerabilitySummarizer(model_name=MODEL_NAME, vector_store=vsm)
    reporter   = RiskReporter()

    for host in hosts_data:
        target_ip = host["target"]
        print(f"[*] Starting deep analysis for host: {target_ip}")

        # ── Deduplicate by port ──────────────────────────────────────────────
        seen_ports  = set()
        work_items  = []   # (finding, policies, vsm, summarizer, index)

        for finding in host["findings"]:
            port   = str(finding.get("port", "unk"))
            s_name = finding.get("service", "Unknown")

            if s_name.lower() in NOISE or any(n in s_name.lower() for n in NOISE):
                continue
            if port in seen_ports:
                continue
            seen_ports.add(port)

            work_items.append((finding, policies, vsm, summarizer, len(work_items)))

        print(f"    {len(work_items)} unique services to analyse "
              f"(parallel workers: {MAX_WORKERS})")

        # ── Parallel execution ───────────────────────────────────────────────
        results: list[tuple] = []

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(_analyse_finding, item): item for item in work_items}
            done_count = 0
            for future in as_completed(futures):
                try:
                    idx, port, product, analysis = future.result()
                    results.append((idx, port, product, analysis))
                    done_count += 1
                    print(f"    [{done_count}/{len(work_items)}] done — port {port} ({product})")
                except Exception as exc:
                    item = futures[future]
                    port = str(item[0].get("port", "?"))
                    print(f"    [!] Error on port {port}: {exc}")

        # Sort results by original index to preserve port order in report
        results.sort(key=lambda x: x[0])
        detailed_findings = [r[3] for r in results]

        print(f"[*] Analysis complete: {len(detailed_findings)} services.")

        # 5. Consolidate and save report
        if detailed_findings:
            print(f"[*] Consolidating final report for {target_ip}...")
            final_report = summarizer.consolidate_report(
                target_ip, detailed_findings, cve_sources=cve_sources
            )
            report_name = f"{target_ip.replace('.', '_')}_final_assessment"
            save_path   = reporter.save_report(report_name, final_report, cve_sources=cve_sources)
            print(f"[+] Success! Final report saved to: {save_path}")
        else:
            print(f"[-] No significant findings for {target_ip}")


if __name__ == "__main__":
    main()