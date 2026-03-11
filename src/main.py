import os
import json
from dotenv import load_dotenv

from src.utils.parsers import ParserFactory
from src.utils.multi_source_api import MultiSourceCVEDownloader
from src.utils.vectore_store import VectorStoreManager
from src.modules.cve_agent import CVEResearchAgent
from src.modules.summarizer import VulnerabilitySummarizer
from src.modules.reporter import RiskReporter

load_dotenv()


def _build_policy_index(policies: list) -> dict:
    """Map service name → list of alert strings for fast lookup."""
    index = {}
    for p in policies:
        for svc in p.get("services", []):
            key = svc.lower()
            msg = (
                f"POLICY_ALERT: {p['category']} | "
                f"Service: {svc} | Risk: {p['risk']} | {p['description']}"
            )
            index.setdefault(key, []).append(msg)
    return index


def _dual_search(vsm: VectorStoreManager, product: str, s_name: str,
                 version: str, k: int = 5) -> str:
    """
    Run two vector searches and merge results (dedup by content).

    Search 1: product + version  (e.g. "Redis key-value store 5.0.7")
    Search 2: s_name alone       (e.g. "redis")

    This ensures services with verbose product names (Redis, ProFTPD, etc.)
    still retrieve their own CVEs even when the vector store is crowded with
    entries from higher-volume products like Apache or Samba.
    """
    seen    = set()
    results = []

    query1 = f"{product} {version}".strip() if product else f"{s_name} {version}".strip()
    query2 = s_name.lower()

    for q in [query1, query2]:
        if not q:
            continue
        raw = vsm.search_context(q, k=k)
        for line in raw.split("\n"):
            line = line.strip()
            if line and line not in seen:
                seen.add(line)
                results.append(line)

    # Cap at 2*k lines to avoid bloating the LLM context
    return "\n".join(results[: k * 2])


def main():
    input_file = "data/test4.xml"

    api_key    = os.getenv("NVD_API_KEY")
    vsm        = VectorStoreManager()
    downloader = MultiSourceCVEDownloader(nvd_api_key=api_key)
    agent      = CVEResearchAgent(downloader=downloader, model_name="qwen3:8b")
    summarizer = VulnerabilitySummarizer(model_name="qwen3:8b", vector_store=vsm)
    reporter   = RiskReporter()

    # 1. Load security policies
    try:
        with open("data/security_policies.json", "r") as f:
            policies = json.load(f)
        print(f"[*] Loaded {len(policies)} security policies.")
    except FileNotFoundError:
        print("[!] Warning: data/security_policies.json not found.")
        policies = []

    policy_index = _build_policy_index(policies)

    # 2. Parse scan
    print(f"[*] Reading scan results from: {input_file}")
    hosts_data = ParserFactory.get_parser(input_file)

    # 3. Autonomous multi-source CVE research
    print("[*] Launching CVEResearchAgent...")
    rag_texts, cve_sources = agent.research(hosts_data)

    if rag_texts:
        vsm.initialize_db(rag_texts)
        print(f"[+] Vector Database updated with {len(rag_texts)} CVE entries.")

    # 4. Per-host deep analysis
    noise = ["tcpwrapped", "unknown"]

    for host in hosts_data:
        target_ip = host["target"]
        print(f"[*] Starting deep analysis for host: {target_ip}")
        detailed_findings = []
        seen_findings     = set()

        for finding in host["findings"]:
            s_name  = finding.get("service", finding.get("name", "Unknown"))
            port    = finding.get("port", "unk")
            find_id = f"{s_name}-{port}"

            if find_id in seen_findings:
                continue
            if any(n in s_name.lower() for n in noise):
                continue

            seen_findings.add(find_id)

            product = finding.get("product", "")
            version = finding.get("version", "")

            print(f"    > Analyzing {product or s_name} (port {port})")

            # Dual vector search — prevents product-name mismatch misses
            cve_context = _dual_search(vsm, product, s_name, version, k=5)

            # Inject policy alerts directly at top of context
            policy_alerts = policy_index.get(s_name.lower(), [])
            if policy_alerts:
                print(f"      [Policy] Injecting {len(policy_alerts)} alert(s) "
                      f"for '{s_name.lower()}'")
                alerts_text  = "\n".join(policy_alerts)
                full_context = alerts_text + "\n\n" + cve_context
            else:
                full_context = cve_context

            analysis = summarizer.analyze_single_service(finding, full_context)
            detailed_findings.append(analysis)

        # 5. Consolidate and save
        if detailed_findings:
            print(f"[*] Consolidating final report for {target_ip}...")
            final_report = summarizer.consolidate_report(target_ip, detailed_findings)

            report_name = f"{target_ip.replace('.', '_')}_final_assessment"
            save_path   = reporter.save_report(
                report_name,
                final_report,
                cve_sources=cve_sources,
            )
            print(f"[+] Report saved to: {save_path}")
        else:
            print(f"[-] No significant findings for {target_ip}")


if __name__ == "__main__":
    main()