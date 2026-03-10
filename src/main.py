"""
Main pipeline for the Hybrid RAG Vulnerability Assessment framework.

Architecture summary:
- Scanner outputs (Nmap XML, Nessus CSV) are parsed and normalised into a
  canonical host/finding schema by ParserFactory.
- NVD CVE data is fetched using product-aware queries with CPE-based version
  filtering to maximise precision. A progressive fallback strategy handles
  cases where NVD does not match the exact version string format.
- CVE embeddings are stored in ChromaDB with per-service metadata tags so
  that retrieval is filtered to the relevant software, preventing cross-service
  CVE contamination.
- Security policies are applied via DIRECT LOOKUP against security_policies.json
  rather than via the vector store. This guarantees that policy alerts are always
  present in the context regardless of semantic similarity scores — policies are
  deterministic rules, not fuzzy knowledge.
- Per-service analysis and final consolidation are handled by VulnerabilitySummarizer
  using structured prompt engineering that enforces strict grounding rules.
"""

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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def build_nvd_query(finding: dict) -> str | None:
    """
    Returns the best possible NVD search query for a finding, or None if
    the available information is too generic to produce useful results.

    Priority:
      1. product + version   -> most specific  (e.g. "Apache httpd 2.4.41")
      2. product only        -> acceptable     (e.g. "ProFTPD")
      3. service name only   -> too generic, skip (e.g. "ftp", "smtp", "pop3")
    Uses `or` guards so None and "" both fall through correctly.
    """
    product = (finding.get('product') or '').strip()
    version = finding.get('version', 'n/a').strip()

    if product:
        if version != 'n/a':
            return f"{product} {version}"
        else:
            return product
    else:
        return None


def build_search_query(finding: dict) -> str:
    """
    Returns the vector-store search query for a finding.
    Mirrors the NVD query logic so retrieval is as specific as possible.
    Uses service name as fallback if product is empty or None.
    """
    product = (finding.get('product') or '').strip()
    version = finding.get('version', 'n/a').strip()
    service = finding.get('service', '').lower().strip()

    if product and version != 'n/a':
        return f"{product} {version}"
    elif product:
        return product
    else:
        return service


def dedup_key(finding: dict) -> str:
    """
    Unique key for a finding within a single host report.
    Includes tunnel so IMAPS (993/ssl) and IMAP (143) are kept separate.
    """
    service = finding.get('service', 'unknown')
    port    = finding.get('port', 'unk')
    tunnel  = finding.get('tunnel', '')
    suffix  = f"-{tunnel}" if tunnel else ""
    return f"{service}-{port}{suffix}"


def get_policy_context(finding: dict, policies: list[dict]) -> str:
    """
    Performs a direct lookup of applicable security policies for a finding.

    Unlike CVE data, policies are deterministic rules -- they must always appear
    in the context if the service is listed, regardless of semantic similarity.
    This function replaces the previous approach of indexing policies in the
    vector store and relying on similarity search to retrieve them (which failed
    silently when the metadata tag did not match the indexed token).

    Returns a newline-separated string of POLICY_ALERT lines, or "" if none apply.
    """
    s_name = finding.get('service', '').lower().strip()
    lines  = []

    for policy in policies:
        if s_name in policy.get('services', []):
            lines.append(
                f"POLICY_ALERT: {policy['category']} | "
                f"Service: {s_name} | "
                f"Risk: {policy['risk']} | "
                f"{policy['description']}"
            )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    input_file = "data/test_target.xml"

    # ------------------------------------------------------------------
    # 0. CLEAN ENVIRONMENT
    # Remove stale vector DB to avoid cross-scan contamination.
    # ------------------------------------------------------------------
    if os.path.exists("./vector_db"):
        shutil.rmtree("./vector_db")
        print("[*] Vector DB cleared for a clean run.")

    api_key    = os.getenv("NVD_API_KEY")
    vsm        = VectorStoreManager()
    downloader = NVDDownloader(api_key=api_key)
    summarizer = VulnerabilitySummarizer(model_name="llama3:8b", vector_store=vsm)
    reporter   = RiskReporter()

    # ------------------------------------------------------------------
    # 1. LOAD LOCAL SECURITY POLICIES
    # ------------------------------------------------------------------
    try:
        with open("data/security_policies.json", "r") as f:
            policies = json.load(f)
        print(f"[*] Loaded {len(policies)} security policies.")
    except FileNotFoundError:
        print("[!] Warning: data/security_policies.json not found. Using empty policies.")
        policies = []

    # ------------------------------------------------------------------
    # 2. PARSE SCAN RESULTS
    # ------------------------------------------------------------------
    print(f"[*] Reading scan results from: {input_file}")
    hosts_data = ParserFactory.get_parser(input_file)

    # ------------------------------------------------------------------
    # 3. NVD CVE ENRICHMENT
    # Policies are no longer indexed in the vector store -- they are applied
    # via direct lookup in step 4. The vector store now contains CVEs only,
    # which makes metadata filtering reliable and avoids tag mismatches.
    # ------------------------------------------------------------------
    all_texts     = []
    all_metadatas = []
    noise         = ["tcpwrapped", "unknown"]

    # Dict maps query_string -> target_version (or None if version_confidence low).
    seen_queries: dict[str, str | None] = {}

    for host in hosts_data:
        for finding in host['findings']:
            s_name = finding.get('service', 'Unknown').lower()

            if any(n in s_name for n in noise):
                continue

            query = build_nvd_query(finding)
            if query is None:
                print(f"    > Skipping NVD query for '{s_name}' on port "
                      f"{finding.get('port', '?')}: no product name available.")
                continue

            if query.lower() not in seen_queries:
                vc = finding.get('version_confidence', 'low')
                v  = finding.get('version', 'n/a')
                # Only filter by version if confidence is high AND version has
                # at least two components (e.g. "2.4.41" not "4").
                if vc == 'high' and v not in ('n/a', '') and len(v.split('.')) >= 2:
                    seen_queries[query.lower()] = v
                else:
                    seen_queries[query.lower()] = None

    print(f"[*] {len(seen_queries)} unique NVD queries identified. Fetching CVE data...")

    for query, target_version in seen_queries.items():
        print(f"    > Querying NVD: '{query}' (version filter: {target_version or 'none'})")

        cves = downloader.fetch_by_keyword(query, target_version=target_version)

        if not cves and len(query.split()) > 1:
            fallback_query = " ".join(query.split()[:-1])
            print(f"    > No results -- retrying broader: '{fallback_query}'")
            cves = downloader.fetch_by_keyword(fallback_query, target_version=target_version)
            time.sleep(6 if api_key else 30)

            if not cves and len(fallback_query.split()) > 1:
                fallback_query = fallback_query.split()[0]
                print(f"    > Still empty -- last resort: '{fallback_query}'")
                cves = downloader.fetch_by_keyword(fallback_query, target_version=target_version)
                time.sleep(6 if api_key else 30)

        if not cves:
            print(f"    > [!] No CVEs found for '{query}' after all fallbacks.")

        base_token = query.split()[0].lower()
        for cve_text in cves:
            all_texts.append(cve_text)
            all_metadatas.append({"service": base_token, "type": "cve"})

        time.sleep(6 if api_key else 30)

    if all_texts:
        vsm.initialize_db(all_texts, all_metadatas)
        print(f"[+] Vector DB populated with {len(all_texts)} CVE entries.")
    else:
        print("[!] No CVE data available. Analysis will proceed without CVE context.")

    # ------------------------------------------------------------------
    # 4. GRANULAR ANALYSIS
    # For each service:
    #   a) Direct policy lookup  -> deterministic, always correct
    #   b) CVE retrieval from DB -> semantic, filtered by service metadata
    #   c) Combined context      -> passed to LLM for structured analysis
    # ------------------------------------------------------------------
    for host in hosts_data:
        target_ip = host['target']
        print(f"\n[*] Starting analysis for host: {target_ip}")
        detailed_findings = []
        seen_findings: set[str] = set()
        findings_metadata = []

        for finding in host['findings']:
            s_name = finding.get('service', 'Unknown')
            port   = finding.get('port', 'unk')
            fid    = dedup_key(finding)

            if fid in seen_findings or any(n in s_name.lower() for n in noise):
                continue
            seen_findings.add(fid)

            search_query = build_search_query(finding)
            tunnel_label = 'ssl/' if finding.get('tunnel') == 'ssl' else ''
            print(f"    > Analyzing {s_name} ({tunnel_label}port {port}) -- query: '{search_query}'")

            # a) Direct policy lookup
            policy_context = get_policy_context(finding, policies)
            if policy_context:
                print(f"      [policy] {len(policy_context.splitlines())} alert(s) for '{s_name}'")

            # b) CVE retrieval filtered by service metadata
            cve_context = vsm.search_context(
                search_query,
                service_name=(finding.get('product') or s_name).split()[0].lower(),
                k=10
            )

            # c) Policy alerts first so the LLM sees them prominently
            specific_context = (
                f"{policy_context}\n\n{cve_context}" if policy_context else cve_context
            )

            service_analysis = summarizer.analyze_single_service(finding, specific_context)
            detailed_findings.append(service_analysis)

            findings_metadata.append({
                "service":            s_name.lower(),
                "product":            finding.get('product', s_name),
                "version":            finding.get('version', 'n/a'),
                "version_confidence": finding.get('version_confidence', 'low'),
                "port":               port,
                "tunnel":             finding.get('tunnel', '')
            })

        # ------------------------------------------------------------------
        # 5. CONSOLIDATE AND SAVE REPORT
        # ------------------------------------------------------------------
        if detailed_findings:
            # --- Section 3: Policy violations (deterministic) ---
            # Iterate over findings_metadata (already deduplicated) instead of
            # host['findings'] to avoid zip misalignment with duplicates.
            # findings_metadata carries service name via the 'service' key added below.
            policy_lines = []
            for meta in findings_metadata:
                s_name = meta.get('service', '').lower()
                port   = meta.get('port', '?')
                tunnel = meta.get('tunnel', '')
                enc    = " (SSL/TLS)" if tunnel == 'ssl' else ""
                product = meta.get('product') or s_name  # fallback to service name

                for policy in policies:
                    if s_name in policy.get('services', []):
                        # Skip "Unencrypted Protocol" policy for services already
                        # running over SSL/TLS — they satisfy the policy requirement.
                        if tunnel == 'ssl' and policy['category'] == 'Unencrypted Protocol':
                            break
                        policy_lines.append(
                            f"* **{product}** (port {port}{enc}) — "
                            f"**{policy['category']}** | Risk: {policy['risk']}\n"
                            f"  {policy['description']}"
                        )
                        break

            policy_section = "\n\n".join(policy_lines) if policy_lines \
                else "_No policy violations identified._"

            # --- Section 2: Service Inventory (deterministic) ---
            inv_rows = ["| Product | Version | Port | Encrypted | Risk Level |",
                        "|---------|---------|------|-----------|------------|"]
            for meta in findings_metadata:
                product = (meta.get('product') or meta.get('service', 'Unknown'))
                version = meta.get('version', 'n/a')
                vc      = meta.get('version_confidence', 'low')
                port    = meta.get('port', '?')
                tunnel  = meta.get('tunnel', '')
                enc     = "Yes (SSL/TLS)" if tunnel == 'ssl' else "No"
                ver_str = version if vc == 'high' else "not detected by scanner"
                inv_rows.append(
                    f"| {product} | {ver_str} | {port} | {enc} | — |"
                )
            inventory_section = "\n".join(inv_rows)

            print(f"\n[*] Consolidating report for {target_ip}...")
            final_report = summarizer.consolidate_report(
                target_ip,
                detailed_findings,
                findings_metadata,
                policy_section=policy_section,
                inventory_section=inventory_section
            )

            report_name = f"{target_ip.replace('.', '_')}_final_assessment"
            save_path   = reporter.save_report(report_name, final_report)
            print(f"[+] Report saved to: {save_path}")
        else:
            print(f"[-] No significant findings for {target_ip}.")


if __name__ == "__main__":
    main()