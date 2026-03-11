"""
VA Agent — 3-phase architecture:
  Phase 1: LLM reads normalized services → produces research plan
  Phase 2: Python executes NVD/OSV queries → populates ChromaDB with metadata
  Phase 3: LLM analyses each service grounded on retrieved CVE context
"""
import json
import re
import os
from langchain_ollama import OllamaLLM
from dotenv import load_dotenv

load_dotenv()

# ── Prompts ───────────────────────────────────────────────────────────────────

PLANNING_PROMPT = """\
You are a cybersecurity analyst performing a vulnerability assessment.
You have been given a list of services discovered on a target machine.

DISCOVERED SERVICES:
{services_json}

Your task is to produce a research plan: for each service that may have security \
vulnerabilities, define the NVD search queries needed to find relevant CVEs.

Rules:
- Focus on services with specific product names and versions
- Generic services with no version (e.g. tcpwrapped, status, nlockmgr) need only 1 generic query
- For well-known vulnerable services (vsftpd, telnet, ftp, smb) add extra targeted queries
- You may add cross-service queries if you suspect shared libraries or components
- Keep queries short and specific (2-5 words max)

Output ONLY a valid JSON array, no other text:
[
  {{
    "port": "21",
    "service": "vsftpd",
    "product": "vsftpd",
    "version": "2.3.4",
    "queries": ["vsftpd 2.3.4", "vsftpd backdoor"]
  }},
  ...
]
"""

ANALYSIS_PROMPT = """\
You are a senior cybersecurity analyst performing a vulnerability assessment.
Analyse the service below using ONLY the provided CVE context and your security knowledge.

SERVICE: {product} {version} on port {port}
PROTOCOL/SERVICE TYPE: {service}

CVE CONTEXT FROM NVD:
{cve_context}

Evaluate:
1. Known CVEs from the context above — cite them explicitly with their CVSS scores
2. Intrinsic protocol/service risks (e.g. cleartext transmission, deprecated protocols, \
unnecessary exposure)
3. Overall risk considering both CVEs and protocol risks

Output ONLY a valid JSON object, no other text:
{{
  "severity": "Critical|High|Medium|Low|Informational",
  "cves_cited": ["CVE-XXXX-XXXX", ...],
  "analysis": "2-3 sentence technical explanation citing specific CVEs and risks",
  "remediation": "concrete step 1 | concrete step 2 | concrete step 3"
}}

Severity rules:
- Critical: CVSS >= 9.0 OR known RCE/backdoor
- High: CVSS 7.0-8.9 OR cleartext protocol with sensitive data OR deprecated protocol
- Medium: CVSS 4.0-6.9 OR unnecessary service exposure
- Low: CVSS < 4.0 OR minor configuration issue
- Informational: no CVEs, no protocol risk, no exposure concern
"""

# ── Phase 1: LLM Planning ─────────────────────────────────────────────────────

class VAAgent:
    def __init__(self, model_name: str = "qwen3:8b", verbose: bool = True):
        self.llm     = OllamaLLM(model=model_name, temperature=0.0)
        self.verbose = verbose
        self.model   = model_name

    def _parse_scan(self, scan_path: str) -> tuple:
        """Returns (target_ip, services_list)."""
        from src.utils.parsers import ParserFactory
        hosts    = ParserFactory.get_parser(scan_path)
        services = []
        seen     = set()
        target   = "unknown"
        for host in hosts:
            target = host["target"]
            for f in host["findings"]:
                port = str(f.get("port", "?"))
                if port in seen:
                    continue
                seen.add(port)
                services.append({
                    "port":    port,
                    "service": f.get("service", "unknown"),
                    "product": f.get("product") or f.get("service", "unknown"),
                    "version": f.get("version", "n/a"),
                })
        return target, services

    def _phase1_plan(self, services: list) -> list:
        """LLM reads service list and produces research plan."""
        print("\n[Phase 1] LLM planning research queries...")
        prompt = PLANNING_PROMPT.format(
            services_json=json.dumps(services, indent=2)
        )
        response = self.llm.invoke(prompt).strip()

        if self.verbose:
            print(f"  [llm raw] {response[:300]}...")

        # Extract JSON array
        try:
            m = re.search(r'\[[\s\S]+\]', response)
            if m:
                plan = json.loads(m.group(0))
                print(f"  [plan] {len(plan)} services planned, "
                      f"{sum(len(p.get('queries',[])) for p in plan)} total queries")
                return plan
        except Exception as e:
            print(f"  [!] Failed to parse plan: {e}")

        # Fallback: build basic plan from services
        print("  [!] Using fallback plan (product+version per service)")
        return [
            {
                "port":    s["port"],
                "service": s["service"],
                "product": s["product"],
                "version": s["version"],
                "queries": [f"{s['product']} {s['version']}".strip()]
            }
            for s in services
        ]

    # ── Phase 2: Python executes queries ─────────────────────────────────────

    def _phase2_fetch(self, plan: list) -> object:
        """
        Execute NVD/OSV queries from the plan.
        Index results in ChromaDB with metadata {port, service}.
        Returns populated VectorStoreManager.
        """
        from src.utils.multi_source_api import MultiSourceCVEDownloader
        from src.utils.vectore_store import VectorStoreManager

        downloader  = MultiSourceCVEDownloader(
            nvd_api_key=os.getenv("NVD_API_KEY")
        )
        vsm         = VectorStoreManager()
        cve_sources = {}   # {cve_id: {cvss, source, description}}
        seen_queries = set()

        print("\n[Phase 2] Executing NVD queries and indexing results...")

        for entry in plan:
            port    = str(entry.get("port", "?"))
            service = entry.get("service", "unknown")
            queries = entry.get("queries", [])

            for query in queries:
                query_clean = query.strip().strip("'\"")
                if not query_clean or query_clean in seen_queries:
                    continue
                seen_queries.add(query_clean)

                print(f"  > [{port}] query: {query_clean}")
                results = downloader.fetch_by_keyword(
                    query_clean, results_per_page=10
                )
                if not results:
                    print(f"    → 0 CVEs")
                    continue

                texts, metas = [], []
                for item in results:
                    if isinstance(item, str):
                        import re as _re
                        cid = _re.search(r'CVE-[\d-]+', item)
                        cid = cid.group(0) if cid else "UNKNOWN"
                        rag_text = item
                        cvss     = "N/A"
                    else:
                        cid      = item.id
                        cvss     = str(item.cvss_score) if item.cvss_score else "N/A"
                        rag_text = (item.to_rag_text()
                                    if hasattr(item, "to_rag_text") else str(item))

                    cve_sources[cid] = {
                        "cvss":        cvss,
                        "source":      "nvd",
                        "port":        port,
                        "service":     service,
                        "description": rag_text[:300],
                        "url":         f"https://nvd.nist.gov/vuln/detail/{cid}"
                    }
                    texts.append(rag_text)
                    metas.append({"port": port, "service": service, "cve_id": cid})

                # Index with metadata
                if texts:
                    if vsm.db is None:
                        vsm.initialize_db_with_metadata(texts, metas)
                    else:
                        vsm.add_texts_with_metadata(texts, metas)
                    print(f"    → {len(texts)} CVEs indexed")

        return vsm, cve_sources

    # ── Phase 3: LLM analysis grounded on ChromaDB ───────────────────────────

    def _phase3_analyse(self, services: list, vsm, cve_sources: dict) -> list:
        """
        For each service: retrieve CVE context filtered by port/service,
        then LLM produces structured JSON analysis.
        """
        print("\n[Phase 3] LLM grounded analysis per service...")
        findings = []

        for i, svc in enumerate(services, 1):
            port    = str(svc.get("port", "?"))
            service = svc.get("service", "unknown")
            product = svc.get("product") or service
            version = svc.get("version", "n/a")

            print(f"\n  [{i}/{len(services)}] Port {port} ({product} {version})")

            # Retrieve CVE context filtered by port
            cve_context = "No CVEs found in NVD for this service."
            if vsm.db is not None:
                try:
                    raw = vsm.search_context_filtered(
                        query=f"{product} {version} vulnerability exploit",
                        port=port,
                        k=5
                    )
                    if raw:
                        cve_context = raw
                except Exception:
                    # Fallback: unfiltered search
                    try:
                        cve_context = vsm.search_context(
                            f"{product} vulnerability", k=5
                        )
                    except Exception:
                        pass

            print(f"    [ctx] {cve_context[:100]}...")

            # LLM analysis
            prompt = ANALYSIS_PROMPT.format(
                product=product,
                version=version,
                port=port,
                service=service,
                cve_context=cve_context,
            )
            response = self.llm.invoke(prompt).strip()

            if self.verbose:
                print(f"    [llm] {response[:200]}...")

            # Parse JSON
            analysis = {}
            try:
                m = re.search(r'\{[\s\S]+\}', response)
                if m:
                    analysis = json.loads(m.group(0))
            except Exception:
                pass

            sev   = analysis.get("severity", "Informational")
            cves  = analysis.get("cves_cited", [])

            # Build CVSS from cve_sources
            best_cvss = "N/A"
            best_val  = 0.0
            for cid in cves:
                try:
                    v = float(cve_sources.get(cid, {}).get("cvss", "N/A"))
                    if v > best_val:
                        best_val  = v
                        best_cvss = str(v)
                except Exception:
                    pass

            # Build CVE references with NVD URLs
            cve_refs = []
            for cid in cves:
                url = cve_sources.get(cid, {}).get(
                    "url", f"https://nvd.nist.gov/vuln/detail/{cid}"
                )
                cve_refs.append({"id": cid, "url": url})

            finding = {
                "port":        port,
                "service":     f"{product} {version}".strip(),
                "target":      svc.get("target", ""),
                "severity":    sev,
                "cvss":        best_cvss,
                "cves":        ", ".join(cves) if cves else "None",
                "cve_refs":    cve_refs,
                "analysis":    analysis.get("analysis", ""),
                "remediation": analysis.get("remediation", ""),
                "has_exploit": False,
            }

            findings.append(finding)
            print(f"    → {sev} | CVEs: {finding['cves'][:60]}")

        return findings

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self, scan_path: str) -> tuple:
        print(f"[*] Parsing scan file: {scan_path}")
        target, services = self._parse_scan(scan_path)
        print(f"[*] Target: {target} | {len(services)} services found")

        # Phase 1
        plan = self._phase1_plan(services)

        # Attach target to each service for later
        for svc in services:
            svc["target"] = target

        # Phase 2
        vsm, cve_sources = self._phase2_fetch(plan)

        # Phase 3
        findings = self._phase3_analyse(services, vsm, cve_sources)

        print(f"\n[*] Done — {len(findings)} findings.")
        return findings, cve_sources, target