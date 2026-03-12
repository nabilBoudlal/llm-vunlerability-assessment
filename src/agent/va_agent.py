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

Your task is to produce a research plan: for each service, define the NVD keyword \
search queries needed to find relevant CVEs.

=== NVD KEYWORD SEARCH CONVENTIONS ===
NVD indexes CVEs by the PRODUCT NAME as it appears in CPE strings, not by service names.
Use the canonical product name, not the Nmap service label.

CRITICAL naming rules (Nmap label → correct NVD keyword):
  apache httpd      → "apache http server"   (NOT "apache httpd")
  distccd / distcc  → "distcc"               (NOT "distccd")
  apache jserv ajp  → "apache tomcat"        (NOT "apache jserv" or "ajp13")
  unrealircd        → "unrealircd"           ✓ correct as-is
  vsftpd            → "vsftpd"               ✓ correct as-is
  proftpd           → "proftpd"             ✓ correct as-is
  openssh           → "openssh"             ✓ correct as-is
  postfix           → "postfix"             ✓ correct as-is
  isc bind          → "bind"                (NOT "isc bind")
  mysql             → "mysql"               ✓ correct as-is
  postgresql        → "postgresql"          ✓ correct as-is
  samba smbd        → "samba"               (NOT "samba smbd")
  vnc               → "vnc"                 ✓ correct as-is
  ruby drb          → "ruby"                (use "drb" as second query)
  java rmi          → "java rmi"            ✓ correct as-is
  rpcbind           → "rpcbind"             ✓ correct as-is

Query construction rules:
1. Always use the CANONICAL NVD product name (see table above)
2. If version is known, add it as a second query: ["samba", "samba 3.0"]
3. For well-known backdoored versions, add a "backdoor" query: ["vsftpd 2.3.4", "vsftpd backdoor"]
4. For generic/wrapper services (tcpwrapped, nlockmgr, mountd, status, rpcbind aux):
   use 1 short query only
5. Maximum 3 queries per service
6. Keep each query 2-4 words

=== EXAMPLES ===
Apache httpd 2.2.8 on port 80:
  queries: ["apache http server 2.2", "apache http server"]

distccd v1 on port 3632:
  queries: ["distcc"]

Apache Jserv (ajp13) on port 8009:
  queries: ["apache tomcat", "ghostcat ajp"]

ISC BIND 9.4.2 on port 53:
  queries: ["bind 9.4.2", "bind dns"]

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
- Critical: CVSS >= 9.0 OR known RCE/backdoor OR bindshell/root shell exposure
- High: CVSS 7.0-8.9 OR cleartext protocol with sensitive data OR deprecated protocol
- Medium: CVSS 4.0-6.9 OR unnecessary service exposure
- Low: CVSS < 4.0 OR minor configuration issue
- Informational: no CVEs, no protocol risk, no exposure concern

IMPORTANT: if the service is a bindshell, root shell, or any form of backdoor, \
severity MUST be Critical.
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
        """LLM reads service list and produces research plan.
        
        Sends services in chunks of CHUNK_SIZE to avoid LLM truncation,
        then applies a safety-net that ensures every service has at least
        one query regardless of LLM output quality.
        """
        CHUNK_SIZE = 10
        print("\n[Phase 1] LLM planning research queries...")

        full_plan = []
        chunks = [services[i:i+CHUNK_SIZE] for i in range(0, len(services), CHUNK_SIZE)]

        for chunk_idx, chunk in enumerate(chunks, 1):
            print(f"  [chunk {chunk_idx}/{len(chunks)}] planning {len(chunk)} services...")
            prompt = PLANNING_PROMPT.format(
                services_json=json.dumps(chunk, indent=2)
            )
            response = self.llm.invoke(prompt).strip()

            if self.verbose and chunk_idx == 1:
                print(f"  [llm raw] {response[:300]}...")

            try:
                m = re.search(r'\[[\s\S]+\]', response)
                if m:
                    chunk_plan = json.loads(m.group(0))
                    full_plan.extend(chunk_plan)
                    print(f"  [chunk {chunk_idx}] → {len(chunk_plan)} entries parsed")
                else:
                    raise ValueError("No JSON array found")
            except Exception as e:
                print(f"  [!] Chunk {chunk_idx} parse failed ({e}) — using deterministic fallback for this chunk")
                for s in chunk:
                    full_plan.append({
                        "port":    s["port"],
                        "service": s["service"],
                        "product": s["product"],
                        "version": s["version"],
                        "queries": [f"{s['product']} {s['version']}".strip()]
                    })

        # ── Safety net: ensure EVERY service has at least one query ──────────
        planned_ports = {str(p.get("port", "")) for p in full_plan}
        missing = [s for s in services if str(s["port"]) not in planned_ports]
        if missing:
            print(f"  [safety-net] Adding deterministic queries for "
                  f"{len(missing)} uncovered services: "
                  f"{[s['port'] for s in missing]}")
            for s in missing:
                product = s.get("product") or s.get("service", "unknown")
                version = s.get("version", "")
                query   = f"{product} {version}".strip() if version not in ("n/a", "") else product
                full_plan.append({
                    "port":    s["port"],
                    "service": s["service"],
                    "product": product,
                    "version": version,
                    "queries": [query]
                })

        total_queries = sum(len(p.get("queries", [])) for p in full_plan)
        print(f"  [plan] {len(full_plan)} services planned, {total_queries} total queries")
        return full_plan

    # ── Phase 2: Python executes queries ─────────────────────────────────────

    def _phase2_fetch(self, plan: list) -> object:
        """
        Execute NVD/OSV queries from the plan.
        Index results in ChromaDB with metadata {port, service}.
        Returns populated VectorStoreManager.
        """
        import shutil
        from src.utils.multi_source_api import MultiSourceCVEDownloader
        from src.utils.vectore_store import VectorStoreManager

        # Clear stale DB from previous runs — prevents context contamination
        db_path = "vector_db"
        if os.path.exists(db_path):
            shutil.rmtree(db_path)
            print("  [db] Cleared stale vector_db/")

        downloader   = MultiSourceCVEDownloader(
            nvd_api_key=os.getenv("NVD_API_KEY")
        )
        vsm          = VectorStoreManager(db_path=db_path)
        cve_sources  = {}
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
                # fetch_structured returns full CVEEntry objects (CVSS, has_exploit,
                # actively_exploited, sources) instead of plain backward-compat strings
                entries = downloader.fetch_structured(
                    query_clean, results_per_page=10
                )
                if not entries:
                    print(f"    → 0 CVEs")
                    continue

                texts, metas = [], []
                for item in entries:
                    cid      = item.id
                    cvss     = str(item.cvss_score) if item.cvss_score not in (None, "N/A", "") else "N/A"
                    rag_text = item.to_rag_text()

                    # Merge into cve_sources — preserve best CVSS, OR-merge flags
                    existing = cve_sources.get(cid)
                    if existing:
                        existing["has_exploit"]        = existing["has_exploit"] or item.has_exploit
                        existing["actively_exploited"] = existing["actively_exploited"] or item.actively_exploited
                        if item.source not in existing["sources"]:
                            existing["sources"].append(item.source)
                    else:
                        cve_sources[cid] = {
                            "cvss":               cvss,
                            "sources":            [item.source],
                            "port":               port,
                            "service":            service,
                            "description":        item.description[:300],
                            "url":                f"https://nvd.nist.gov/vuln/detail/{cid}",
                            "has_exploit":        item.has_exploit,
                            "actively_exploited": item.actively_exploited,
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

            # Parse JSON — 3-strategy cascade for llama's inconsistent output
            def _parse_llm_json(resp):
                start = resp.find('{')
                if start == -1: return {}
                chunk = resp[start:]
                # S1: raw_decode — handles preamble + braces inside strings
                try:
                    raw, _ = json.JSONDecoder().raw_decode(chunk)
                    return {k.lower(): v for k, v in raw.items()}
                except Exception: pass
                # S2: escape raw newlines inside quoted strings, retry
                fixed = re.sub(r'"(?:[^"\\]|\\.)*"',
                               lambda m: m.group(0).replace('\n', '\\n'),
                               chunk, flags=re.DOTALL)
                try:
                    raw, _ = json.JSONDecoder().raw_decode(fixed)
                    return {k.lower(): v for k, v in raw.items()}
                except Exception: pass
                # S3: regex — CVEs only from cves_cited section to avoid duplicates
                sm = re.search(r'"[Ss]everity"\s*:\s*"(\w+)"', resp)
                cve_end = resp.find('"analysis"') if '"analysis"' in resp else len(resp)
                cm = list(dict.fromkeys(re.findall(r'CVE-\d{4}-\d+', resp[:cve_end])))
                if sm:
                    print(f"    [!] Fallback extracted: severity={sm.group(1)}")
                    return {"severity": sm.group(1), "cves_cited": cm,
                            "analysis": "", "remediation": ""}
                return {}
            analysis = _parse_llm_json(response)
            if not analysis:
                print(f"    [!] All parse strategies failed")

            sev   = analysis.get("severity", "Informational")

            # Deterministic override: bindshell / root shell is always Critical
            backdoor_keywords = ("bindshell", "root shell", "backdoor", "metasploitable")
            if any(kw in (product + " " + service).lower() for kw in backdoor_keywords):
                if sev != "Critical":
                    print(f"    [override] {sev} → Critical (bindshell/root shell detected)")
                    sev = "Critical"
            cves  = analysis.get("cves_cited", [])

            # Anti-hallucination: accept CVE only if it was retrieved from NVD
            # (either in cve_sources dict OR visible in the retrieved context text)
            # Additionally reject CVEs with impossible years (future or pre-1999)
            import datetime
            current_year = datetime.datetime.now().year
            def _valid_cve_year(cve_id: str) -> bool:
                m = re.match(r'CVE-(\d{4})-', cve_id)
                if not m:
                    return False
                year = int(m.group(1))
                return 1999 <= year <= current_year

            verified_cves = [c for c in cves
                             if (c in cve_sources or c in cve_context)
                             and _valid_cve_year(c)]
            hallucinated  = [c for c in cves
                             if c not in verified_cves]
            if hallucinated:
                print(f"    [!] Removed hallucinated CVEs: {hallucinated}")
            cves = verified_cves

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

            # Build CVE references enriched with all metadata from cve_sources
            cve_refs = []
            has_exploit        = False
            actively_exploited = False
            for cid in cves:
                src = cve_sources.get(cid, {})
                cve_refs.append({
                    "id":                cid,
                    "url":               src.get("url", f"https://nvd.nist.gov/vuln/detail/{cid}"),
                    "cvss":              src.get("cvss", "N/A"),
                    "sources":           src.get("sources", []),
                    "has_exploit":       src.get("has_exploit", False),
                    "actively_exploited": src.get("actively_exploited", False),
                })
                has_exploit        = has_exploit or src.get("has_exploit", False)
                actively_exploited = actively_exploited or src.get("actively_exploited", False)

            # Log important flags
            if has_exploit:
                print(f"    [exploit] public exploit available for this service")
            if actively_exploited:
                print(f"    [KEV] 🚨 CISA KEV — actively exploited in the wild!")

            finding = {
                "port":               port,
                "service":            f"{product} {version}".strip(),
                "target":             svc.get("target", ""),
                "severity":           sev,
                "cvss":               best_cvss,
                "cves":               ", ".join(cves) if cves else "None",
                "cve_refs":           cve_refs,
                "analysis":           analysis.get("analysis", ""),
                "remediation":        analysis.get("remediation", ""),
                "has_exploit":        has_exploit,
                "actively_exploited": actively_exploited,
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