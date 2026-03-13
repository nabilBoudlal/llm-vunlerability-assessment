"""
VA Agent — 3-phase architecture (v6)
  Phase 1  : LLM reads normalized services → produces research plan
  Phase 2  : Python executes NVD/OSV queries → populates ChromaDB with metadata
  Phase 1.5: Agentic reflection loop — LLM reviews Phase-2 coverage gaps
             and autonomously requests additional targeted queries (FIX-6)
  Phase 3  : LLM analyses each service grounded on retrieved CVE context

Fixes applied (v5):
  FIX-1  Anti-hallucination: CVE verification is now PORT-SCOPED
           (prevents MySQL CVEs from being accepted for a BACnet service)
  FIX-2  vsftpd backdoor query only emitted when version == 2.3.4
  FIX-3  Deterministic overrides: Docker 2375, Jupyter 8888,
           Modbus 502, DNP3 20000, EtherNet/IP 44818 (ICS no-auth risks)
  FIX-4  Version-era year filter: products versioned >= 2015 discard CVEs < 2010
  FIX-5  CVE Reference URLs propagated through cve_refs (reporter renders them)
  FIX-6  Agentic Phase 1.5: LLM reviews coverage gaps and autonomously adds queries

  RC-1  Vendor-mismatch filter: Phase 3 rejects CVEs whose NVD description
           does not mention the target product name (catches Schneider/Redis confusion)
  RC-2  _version_era() fallback for Windows/Microsoft services:
           "n/a" version with Windows product → era defaults to 2000
  RC-3  Python-level CVSS override: best_cvss >= 9.0 forces Critical
           (LLM prompt rule alone is insufficient)
  RC-4  _version_era() lookup table extended to cover major versions 1-5
  RC-5  PLANNING_PROMPT: SMB and RDP now use more specific NVD query strings
           targeting EternalBlue/BlueKeep-class CVEs
"""
import json
import re
import os
import datetime
from langchain_ollama import OllamaLLM
from dotenv import load_dotenv

load_dotenv()

CURRENT_YEAR = datetime.datetime.now().year

# ─────────────────────────────────────────────────────────────────────────────
# Prompts
# ─────────────────────────────────────────────────────────────────────────────

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

CRITICAL naming rules (Nmap label -> correct NVD keyword):
  apache httpd      -> "apache http server"   (NOT "apache httpd")
  distccd / distcc  -> "distcc"               (NOT "distccd")
  apache jserv ajp  -> "apache tomcat"        (NOT "apache jserv" or "ajp13")
  unrealircd        -> "unrealircd"
  vsftpd            -> "vsftpd"
  proftpd           -> "proftpd"
  openssh           -> "openssh"
  postfix           -> "postfix"
  isc bind          -> "bind"                 (NOT "isc bind")
  mysql             -> "mysql"
  postgresql        -> "postgresql"
  samba smbd        -> "samba"                (NOT "samba smbd")
  vnc               -> "vnc"
  ruby drb          -> "ruby"                 (use "drb" as second query)
  java rmi          -> "java rmi"
  rpcbind           -> "rpcbind"

ICS / INDUSTRIAL PROTOCOLS:
  modbus / modbus tcp (port 502)        -> "modbus"
  dnp3 / dnp3 outstation (port 20000)   -> "dnp3"
  siemens s7 / iso-tsap (port 102)      -> "siemens s7"
  ethernet/ip / enip (port 44818)       -> "ethernet ip rockwell"
  bacnet / bacnet ip (port 47808)       -> "bacnet"
  net-snmp / snmp                       -> "net-snmp"

WINDOWS ECOSYSTEM:
  SMB / microsoft-ds (port 445)  -> "microsoft smb remote code execution", "windows smb"
                                    (use "microsoft smb remote code execution" as FIRST query
                                     to capture EternalBlue-class CVEs like CVE-2017-0144)
  RDP / ms-wbt-server (port 3389)-> "windows remote desktop services remote code", "remote desktop protocol"
                                    (use "windows remote desktop services remote code" as FIRST query
                                     to capture BlueKeep-class CVEs like CVE-2019-0708)
  IIS httpd (port 80/443)        -> "microsoft internet information services"
  MS SQL Server                  -> "sql server"
  Windows RPC / msrpc (port 135) -> "windows rpc remote code execution", "windows rpc"
  Windows DNS (port 53)          -> "windows dns server"
  Active Directory / LDAP (389)  -> "active directory", "windows ldap"
  Kerberos (port 88)             -> "windows kerberos"
  WinRM / HTTPAPI (port 5985)    -> "windows remote management", "winrm"
  Print Spooler                  -> "windows print spooler"

Query construction rules:
1. Use canonical NVD product names (see tables above)
2. If version is known, add it as a second query: ["samba", "samba 3.0"]
3. BACKDOOR RULE: only add a "backdoor" query for vsftpd version 2.3.4 specifically.
   For all other vsftpd versions use only ["vsftpd", "vsftpd <version>"].
4. For generic services (tcpwrapped, nlockmgr, mountd, status): 1 short query only
5. Maximum 3 queries per service
6. Keep each query 2-4 words

=== EXAMPLES ===
Apache httpd 2.2.8 on port 80:
  queries: ["apache http server 2.2", "apache http server"]

vsftpd 2.3.4 on port 21:
  queries: ["vsftpd 2.3.4", "vsftpd backdoor"]

vsftpd 3.0.2 on port 21:
  queries: ["vsftpd 3.0.2", "vsftpd"]

BACnet/IP on port 47808:
  queries: ["bacnet"]

Output ONLY a valid JSON array, no other text:
[
  {{
    "port": "21",
    "service": "ftp",
    "product": "vsftpd",
    "version": "2.3.4",
    "queries": ["vsftpd 2.3.4", "vsftpd backdoor"]
  }}
]
"""

REFLECTION_PROMPT = """\
You are a cybersecurity analyst reviewing the results of an automated CVE search.

TARGET SERVICES AND CURRENT COVERAGE:
{coverage_json}

For each service you can see how many CVEs were found and sample CVE IDs.
Your task: identify services with POOR coverage and propose up to 5 additional
targeted NVD search queries to improve it.

Focus on:
- Services with 0 CVEs found
- Critical services (databases, web servers, industrial protocols) that need more coverage
- Services where the sample CVEs look unrelated to the product

Output ONLY a valid JSON array (empty [] if coverage is already good):
[
  {{
    "port": "6379",
    "service": "redis",
    "reason": "No Redis-specific CVEs found, only third-party CVEs",
    "queries": ["redis server rce", "redis lua sandbox"]
  }}
]
If coverage looks good, output exactly: []
"""

ANALYSIS_PROMPT = """\
You are a senior cybersecurity analyst performing a vulnerability assessment.
Analyse the service below using ONLY the provided CVE context and your security knowledge.

SERVICE: {product} {version} on port {port}
PROTOCOL/SERVICE TYPE: {service}

CVE CONTEXT FROM NVD:
{cve_context}

Evaluate:
1. Known CVEs from the context above -- cite them with their CVSS scores
2. Intrinsic protocol/service risks (cleartext, deprecated protocols, unnecessary exposure)
3. Overall risk considering both CVEs and protocol risks

STRICT RULE: cite ONLY CVE IDs that appear in the CVE CONTEXT above.
Do NOT invent or recall CVE IDs from memory.

Output ONLY a valid JSON object, no other text:
{{
  "severity": "Critical|High|Medium|Low|Informational",
  "cves_cited": ["CVE-XXXX-XXXX"],
  "analysis": "2-3 sentence technical explanation citing specific CVEs and risks",
  "remediation": "step 1 | step 2 | step 3"
}}

Severity rules:
- Critical: CVSS >= 9.0 OR known RCE/backdoor OR bindshell/root shell
- High: CVSS 7.0-8.9 OR cleartext protocol OR deprecated protocol
- Medium: CVSS 4.0-6.9 OR unnecessary exposure
- Low: CVSS < 4.0 OR minor config issue
- Informational: no CVEs, no protocol risk

IMPORTANT: if the service is a bindshell, root shell, or backdoor, severity MUST be Critical.
"""

# ─────────────────────────────────────────────────────────────────────────────
# FIX-3: Deterministic overrides for architectural / no-auth risks
# These bypass the LLM entirely and are always Critical.
# ─────────────────────────────────────────────────────────────────────────────
ARCH_CRITICAL_OVERRIDES = {
    "2375": (
        "Docker Remote API — unauthenticated",
        "Docker daemon API exposed on port 2375 without TLS or authentication. "
        "Any network attacker can create privileged containers, mount the host "
        "filesystem and achieve full host takeover. This is an architectural "
        "misconfiguration with no single CVE identifier.",
        "Disable unauthenticated Docker API | "
        "Bind daemon to Unix socket only (unix:///var/run/docker.sock) | "
        "If remote access is required, enforce mutual TLS (--tlsverify)"
    ),
    "8888": (
        "Jupyter Notebook — no authentication",
        "Jupyter Notebook server is accessible without a password or token. "
        "Any network attacker can execute arbitrary Python code in the server "
        "kernel, giving full remote code execution with the Jupyter process privileges.",
        "Set a strong token or password in jupyter_notebook_config.py | "
        "Bind to localhost only and expose via an authenticated reverse proxy | "
        "Upgrade to JupyterLab and enable an identity provider"
    ),
    "502": (
        "Modbus TCP — no authentication by design",
        "Modbus TCP (port 502) provides zero authentication or encryption by "
        "specification (Modicon Modbus Protocol Reference Guide, 1979). Any "
        "attacker on the network can issue read/write coil and register commands "
        "to directly manipulate PLC I/O — a Critical industrial risk.",
        "Isolate Modbus devices behind a dedicated OT DMZ | "
        "Deploy a unidirectional security gateway or industrial firewall | "
        "Apply network whitelisting, VPN, and anomaly detection as compensating controls"
    ),
    "20000": (
        "DNP3 — unauthenticated SCADA protocol",
        "DNP3 (port 20000) lacks authentication in its base specification. "
        "Attackers can send spoofed DNP3 frames to outstations to gain "
        "unauthorised control of field devices. DNP3 Secure Authentication v5 "
        "exists but is rarely deployed in legacy environments.",
        "Deploy DNP3 Secure Authentication v5 | "
        "Segment network so DNP3 traffic is firewalled from corporate LAN | "
        "Monitor for anomalous DNP3 function codes (write, direct operate)"
    ),
    "44818": (
        "EtherNet/IP — unauthenticated industrial protocol",
        "EtherNet/IP (ODVA, port 44818) has no built-in authentication. "
        "Attackers can send CIP (Common Industrial Protocol) commands to "
        "enumerate, read, and write to PLCs and automation devices without credentials.",
        "Restrict EtherNet/IP traffic to a dedicated OT network segment | "
        "Apply IP allowlisting on the industrial firewall | "
        "Monitor with an ICS-specific IDPS (e.g. Claroty, Dragos, Nozomi)"
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# RC-5: Known Critical CVEs for Windows services that NVD keyword search misses.
# These are injected into the context for the relevant port, regardless of what
# the generic NVD query returns.
# Format: { port: [(cve_id, cvss, short_description)] }
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_CRITICAL_CVES: dict = {
    # SMB — EternalBlue family (used by WannaCry, NotPetya)
    "445": [
        ("CVE-2017-0144", "9.8",
         "EternalBlue: Remote code execution in SMBv1 (Microsoft Windows). "
         "Exploited by WannaCry and NotPetya ransomware. CISA KEV."),
        ("CVE-2017-0143", "9.8",
         "EternalRomance: Remote code execution in SMBv1 (Microsoft Windows). CISA KEV."),
        ("CVE-2017-0145", "9.8",
         "EternalChampion: Remote code execution in SMBv1 (Microsoft Windows). CISA KEV."),
    ],
    # RDP — BlueKeep and DejaBlue
    "3389": [
        ("CVE-2019-0708", "9.8",
         "BlueKeep: Unauthenticated pre-auth RCE in Remote Desktop Services "
         "(Windows XP/7/2003/2008). Wormable. CISA KEV."),
        ("CVE-2019-1181", "9.8",
         "DejaBlue: RCE in Remote Desktop Services (Windows 8/10/2019). Wormable."),
        ("CVE-2019-1182", "9.8",
         "DejaBlue variant: RCE in Remote Desktop Services (Windows 8/10/2019). Wormable."),
    ],
    # MS Print Spooler — PrintNightmare
    "445+spooler": [
        ("CVE-2021-34527", "8.8",
         "PrintNightmare: RCE/LPE in Windows Print Spooler service. CISA KEV."),
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _version_era(version: str, product: str = ""):
    """
    RC-4 + RC-2: estimate the release era of a version string.
    Returns an integer year or None.

    RC-4: extended major-version table to cover 1-5 (Node 4.x, PHP 5.x, etc.)
    RC-2: Windows/Microsoft services with no version string default to era 2000,
          so CVE-1999-xxxx are still excluded by _valid_cve_year.
    """
    m = re.search(r'\b(199\d|200\d|201\d|202\d)\b', version or "")
    if m:
        return int(m.group(1))
    m2 = re.match(r'(\d+)\.', version or "")
    if m2:
        major = int(m2.group(1))
        if major >= 8:  return 2019
        if major >= 7:  return 2016
        if major >= 6:  return 2012
        if major >= 5:  return 2010   # RC-4: Node 5.x, PHP 5.x
        if major >= 4:  return 2009   # RC-4: Node 4.x, Express 4.x
        if major >= 2:  return 2005   # RC-4: Python 2.x, legacy
        if major >= 1:  return 2002   # RC-4: legacy 1.x
    # RC-2: Windows/Microsoft services with no parseable version
    prod_lower = (product or "").lower()
    if any(kw in prod_lower for kw in ("windows", "microsoft", "ms-")):
        return 2000
    return None


def _valid_cve_year(cve_id: str, version: str = "", product: str = "") -> bool:
    """
    RC-4 + RC-2: accept a CVE only if its year is plausible.
    - Reject year < 1999 (pre-CVE era).
    - Reject year >= current year (future hallucinations — NVD doesn't have future CVEs).
    - If product era >= 2015, reject CVEs with year < 2010.
    """
    m = re.match(r'CVE-(\d{4})-', cve_id)
    if not m:
        return False
    year = int(m.group(1))
    if year < 1999 or year >= CURRENT_YEAR:   # strict < rejects current-year hallucinations
        return False
    era = _version_era(version, product)
    if era and era >= 2015 and year < 2010:
        return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
# VAAgent
# ─────────────────────────────────────────────────────────────────────────────

class VAAgent:
    def __init__(self, model_name: str = "qwen3:8b", verbose: bool = True):
        self.llm     = OllamaLLM(model=model_name, temperature=0.0)
        self.verbose = verbose
        self.model   = model_name

    # ── Scan parsing ──────────────────────────────────────────────────────────

    def _parse_scan(self, scan_path: str) -> tuple:
        from src.utils.parsers import ParserFactory
        hosts, services, seen, target = ParserFactory.get_parser(scan_path), [], set(), "unknown"
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

    # ── Phase 1 ───────────────────────────────────────────────────────────────

    def _phase1_plan(self, services: list) -> list:
        CHUNK_SIZE = 10
        print("\n[Phase 1] LLM planning research queries...")

        full_plan = []
        chunks = [services[i:i+CHUNK_SIZE] for i in range(0, len(services), CHUNK_SIZE)]

        for idx, chunk in enumerate(chunks, 1):
            print(f"  [chunk {idx}/{len(chunks)}] planning {len(chunk)} services...")
            response = self.llm.invoke(
                PLANNING_PROMPT.format(services_json=json.dumps(chunk, indent=2))
            ).strip()
            if self.verbose and idx == 1:
                print(f"  [llm raw] {response[:300]}...")
            try:
                m = re.search(r'\[[\s\S]+\]', response)
                if not m:
                    raise ValueError("No JSON array found")
                chunk_plan = json.loads(m.group(0))
                full_plan.extend(chunk_plan)
                print(f"  [chunk {idx}] -> {len(chunk_plan)} entries parsed")
            except Exception as e:
                print(f"  [!] Chunk {idx} parse failed ({e}) -- deterministic fallback")
                for s in chunk:
                    full_plan.append({
                        "port": s["port"], "service": s["service"],
                        "product": s["product"], "version": s["version"],
                        "queries": [f"{s['product']} {s['version']}".strip()],
                    })

        # Safety-net
        planned_ports = {str(p.get("port", "")) for p in full_plan}
        missing = [s for s in services if str(s["port"]) not in planned_ports]
        if missing:
            print(f"  [safety-net] Fallback for {len(missing)} uncovered ports: "
                  f"{[s['port'] for s in missing]}")
            for s in missing:
                product = s.get("product") or s.get("service", "unknown")
                version = s.get("version", "")
                query   = f"{product} {version}".strip() if version not in ("n/a", "") else product
                full_plan.append({
                    "port": s["port"], "service": s["service"],
                    "product": product, "version": version, "queries": [query],
                })

        # FIX-2: sanitize vsftpd backdoor query
        for entry in full_plan:
            if entry.get("product", "").lower() == "vsftpd":
                version = str(entry.get("version", ""))
                cleaned = []
                for q in entry.get("queries", []):
                    if "backdoor" in q.lower() and "2.3.4" not in version:
                        print(f"  [fix-2] Removed 'backdoor' query for vsftpd {version} "
                              f"(backdoor query only valid for v2.3.4)")
                        continue
                    cleaned.append(q)
                entry["queries"] = cleaned or [f"vsftpd {version}".strip()]

        total_q = sum(len(p.get("queries", [])) for p in full_plan)
        print(f"  [plan] {len(full_plan)} services planned, {total_q} total queries")
        return full_plan

    # ── Phase 2 ───────────────────────────────────────────────────────────────

    def _phase2_fetch(self, plan: list) -> tuple:
        """
        Returns (vsm, cve_sources, port_cve_index).
        port_cve_index: port -> set of CVE IDs indexed for that port (FIX-1).
        """
        import shutil
        from src.utils.multi_source_api import MultiSourceCVEDownloader
        from src.utils.vectore_store import VectorStoreManager

        db_path = "vector_db"
        if os.path.exists(db_path):
            shutil.rmtree(db_path)
            print("  [db] Cleared stale vector_db/")

        downloader     = MultiSourceCVEDownloader(nvd_api_key=os.getenv("NVD_API_KEY"))
        vsm            = VectorStoreManager(db_path=db_path)
        cve_sources    = {}
        port_cve_index = {}   # FIX-1
        seen_queries   = set()

        print("\n[Phase 2] Executing NVD queries and indexing results...")

        for entry in plan:
            port    = str(entry.get("port", "?"))
            service = entry.get("service", "unknown")
            queries = entry.get("queries", [])
            port_cve_index.setdefault(port, set())

            for query in queries:
                q = query.strip().strip("'\"")
                if not q or q in seen_queries:
                    continue
                seen_queries.add(q)
                print(f"  > [{port}] query: {q}")
                entries = downloader.fetch_structured(q, results_per_page=10)
                if not entries:
                    print(f"    -> 0 CVEs")
                    continue

                texts, metas = [], []
                for item in entries:
                    cid = item.id
                    port_cve_index[port].add(cid)   # FIX-1: track per port
                    cvss_val = str(item.cvss_score) if item.cvss_score not in (None, "N/A", "") else "N/A"
                    existing = cve_sources.get(cid)
                    if existing:
                        existing["has_exploit"]        = existing["has_exploit"] or item.has_exploit
                        existing["actively_exploited"] = existing["actively_exploited"] or item.actively_exploited
                        if item.source not in existing["sources"]:
                            existing["sources"].append(item.source)
                    else:
                        cve_sources[cid] = {
                            "cvss":               cvss_val,
                            "sources":            [item.source],
                            "port":               port,
                            "service":            service,
                            "description":        item.description[:300],
                            "url":                f"https://nvd.nist.gov/vuln/detail/{cid}",
                            "has_exploit":        item.has_exploit,
                            "actively_exploited": item.actively_exploited,
                        }
                    texts.append(item.to_rag_text())
                    metas.append({"port": port, "service": service, "cve_id": cid})

                if texts:
                    if vsm.db is None:
                        vsm.initialize_db_with_metadata(texts, metas)
                    else:
                        vsm.add_texts_with_metadata(texts, metas)
                    print(f"    -> {len(texts)} CVEs indexed")

        # RC-5: inject KNOWN_CRITICAL_CVES for ports present in this scan
        injected_total = 0
        for kport, known_list in KNOWN_CRITICAL_CVES.items():
            if "+" in kport:
                continue  # compound keys (e.g. "445+spooler") handled separately
            if kport not in port_cve_index:
                continue  # port not in this scan
            texts, metas = [], []
            for (cid, cvss, desc) in known_list:
                port_cve_index[kport].add(cid)
                if cid not in cve_sources:
                    cve_sources[cid] = {
                        "cvss":               cvss,
                        "sources":            ["known_critical"],
                        "port":               kport,
                        "service":            "windows",
                        "description":        desc,
                        "url":                f"https://nvd.nist.gov/vuln/detail/{cid}",
                        "has_exploit":        True,
                        "actively_exploited": True,
                    }
                rag_text = f"Source: known_critical | ID: {cid} | CVSS: {cvss} | Description: {desc}"
                texts.append(rag_text)
                metas.append({"port": kport, "service": "windows", "cve_id": cid})
                injected_total += 1
            if texts:
                if vsm.db is None:
                    vsm.initialize_db_with_metadata(texts, metas)
                else:
                    vsm.add_texts_with_metadata(texts, metas)
        if injected_total:
            print(f"  [RC-5] Injected {injected_total} known-critical CVEs "
                  f"(EternalBlue/BlueKeep/PrintNightmare)")

        return vsm, cve_sources, port_cve_index

    # ── Phase 1.5: Agentic reflection (FIX-6) ────────────────────────────────

    def _phase15_reflect(self, plan: list, port_cve_index: dict,
                         vsm, cve_sources: dict) -> None:
        """
        FIX-6: LLM reviews coverage, autonomously proposes additional queries,
        then executes them. This is the 'autonomous CVE research' feature.
        """
        print("\n[Phase 1.5] Agentic reflection -- LLM reviewing coverage gaps...")

        coverage = []
        for entry in plan:
            port = str(entry.get("port", "?"))
            coverage.append({
                "port":        port,
                "product":     entry.get("product", entry.get("service", "?")),
                "version":     entry.get("version", ""),
                "cves_found":  len(port_cve_index.get(port, set())),
                "sample_cves": list(port_cve_index.get(port, set()))[:3],
            })

        response = self.llm.invoke(
            REFLECTION_PROMPT.format(coverage_json=json.dumps(coverage, indent=2))
        ).strip()
        print(f"  [llm reflection] {response[:200]}...")

        try:
            m = re.search(r'\[[\s\S]*\]', response)
            additional = json.loads(m.group(0)) if m else []
        except Exception as e:
            print(f"  [1.5] Reflection parse failed ({e}) -- skipping")
            return

        if not additional:
            print("  [1.5] LLM reports coverage is satisfactory.")
            return

        from src.utils.multi_source_api import MultiSourceCVEDownloader
        downloader  = MultiSourceCVEDownloader(nvd_api_key=os.getenv("NVD_API_KEY"))
        added_total = 0

        for req in additional[:5]:
            port    = str(req.get("port", "?"))
            service = req.get("service", "?")
            reason  = req.get("reason", "")
            queries = req.get("queries", [])
            print(f"  [1.5] Port {port} ({service}): {reason}")
            port_cve_index.setdefault(port, set())

            for q in queries[:3]:
                q = q.strip()
                if not q:
                    continue
                print(f"    > [{port}] extra query: {q}")
                entries = downloader.fetch_structured(q, results_per_page=10)
                if not entries:
                    print(f"    -> 0 CVEs")
                    continue
                texts, metas = [], []
                for item in entries:
                    cid = item.id
                    port_cve_index[port].add(cid)
                    if cid not in cve_sources:
                        cve_sources[cid] = {
                            "cvss":               str(item.cvss_score) if item.cvss_score not in (None, "N/A", "") else "N/A",
                            "sources":            [item.source],
                            "port":               port,
                            "service":            service,
                            "description":        item.description[:300],
                            "url":                f"https://nvd.nist.gov/vuln/detail/{cid}",
                            "has_exploit":        item.has_exploit,
                            "actively_exploited": item.actively_exploited,
                        }
                    else:
                        src = cve_sources[cid]
                        src["has_exploit"]        = src["has_exploit"] or item.has_exploit
                        src["actively_exploited"] = src["actively_exploited"] or item.actively_exploited
                        if item.source not in src["sources"]:
                            src["sources"].append(item.source)
                    texts.append(item.to_rag_text())
                    metas.append({"port": port, "service": service, "cve_id": cid})
                if texts:
                    vsm.add_texts_with_metadata(texts, metas)
                    added_total += len(texts)
                    print(f"    -> {len(texts)} additional CVEs indexed")

        print(f"  [1.5] Agentic phase complete -- {added_total} additional CVEs added.")

    # ── Phase 3 ───────────────────────────────────────────────────────────────

    def _phase3_analyse(self, services: list, vsm, cve_sources: dict,
                        port_cve_index: dict) -> list:
        print("\n[Phase 3] LLM grounded analysis per service...")
        findings = []

        for i, svc in enumerate(services, 1):
            port    = str(svc.get("port", "?"))
            service = svc.get("service", "unknown")
            product = svc.get("product") or service
            version = svc.get("version", "n/a")

            print(f"\n  [{i}/{len(services)}] Port {port} ({product} {version})")

            # ── FIX-3: Architectural Critical override ────────────────────────
            if port in ARCH_CRITICAL_OVERRIDES:
                risk_label, analysis_txt, remediation_txt = ARCH_CRITICAL_OVERRIDES[port]
                print(f"    [override FIX-3] -> Critical (architectural risk: {risk_label})")
                findings.append({
                    "port":               port,
                    "service":            f"{product} {version}".strip(),
                    "target":             svc.get("target", ""),
                    "severity":           "Critical",
                    "cvss":               "N/A",
                    "cves":               "None (architectural risk — no CVE identifier)",
                    "cve_refs":           [],
                    "analysis":           f"[{risk_label}] {analysis_txt}",
                    "remediation":        remediation_txt,
                    "has_exploit":        False,
                    "actively_exploited": False,
                })
                print(f"    -> Critical | architectural risk")
                continue

            # Retrieve context
            cve_context = "No CVEs found in NVD for this service."
            if vsm.db is not None:
                try:
                    raw = vsm.search_context_filtered(
                        query=f"{product} {version} vulnerability exploit",
                        port=port, k=5
                    )
                    if raw:
                        cve_context = raw
                except Exception:
                    try:
                        cve_context = vsm.search_context(f"{product} vulnerability", k=5)
                    except Exception:
                        pass

            # RC-5: prepend known_critical CVEs at the TOP of context so the LLM
            # always sees EternalBlue/BlueKeep/etc. regardless of similarity ranking.
            if port in KNOWN_CRITICAL_CVES:
                pinned = []
                for (cid, cvss, desc) in KNOWN_CRITICAL_CVES[port]:
                    pinned.append(
                        f"Source: known_critical | ID: {cid} | CVSS: {cvss} | "
                        f"Description: {desc}"
                    )
                if pinned:
                    pinned_block = "\n".join(pinned)
                    if cve_context.startswith("No CVEs"):
                        cve_context = pinned_block
                    else:
                        cve_context = pinned_block + "\n" + cve_context

            print(f"    [ctx] {cve_context[:100]}...")

            # LLM analysis
            response = self.llm.invoke(
                ANALYSIS_PROMPT.format(
                    product=product, version=version,
                    port=port, service=service, cve_context=cve_context,
                )
            ).strip()
            if self.verbose:
                print(f"    [llm] {response[:200]}...")

            # JSON parser — always takes FIRST valid JSON block (FIX-1 note)
            def _parse_llm_json(resp):
                start = resp.find('{')
                if start == -1:
                    return {}
                chunk = resp[start:]
                # S1: raw_decode stops at end of FIRST complete JSON object
                try:
                    raw, _ = json.JSONDecoder().raw_decode(chunk)
                    result = {k.lower(): v for k, v in raw.items()}
                    if result.get("severity"):
                        return result
                    # first block had no severity — try next '{'
                    nxt = chunk.find('{', 1)
                    if nxt != -1:
                        try:
                            raw2, _ = json.JSONDecoder().raw_decode(chunk[nxt:])
                            r2 = {k.lower(): v for k, v in raw2.items()}
                            if r2.get("severity"):
                                return r2
                        except Exception:
                            pass
                    return result
                except Exception:
                    pass
                # S2: escape raw newlines
                fixed = re.sub(r'"(?:[^"\\]|\\.)*"',
                               lambda m: m.group(0).replace('\n', '\\n'),
                               chunk, flags=re.DOTALL)
                try:
                    raw, _ = json.JSONDecoder().raw_decode(fixed)
                    return {k.lower(): v for k, v in raw.items()}
                except Exception:
                    pass
                # S3: regex fallback
                sm      = re.search(r'"[Ss]everity"\s*:\s*"(\w+)"', resp)
                cve_end = resp.find('"analysis"') if '"analysis"' in resp else len(resp)
                cm      = list(dict.fromkeys(re.findall(r'CVE-\d{4}-\d+', resp[:cve_end])))
                if sm:
                    print(f"    [!] Fallback extracted: severity={sm.group(1)}")
                    return {"severity": sm.group(1), "cves_cited": cm,
                            "analysis": "", "remediation": ""}
                return {}

            analysis = _parse_llm_json(response)
            if not analysis:
                print(f"    [!] All parse strategies failed")

            sev  = analysis.get("severity", "Informational")
            cves = analysis.get("cves_cited", [])

            # Backdoor/bindshell override
            backdoor_kw = ("bindshell", "root shell", "backdoor", "metasploitable")
            if any(kw in (product + " " + service).lower() for kw in backdoor_kw):
                if sev != "Critical":
                    print(f"    [override] {sev} -> Critical (bindshell/root shell)")
                    sev = "Critical"

            # FIX-1 (port-scoped) + RC-2/RC-4 (pass product) + RC-1 (vendor-mismatch)
            port_allowed = port_cve_index.get(port, set())
            product_kw   = product.lower().split()[0] if product else ""  # RC-1: first word e.g. "redis"

            def _vendor_matches(cve_id: str) -> bool:
                """RC-1 (v2): reject CVEs whose NVD description does not mention the product.

                Uses a WORD-BOUNDARY regex so 'redis' does NOT match 'redirect',
                'bacnet' matches 'BACnOPCServer' (case-insensitive prefix trick replaced).

                Empty description → reject.
                CVEs from 'known_critical' source → always accept.
                """
                if not product_kw or len(product_kw) < 4:
                    return True   # too short to check reliably (e.g. "vnc")
                src = cve_sources.get(cve_id, {})
                if src.get("sources") == ["known_critical"]:
                    return True   # always trust our injected CVEs
                desc = src.get("description", "").lower()
                if not desc:
                    return False  # no description → can't verify → reject
                # word-boundary match: 'redis' won't match 'redirect'
                return bool(re.search(r'\b' + re.escape(product_kw) + r'\b', desc))

            verified_cves = [
                c for c in cves
                if c in port_allowed
                and _valid_cve_year(c, version, product)
                and _vendor_matches(c)
            ]
            hallucinated = [c for c in cves if c not in verified_cves]
            if hallucinated:
                print(f"    [!] Removed {len(hallucinated)} CVEs (wrong port/vendor/era): {hallucinated}")
            cves = verified_cves

            # Best CVSS
            best_cvss, best_val = "N/A", 0.0
            for cid in cves:
                try:
                    v = float(cve_sources.get(cid, {}).get("cvss", "N/A"))
                    if v > best_val:
                        best_val, best_cvss = v, str(v)
                except Exception:
                    pass

            # RC-3: Python-level CVSS override — LLM prompt rule alone is unreliable
            if best_val >= 9.0 and sev not in ("Critical",):
                print(f"    [override RC-3] {sev} -> Critical (CVSS {best_val} >= 9.0)")
                sev = "Critical"

            # Build enriched CVE refs (FIX-5: URLs in cve_sources)
            cve_refs, has_exploit, actively_exploited = [], False, False
            for cid in cves:
                src = cve_sources.get(cid, {})
                cve_refs.append({
                    "id":                 cid,
                    "url":                src.get("url", f"https://nvd.nist.gov/vuln/detail/{cid}"),
                    "cvss":               src.get("cvss", "N/A"),
                    "sources":            src.get("sources", []),
                    "has_exploit":        src.get("has_exploit", False),
                    "actively_exploited": src.get("actively_exploited", False),
                })
                has_exploit        = has_exploit or src.get("has_exploit", False)
                actively_exploited = actively_exploited or src.get("actively_exploited", False)

            if has_exploit:
                print(f"    [exploit] public exploit available")
            if actively_exploited:
                print(f"    [KEV] CISA KEV -- actively exploited in the wild!")

            findings.append({
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
            })
            cve_preview = ", ".join(cves[:3]) + ("..." if len(cves) > 3 else "")
            print(f"    -> {sev} | CVEs: {cve_preview or 'None'}")

        return findings

    # ── Entry point ───────────────────────────────────────────────────────────

    def run(self, scan_path: str) -> tuple:
        print(f"[*] Parsing scan file: {scan_path}")
        target, services = self._parse_scan(scan_path)
        print(f"[*] Target: {target} | {len(services)} services found")

        plan = self._phase1_plan(services)
        for svc in services:
            svc["target"] = target

        vsm, cve_sources, port_cve_index = self._phase2_fetch(plan)
        self._phase15_reflect(plan, port_cve_index, vsm, cve_sources)
        findings = self._phase3_analyse(services, vsm, cve_sources, port_cve_index)

        print(f"\n[*] Done -- {len(findings)} findings.")
        return findings, cve_sources, target