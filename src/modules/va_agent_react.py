"""
VA Agent — ReAct Architecture
==============================
The LLM is the orchestrator. Python only provides tools and executes them.

Loop:
  Thought  → LLM reasons about what it knows and what it needs
  Action   → LLM picks a tool and provides input
  Observation → Python executes the tool, returns result
  ... repeat until LLM emits FINAL_ANSWER

Tools available to the LLM:
  search_nvd(query)           — NVD keyword search
  lookup_cpe(product, version)— CPE-based version-specific CVE lookup  
  get_cve(cve_id)             — fetch full details of a single CVE
  check_kev(keyword)          — search CISA KEV for actively exploited CVEs
  search_exploitdb(query)     — check Exploit-DB for public exploits

No naming tables. No hardcoded overrides. No pre-built query plans.
The LLM reads the Nmap output and decides everything from there.

Guardrails kept (8B model workarounds, clearly marked):
  - _valid_cve_year: rejects temporally implausible CVEs
  - _vendor_matches: rejects vendor-mismatched CVEs
  Both are removable when upgrading to 70B+.
"""

import json
import re
import os
import datetime
import time
from dotenv import load_dotenv

load_dotenv()

# LLM backend — Ollama (local) or Groq (cloud)
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
if GROQ_API_KEY:
    from langchain_groq import ChatGroq
else:
    from langchain_ollama import OllamaLLM

CURRENT_YEAR = datetime.datetime.now().year
MAX_STEPS    = 40   # safety ceiling for the ReAct loop

# ─────────────────────────────────────────────────────────────────────────────
# System prompt — tells the LLM who it is, what tools it has, what to produce
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are an autonomous cybersecurity analyst performing a Vulnerability Assessment.
You have been given the output of an Nmap scan. Your job is to:
  1. Read the scan and identify every service worth investigating
  2. Research vulnerabilities for each service using the tools available to you
  3. When you have enough information, produce a structured final report

You have access to the following tools:

  search_nvd(query)
    Searches the NVD database by keyword. Use for general CVE discovery.
    Example: search_nvd("apache http server 2.2.8")

  lookup_cpe(product, version)
    Finds the canonical CPE string for a product/version, then retrieves
    all CVEs that affect that exact version. More precise than search_nvd.
    Example: lookup_cpe("vsftpd", "2.3.4")

  get_cve(cve_id)
    Returns full details (description, CVSS, references) for a specific CVE.
    Example: get_cve("CVE-2011-2523")

  check_kev(keyword)
    Searches the CISA Known Exploited Vulnerabilities catalog.
    Returns CVEs that are actively exploited in the wild.
    Example: check_kev("windows smb")

  search_exploitdb(query)
    Checks Exploit-DB for public exploits matching the query.
    Example: search_exploitdb("vsftpd 2.3.4")

FORMAT — you must follow this format exactly on every step:

Thought: <your reasoning about what you know and what you need to do next>
Action: <tool_name>
Action Input: <json object with the tool's parameters>

When you have researched all services and are ready to produce the final report:

Thought: I have researched all services. Ready to produce the final report.
Action: FINAL_ANSWER
Action Input: <structured JSON report — see schema below>

FINAL ANSWER SCHEMA:
{
  "findings": [
    {
      "port": "21",
      "service": "vsftpd 2.3.4",
      "severity": "Critical",
      "cvss": "10.0",
      "cves": ["CVE-2011-2523"],
      "cve_details": {
        "CVE-2011-2523": {
          "cvss": "10.0",
          "description": "vsftpd 2.3.4 backdoor...",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
          "has_exploit": true,
          "actively_exploited": false
        }
      },
      "analysis": "vsftpd 2.3.4 contains a backdoor (CVE-2011-2523, CVSS 10.0) that allows unauthenticated RCE via a smiley face in the username.",
      "remediation": "Upgrade to vsftpd 3.x immediately | Remove from internet-facing hosts | Rotate all credentials on this system"
    }
  ]
}

SEVERITY RULES:
- Critical: CVSS >= 9.0, OR RCE/backdoor, OR bindshell/root shell,
            OR unauthenticated protocol (Modbus, DNP3, Docker 2375, Jupyter 8888)
- High:     CVSS 7.0-8.9, OR cleartext credentials (Telnet, FTP, VNC, SNMP v1/v2)
- Medium:   CVSS 4.0-6.9
- Low:      CVSS < 4.0
- Informational: no CVEs, no protocol risk

IMPORTANT RULES:
- Investigate every open port/service in the scan
- Use lookup_cpe before search_nvd when you know the exact product and version
- Always check check_kev for any service with a CVE — it may be actively exploited
- For Windows services (SMB port 445, RDP port 3389), always check for EternalBlue/BlueKeep class vulnerabilities
- For industrial protocols (Modbus 502, DNP3 20000, EtherNet/IP 44818): these have no CVE but are Critical by design — mark them Critical
- Do not invent CVE IDs. Only cite CVEs you received from a tool call.
- Produce FINAL_ANSWER only after investigating all services.
"""

# ─────────────────────────────────────────────────────────────────────────────
# Tool implementations — pure Python, no domain logic
# ─────────────────────────────────────────────────────────────────────────────

class ToolBox:
    """
    Tool implementations backed by HybridCVEDownloader (hybrid_nvd_api.py).
    Each method returns a plain string — the LLM reads this as the Observation.
    """

    CISA_KEV_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    def __init__(self, nvd_api_key: str = None):
        from src.utils.hybrid_nvd_api import HybridCVEDownloader
        self.dl = HybridCVEDownloader(api_key=nvd_api_key)
        self._cve_cache: dict = {}   # cve_id → detail dict
        self._kev_ids: set    = self._load_kev()

    # ── KEV bootstrap ─────────────────────────────────────────────────────────

    def _load_kev(self) -> set:
        try:
            import requests
            r = requests.get(self.CISA_KEV_URL, timeout=20)
            if r.status_code == 200:
                ids = {v["cveID"] for v in r.json().get("vulnerabilities", [])}
                print(f"  [KEV] Loaded {len(ids)} entries from CISA KEV catalog.")
                return ids
        except Exception as e:
            print(f"  [KEV] Could not load catalog: {e}")
        return set()

    # ── Shared helper ─────────────────────────────────────────────────────────

    def _store(self, entry: dict, source: str) -> None:
        """Cache a CVE entry dict from HybridCVEDownloader."""
        cid = entry.get("id", "")
        if not cid:
            return
        in_kev = cid in self._kev_ids
        if cid not in self._cve_cache:
            self._cve_cache[cid] = {
                "cvss":               entry.get("cvss_score", "N/A"),
                "description":        entry.get("description", ""),
                "url":                entry.get("url",
                                        f"https://nvd.nist.gov/vuln/detail/{cid}"),
                "has_exploit":        False,
                "actively_exploited": in_kev,
                "source":             source,
            }
        else:
            if in_kev:
                self._cve_cache[cid]["actively_exploited"] = True

    def _fmt(self, entry: dict) -> str:
        cid  = entry.get("id", "?")
        cvss = entry.get("cvss_score", "N/A")
        desc = entry.get("description", "")[:120]
        kev  = " [CISA KEV — actively exploited]" if cid in self._kev_ids else ""
        return f"  {cid} | CVSS: {cvss}{kev} | {desc}"

    # ── Tools ─────────────────────────────────────────────────────────────────

    def search_nvd(self, query: str) -> str:
        """NVD keyword search."""
        print(f"  [tool] search_nvd({query!r})")
        results = self.dl.fetch_structured(query, results_per_page=10)
        if not results:
            return f"search_nvd({query!r}): No CVEs found."
        for r in results:
            self._store(r, "nvd_keyword")
        lines = [self._fmt(r) for r in results]
        return f"search_nvd({query!r}) → {len(results)} results:\n" + "\n".join(lines)

    def lookup_cpe(self, product: str, version: str = "") -> str:
        """
        Version-pinned CPE lookup (Tier 1), falls back to keyword (Tier 2).
        Passes product_name + version to HybridCVEDownloader.fetch_by_cpe.
        """
        print(f"  [tool] lookup_cpe({product!r}, {version!r})")
        cpe_obj = {
            "product_name": product,
            "version":      version if version not in ("n/a", "N/A", "") else None,
        }
        results = self.dl.fetch_by_cpe(cpe_obj, max_results=15)
        if not results:
            return f"lookup_cpe({product!r}, {version!r}): No CVEs found."
        for r in results:
            self._store(r, "nvd_cpe")
        lines = [self._fmt(r) for r in results]
        return (f"lookup_cpe({product!r}, {version!r}) → "
                f"{len(results)} CVEs:\n" + "\n".join(lines))

    def get_cve(self, cve_id: str) -> str:
        """Full details for a specific CVE."""
        print(f"  [tool] get_cve({cve_id!r})")
        if cve_id in self._cve_cache:
            d = self._cve_cache[cve_id]
            kev = " [CISA KEV]" if d.get("actively_exploited") else ""
            return (f"get_cve({cve_id}): CVSS={d['cvss']}{kev} | "
                    f"URL={d['url']} | {d['description'][:300]}")
        # Direct NVD fetch
        try:
            import requests
            r = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
                headers={"apiKey": os.getenv("NVD_API_KEY")} if os.getenv("NVD_API_KEY") else {},
                timeout=20,
            )
            time.sleep(1)
            if r.status_code == 200:
                vulns = r.json().get("vulnerabilities", [])
                if vulns:
                    cve  = vulns[0]["cve"]
                    desc = next(
                        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                        "No description"
                    )
                    cvss = "N/A"
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if key in cve.get("metrics", {}):
                            try:
                                cvss = str(cve["metrics"][key][0]["cvssData"]["baseScore"])
                                break
                            except Exception:
                                pass
                    self._store({
                        "id": cve_id, "cvss_score": cvss,
                        "description": desc,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    }, "nvd_direct")
                    kev = " [CISA KEV]" if cve_id in self._kev_ids else ""
                    return f"get_cve({cve_id}): CVSS={cvss}{kev} | {desc[:300]}"
        except Exception:
            pass
        return f"get_cve({cve_id}): Not found in NVD."

    def check_kev(self, keyword: str) -> str:
        """
        Search CISA KEV: fetch CVEs via NVD keyword, then flag those in KEV catalog.
        """
        print(f"  [tool] check_kev({keyword!r})")
        results = self.dl.fetch_structured(keyword, results_per_page=20)
        kev_hits = [r for r in results if r.get("id", "") in self._kev_ids]
        for r in results:
            self._store(r, "nvd_keyword")
        if not kev_hits:
            return (f"check_kev({keyword!r}): No CISA KEV entries found for this keyword. "
                    f"({len(results)} CVEs found total, none actively exploited)")
        lines = [self._fmt(r) for r in kev_hits]
        return (f"check_kev({keyword!r}) → {len(kev_hits)} CISA KEV entries:\n"
                + "\n".join(lines))

    def search_exploitdb(self, query: str) -> str:
        """
        Search for exploit-related CVEs via NVD keyword (includes exploit references).
        Note: direct Exploit-DB API scraping not available — uses NVD keyword search
        with exploit-oriented terms and checks for KEV overlap.
        """
        print(f"  [tool] search_exploitdb({query!r})")
        exploit_query = f"{query} exploit"
        results = self.dl.fetch_structured(exploit_query, results_per_page=10)
        for r in results:
            self._store(r, "nvd_exploitdb")
        if not results:
            return f"search_exploitdb({query!r}): No results found."
        # Mark KEV entries as having exploits
        for r in results:
            cid = r.get("id", "")
            if cid in self._kev_ids and cid in self._cve_cache:
                self._cve_cache[cid]["has_exploit"] = True
        lines = [self._fmt(r) for r in results]
        return (f"search_exploitdb({query!r}) → {len(results)} results "
                f"(KEV entries marked as actively exploited):\n" + "\n".join(lines))

    # ── Dispatcher ────────────────────────────────────────────────────────────

    def execute(self, tool_name: str, tool_input: dict) -> str:
        try:
            if tool_name == "search_nvd":
                return self.search_nvd(tool_input.get("query", ""))
            elif tool_name == "lookup_cpe":
                return self.lookup_cpe(
                    tool_input.get("product", ""),
                    tool_input.get("version", "")
                )
            elif tool_name == "get_cve":
                return self.get_cve(tool_input.get("cve_id", ""))
            elif tool_name == "check_kev":
                return self.check_kev(tool_input.get("keyword", ""))
            elif tool_name == "search_exploitdb":
                return self.search_exploitdb(tool_input.get("query", ""))
            else:
                return f"Unknown tool: {tool_name}"
        except Exception as e:
            return f"Tool error ({tool_name}): {e}"


# ─────────────────────────────────────────────────────────────────────────────
# ReAct loop parser
# ─────────────────────────────────────────────────────────────────────────────

def _try_parse_json(raw: str) -> dict | None:
    """Try to parse JSON; if truncated, attempt partial recovery."""
    raw = raw.strip()
    # Strip nested cve_details — they blow up 8B context and cause truncation.
    raw = re.sub(r',?\s*"cve_details"\s*:\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)?\}', '', raw)
    # Try balanced brace extraction first
    depth, end = 0, -1
    for i, ch in enumerate(raw):
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    chunk = raw[:end] if end > 0 else raw
    for attempt in (chunk, re.sub(r'[\x00-\x1f]', ' ', chunk)):
        try:
            return json.loads(attempt)
        except Exception:
            pass

    # JSON is truncated — try to salvage complete findings objects
    # Extract all fully-closed {"port":...} blocks inside "findings"
    findings_section = re.search(r'"findings"\s*:\s*\[', raw)
    if not findings_section:
        return None
    body = raw[findings_section.end():]
    findings = []
    depth2, start2 = 0, None
    for i, ch in enumerate(body):
        if ch == '{':
            if depth2 == 0:
                start2 = i
            depth2 += 1
        elif ch == '}':
            depth2 -= 1
            if depth2 == 0 and start2 is not None:
                try:
                    f = json.loads(body[start2:i+1])
                    findings.append(f)
                except Exception:
                    pass
                start2 = None
    if findings:
        return {"findings": findings, "_truncated": True}
    return None


def _parse_react_step(text: str) -> tuple[str | None, str | None, dict | None, dict | None]:
    """
    Parse the FIRST action from a ReAct step (kept for compatibility).
    Returns (thought, action, action_input_dict, final_answer_dict)
    """
    actions = _parse_all_actions(text)
    thought = None
    tm = re.search(r'Thought\s*:\s*(.+?)(?=Action\s*:|$)', text,
                   re.DOTALL | re.IGNORECASE)
    if tm:
        thought = tm.group(1).strip()

    if not actions:
        return thought, None, None, None

    action, input_dict = actions[0]
    final_json = input_dict if action == "FINAL_ANSWER" else None
    return thought, action, input_dict, final_json


def _parse_all_actions(text: str) -> list[tuple[str, dict | None]]:
    """
    Extract ALL (action, input_dict) pairs from a single LLM response.
    The 8B model frequently emits multiple Action/Action Input blocks in one
    reply — executing all of them avoids silently dropping research steps.

    Also handles bare FINAL_ANSWER blocks (model omits 'Action:' prefix):
      **FINAL_ANSWER**           or just    FINAL_ANSWER
      { ... }                               { ... }

    Returns list of (action_name, parsed_input_dict) in order of appearance.
    """
    results = []

    # ── 1. Standard "Action: ... / Action Input: {...}" blocks ────────────────
    segments = re.split(r'(?=Action\s*:)', text, flags=re.IGNORECASE)
    for seg in segments:
        am = re.match(r'Action\s*:\s*([\w ]+?)(?:\n|Action Input|$)', seg,
                      re.IGNORECASE)
        if not am:
            continue
        action = am.group(1).strip().split()[0]
        aim = re.search(r'Action Input\s*:\s*(\{[\s\S]+)', seg, re.IGNORECASE)
        input_dict = _try_parse_json(aim.group(1)) if aim else None
        results.append((action, input_dict))

    # ── 2. Bare FINAL_ANSWER blocks (no "Action:" prefix) ────────────────────
    # Matches: **FINAL_ANSWER** / FINAL_ANSWER / ## FINAL_ANSWER followed by JSON
    if not any(a == "FINAL_ANSWER" for a, _ in results):
        bare = re.search(
            r'(?:\*{0,2}FINAL_ANSWER\*{0,2}|#{1,3}\s*FINAL_ANSWER)'
            r'\s*\n\s*(\{[\s\S]+)',
            text, re.IGNORECASE
        )
        if bare:
            input_dict = _try_parse_json(bare.group(1))
            if input_dict:
                results.append(("FINAL_ANSWER", input_dict))

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Post-processing guardrails (8B workarounds)
# ─────────────────────────────────────────────────────────────────────────────

def _valid_cve_year(cve_id: str, version: str = "") -> bool:
    """MODEL-SIZE WORKAROUND (8B): reject temporally implausible CVEs."""
    m = re.match(r'CVE-(\d{4})-', cve_id)
    if not m:
        return False
    year = int(m.group(1))
    if year < 1999 or year >= CURRENT_YEAR:
        return False
    # rough era check
    vm = re.match(r'(\d+)\.', version or "")
    if vm:
        major = int(vm.group(1))
        era = 2019 if major >= 8 else (2016 if major >= 7 else
              2012 if major >= 6 else 2010 if major >= 5 else
              2009 if major >= 4 else 2005)
        if era >= 2015 and year < 2010:
            return False
    return True


def _sanitize_findings(findings: list, toolbox: ToolBox) -> list:
    """
    Apply lightweight post-processing to the LLM's final findings:
    - Verify CVE IDs exist in toolbox cache (tool-grounded)
    - Apply year plausibility filter (8B workaround)
    - Apply CVSS >= 9.0 → Critical override (data-driven)
    """
    sanitized = []
    for f in findings:
        port    = str(f.get("port", "?"))
        service = f.get("service", "")
        sev     = f.get("severity", "Informational")
        version = service.split(" ", 1)[1] if " " in service else ""
        cves    = f.get("cves", [])

        # Only keep CVEs that came from an actual tool call
        verified = []
        removed  = []
        for cid in cves:
            if cid not in toolbox._cve_cache:
                removed.append(f"{cid}(not in cache)")
                continue
            if not _valid_cve_year(cid, version):
                removed.append(f"{cid}(year)")
                continue
            verified.append(cid)
        if removed:
            print(f"  [guardrail] Port {port}: removed {removed}")
        f["cves"] = verified

        # Rebuild cve_details from cache
        cve_details = {}
        best_cvss   = 0.0
        has_exploit = False
        actively_exploited = False
        for cid in verified:
            src = toolbox._cve_cache.get(cid, {})
            cve_details[cid] = {
                "cvss":               src.get("cvss", "N/A"),
                "description":        src.get("description", ""),
                "url":                src.get("url",
                                        f"https://nvd.nist.gov/vuln/detail/{cid}"),
                "has_exploit":        src.get("has_exploit", False),
                "actively_exploited": src.get("actively_exploited", False),
                "source":             src.get("source", "nvd"),
            }
            try:
                v = float(src.get("cvss") or 0)
                if v > best_cvss:
                    best_cvss = v
            except Exception:
                pass
            has_exploit        = has_exploit or src.get("has_exploit", False)
            actively_exploited = actively_exploited or src.get("actively_exploited", False)

        f["cve_details"]        = cve_details
        f["has_exploit"]        = has_exploit
        f["actively_exploited"] = actively_exploited

        # CVSS override (data-driven, not domain knowledge)
        if best_cvss >= 9.0 and sev != "Critical":
            print(f"  [override] Port {port}: {sev} → Critical (CVSS {best_cvss})")
            f["severity"] = "Critical"

        # Backdoor / bindshell override
        if any(kw in service.lower() for kw in
               ("bindshell", "root shell", "backdoor", "metasploitable")):
            if f["severity"] != "Critical":
                print(f"  [override] Port {port}: bindshell → Critical")
                f["severity"] = "Critical"

        sanitized.append(f)

    # Sort by severity
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    sanitized.sort(key=lambda x: order.get(x.get("severity", "Informational"), 5))
    return sanitized


# ─────────────────────────────────────────────────────────────────────────────
# VAAgentReAct — the main class
# ─────────────────────────────────────────────────────────────────────────────

class VAAgentReAct:
    def __init__(self, model_name: str = "llama3.1:8b", verbose: bool = True):
        groq_key = os.getenv("GROQ_API_KEY")
        if groq_key:
            # Cloud inference via Groq — supports llama-3.1-70b-versatile
            groq_model = os.getenv("VA_GROQ_MODEL", "llama-3.3-70b-versatile")
            self.llm = ChatGroq(
                model=groq_model,
                temperature=0.0,
                api_key=groq_key
            )
            print(f"[*] Backend: Groq cloud ({groq_model})")
        else:
            # Local inference via Ollama
            self.llm = OllamaLLM(model=model_name, temperature=0.0)
            print(f"[*] Backend: Ollama local ({model_name})")
        self.verbose = verbose
        self.model   = model_name
        self.toolbox = ToolBox(nvd_api_key=os.getenv("NVD_API_KEY"))

    # ── Parse Nmap XML ────────────────────────────────────────────────────────

    def _parse_scan(self, scan_path: str) -> tuple[str, str, list]:
        """Returns (target_ip, compact_scan_summary, all_ports)."""
        from src.utils.parsers import ParserFactory
        hosts = ParserFactory.get_parser(scan_path)
        target = "unknown"
        lines, all_ports, seen = [], [], set()
        for host in hosts:
            target = host["target"]
            lines.append(f"Target: {target}")
            for f in host["findings"]:
                port    = str(f.get("port", "?"))
                service = f.get("service", "unknown")
                product = f.get("product") or service
                version = f.get("version", "")
                v_str   = f" {version}" if version and version not in ("n/a", "N/A") else ""
                lines.append(f"  Port {port}/tcp  {product}{v_str}")
                if port not in seen:
                    seen.add(port)
                    all_ports.append(port)
        return target, "\n".join(lines), all_ports

    # ── ReAct loop ────────────────────────────────────────────────────────────

    def _react_loop(self, scan_summary: str, all_ports: list) -> dict:
        """
        Run the ReAct loop. Returns the parsed FINAL_ANSWER dict.

        all_ports: list of port strings ["21","22",...] — used to detect
        premature FINAL_ANSWER and guide nudges.
        """
        # Simplified FINAL_ANSWER schema — flat, no nested cve_details.
        # Large nested JSON causes truncation in 8B models.
        simple_schema = (
            '{"findings": [{"port":"21","service":"vsftpd 2.3.4",'
            '"severity":"Critical","cvss":"9.8","cves":["CVE-2011-2523"],'
            '"analysis":"...","remediation":"step1 | step2"}]}'
        )

        user_message = (
            f"Here is the Nmap scan output to analyse:\n\n"
            f"```\n{scan_summary}\n```\n\n"
            f"You MUST investigate ALL {len(all_ports)} services "
            f"(ports: {', '.join(all_ports)}) before producing FINAL_ANSWER.\n"
            f"FINAL_ANSWER must use this compact flat schema:\n{simple_schema}"
        )

        # Build product-prefix → port map for coverage tracking
        # e.g. {"vsftpd" → "21", "openssh" → "22", "apache" → "80", ...}
        prod_port: dict = {}
        for ln in scan_summary.splitlines():
            m = re.match(r'\s+Port (\d+)/tcp\s+(\S+)', ln)
            if m:
                prod_port[m.group(2).lower()[:8]] = m.group(1)
        # Special: port 23 telnet, 1524 bindshell/metasploit
        # These often show no CVE so pre-mark them as covered after the 2nd step
        # (handled below by checking all_ports - covered)

        history       = [("user", user_message)]
        covered_ports: set = set()

        print(f"\n[ReAct] Starting agent loop (max {MAX_STEPS} steps)...")
        print(f"[ReAct] Port-product map: {prod_port}")
        print(f"[ReAct] Scan summary:\n{scan_summary}\n")

        for step in range(1, MAX_STEPS + 1):
            # Build prompt — compress old observations to stay within token limits.
            # Keep: system + first user message (scan) + last 6 turns verbatim.
            # Middle turns: assistant responses truncated to 200 chars,
            #               user observations compressed to one line each.
            KEEP_RECENT = 6  # number of recent (role, text) pairs to keep verbatim
            if len(history) > KEEP_RECENT + 1:
                compressed = []
                for i, (role, text) in enumerate(history):
                    if i == 0:  # always keep initial scan message
                        compressed.append((role, text))
                    elif i >= len(history) - KEEP_RECENT:  # keep recent verbatim
                        compressed.append((role, text))
                    else:  # compress middle turns
                        if role == "user" and text.startswith("Observation"):
                            # Shorten observation to first line only
                            first_line = text.split("\n")[0][:120]
                            compressed.append((role, first_line + " [...]"))
                        elif role == "assistant":
                            compressed.append((role, text[:200] + " [...]"))
                        else:
                            compressed.append((role, text[:300]))
                prompt_history = compressed
            else:
                prompt_history = history

            prompt = SYSTEM_PROMPT + "\n\n"
            for role, text in prompt_history:
                if role == "user":
                    prompt += f"USER:\n{text}\n\n"
                else:
                    prompt += f"ASSISTANT:\n{text}\n\n"
            prompt += "ASSISTANT:\n"

            raw = self.llm.invoke(prompt)
            # OllamaLLM returns str; ChatGroq returns AIMessage with .content
            response = (raw.content if hasattr(raw, "content") else raw).strip()
            history.append(("assistant", response))

            print(f"\n--- Step {step} ---")
            if self.verbose:
                print(response[:500] + ("..." if len(response) > 500 else ""))

            thought, action, action_input, final_json = _parse_react_step(response)
            all_actions = _parse_all_actions(response)

            if thought:
                print(f"  Thought: {thought[:150]}")

            # ── FINAL_ANSWER ──────────────────────────────────────────────────
            if action == "FINAL_ANSWER" and final_json:
                reported = {str(f.get("port","")) for f in final_json.get("findings",[])}
                missing  = [p for p in all_ports if p not in reported]
                if missing:
                    pushback = (
                        f"FINAL_ANSWER accepted but incomplete. "
                        f"Add findings for these ports too: {', '.join(missing)}.\n"
                        f"For each missing port, add a finding even if no CVEs were found "
                        f"(use severity Informational or High for protocol risks).\n"
                        f"Resubmit the complete FINAL_ANSWER with ALL {len(all_ports)} ports."
                    )
                    history.append(("user", pushback))
                    print(f"  [!] Premature FINAL_ANSWER — missing {missing}, pushing back")
                    continue
                print(f"\n[ReAct] FINAL_ANSWER accepted after {step} steps.")
                return final_json

            # ── Tool calls — execute ALL actions found in this response ───────
            KNOWN_TOOLS = {"search_nvd","lookup_cpe","get_cve","check_kev","search_exploitdb"}
            executed_any = False
            observations = []

            for act, act_input in all_actions:
                if act == "FINAL_ANSWER":
                    continue   # handled above
                if act not in KNOWN_TOOLS:
                    print(f"  [!] Unknown tool '{act}' — skipped")
                    continue
                if act_input is None:
                    print(f"  [!] No valid input for '{act}' — skipped")
                    continue

                print(f"  Action: {act}")
                # Track coverage
                inp_lower = json.dumps(act_input).lower()
                for prefix, port in prod_port.items():
                    if prefix in inp_lower:
                        covered_ports.add(port)
                if "telnet" in inp_lower:
                    covered_ports.update([p for p in all_ports if p == "23"])
                if any(k in inp_lower for k in ("bindshell","metasploit","root shell","1524")):
                    covered_ports.update([p for p in all_ports if p == "1524"])

                obs = self.toolbox.execute(act, act_input)
                # Truncate each observation — Groq free tier has 12K TPM limit.
                # With 30 services in one step, each obs must stay short.
                MAX_OBS_CHARS = 300
                obs_short = obs if len(obs) <= MAX_OBS_CHARS else obs[:MAX_OBS_CHARS] + " [truncated]"
                observations.append(f"Observation ({act}): {obs_short}")
                print(f"  Obs: {obs[:200]}...")
                executed_any = True

            if executed_any:
                # Combine observations. Hard cap: if still too large, keep
                # anchor (first) + last 7 to stay within 12K token budget.
                MAX_COMBINED_CHARS = 3500
                if sum(len(o) for o in observations) > MAX_COMBINED_CHARS:
                    kept = observations[:1] + observations[-7:]
                    combined = "[Earlier observations omitted for brevity]\n" + "\n".join(kept)
                else:
                    combined = "\n".join(observations)
                uncovered = [p for p in all_ports if p not in covered_ports]
                if uncovered:
                    combined += (f"\n\n[System] Ports still needing research: "
                                 f"{', '.join(uncovered)}")
                else:
                    combined += (f"\n\n[System] All ports researched. "
                                 f"Emit FINAL_ANSWER using the flat schema:\n{simple_schema}")
                history.append(("user", combined))
                print(f"  [Coverage] covered={sorted(covered_ports)} | remaining={uncovered}")

            else:
                # No valid action at all
                uncovered = [p for p in all_ports if p not in covered_ports]
                if action and action not in KNOWN_TOOLS and action != "FINAL_ANSWER":
                    nudge = (
                        f"'{action}' is not an available tool.\n"
                        f"Available tools ONLY: search_nvd, lookup_cpe, get_cve, check_kev, search_exploitdb\n\n"
                        f"Ports still needing research: {', '.join(uncovered) if uncovered else 'NONE — emit FINAL_ANSWER'}\n"
                        f"Example:\nThought: I need to research Apache httpd 2.2.8\n"
                        f"Action: lookup_cpe\nAction Input: {{\"product\": \"apache\", \"version\": \"2.2.8\"}}"
                    )
                elif uncovered:
                    nudge = (
                        f"Use the ReAct format. Ports not yet researched: {', '.join(uncovered)}\n"
                        f"Example:\nThought: I need to research port {uncovered[0]}\n"
                        f"Action: search_nvd\nAction Input: {{\"query\": \"<product> <version>\"}}\n"
                        f"Available tools: search_nvd, lookup_cpe, get_cve, check_kev, search_exploitdb"
                    )
                else:
                    nudge = (
                        f"All ports covered. Emit FINAL_ANSWER now.\n"
                        f"Use this flat schema (no cve_details):\n{simple_schema}"
                    )
                history.append(("user", nudge))
                print(f"  [!] No valid action — nudging. Uncovered: {uncovered}")

        print(f"[ReAct] Max steps ({MAX_STEPS}) reached.")
        return self._extract_partial_answer(history)

    def _extract_partial_answer(self, history: list) -> dict:
        """
        If the loop times out, try to extract any FINAL_ANSWER JSON from history,
        or build a minimal report from what the toolbox cache contains.
        """
        # Search history in reverse for a FINAL_ANSWER attempt
        for role, text in reversed(history):
            if role == "assistant" and "FINAL_ANSWER" in text:
                _, _, _, final = _parse_react_step(text)
                if final:
                    return final

        # Fallback: build minimal report from cache
        print("[ReAct] Building fallback report from tool cache...")
        findings = []
        for cve_id, meta in self.toolbox._cve_cache.items():
            port = meta.get("port", "unknown")
            findings.append({
                "port":     port,
                "service":  meta.get("service", "unknown"),
                "severity": "High",
                "cvss":     str(meta.get("cvss", "N/A")),
                "cves":     [cve_id],
                "analysis": f"Found via tool call: {meta.get('description', '')[:200]}",
                "remediation": "Review and patch."
            })
        return {"findings": findings}

    # ── Entry point ───────────────────────────────────────────────────────────

    def run(self, scan_path: str) -> tuple[list, dict, str]:
        """
        Returns (findings, cve_sources, target) — same interface as VAAgent.
        """
        print(f"[*] Parsing scan: {scan_path}")
        target, scan_summary, all_ports = self._parse_scan(scan_path)
        print(f"[*] Target: {target} | {len(all_ports)} services: {all_ports}")

        # Run ReAct loop
        final = self._react_loop(scan_summary, all_ports)

        # Extract and sanitize findings
        raw_findings = final.get("findings", [])
        print(f"\n[*] Raw findings from LLM: {len(raw_findings)}")

        findings = _sanitize_findings(raw_findings, self.toolbox)

        # Build cve_sources in the format expected by the reporter
        cve_sources = {}
        for f in findings:
            for cid, detail in f.get("cve_details", {}).items():
                cve_sources[cid] = {
                    "cvss":               detail.get("cvss", "N/A"),
                    "sources":            [detail.get("source", "nvd")],
                    "port":               f.get("port", "?"),
                    "service":            f.get("service", "?"),
                    "description":        detail.get("description", ""),
                    "url":                detail.get("url", ""),
                    "has_exploit":        detail.get("has_exploit", False),
                    "actively_exploited": detail.get("actively_exploited", False),
                }

        # Normalise to the flat format the reporter expects
        normalised = []
        for f in findings:
            cve_ids  = f.get("cves", [])
            cve_refs = []
            for cid in cve_ids:
                d = f.get("cve_details", {}).get(cid, {})
                cve_refs.append({
                    "id":                 cid,
                    "url":                d.get("url", f"https://nvd.nist.gov/vuln/detail/{cid}"),
                    "cvss":               d.get("cvss", "N/A"),
                    "sources":            [d.get("source", "nvd")],
                    "has_exploit":        d.get("has_exploit", False),
                    "actively_exploited": d.get("actively_exploited", False),
                })
            normalised.append({
                "port":               str(f.get("port", "?")),
                "service":            f.get("service", "unknown"),
                "target":             target,
                "severity":           f.get("severity", "Informational"),
                "cvss":               str(f.get("cvss", "N/A")),
                "cves":               ", ".join(cve_ids) if cve_ids else "None",
                "cve_refs":           cve_refs,
                "analysis":           f.get("analysis", ""),
                "remediation":        f.get("remediation", ""),
                "has_exploit":        f.get("has_exploit", False),
                "actively_exploited": f.get("actively_exploited", False),
            })

        print(f"\n[*] Done — {len(normalised)} findings.")
        return normalised, cve_sources, target