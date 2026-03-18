"""
va_agent_react.py — ReAct agent orchestrator.

The LLM is the orchestrator. Python only provides tools and executes them.

Loop:
  Thought     → LLM reasons about what it knows and what it needs
  Action      → LLM picks a tool and provides input
  Observation → Python executes the tool, returns result
  ... repeat until LLM emits FINAL_ANSWER

Architecture:
  toolbox.py      — tool implementations (search_nvd, lookup_cpe, etc.)
  react_parser.py — pure parsing utilities (_parse_all_actions, etc.)
  va_agent_react.py (this file) — LLM loop, prompt, orchestration
"""

import re
import os
import json
from dotenv import load_dotenv

from src.modules.toolbox import ToolBox
from src.modules.react_parser import (
    _parse_react_step,
    _parse_all_actions,
    _sanitize_findings,
)

load_dotenv()

# LLM backend — Ollama (local) or Groq (cloud)
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
if GROQ_API_KEY:
    from langchain_groq import ChatGroq
else:
    from langchain_ollama import OllamaLLM

MAX_STEPS = 40

# ─────────────────────────────────────────────────────────────────────────────
# System prompt
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are an autonomous cybersecurity analyst performing a Vulnerability Assessment.
You have been given the output of an Nmap scan. Your job is to:
  1. Read the scan and identify every service worth investigating
  2. Research vulnerabilities for each service using the tools available to you
  3. When you have enough information, produce a structured final report

You have access to the following tools:

  search_nvd(query)
    Searches the NIST NVD database by keyword. Use for general CVE discovery.
    Example: search_nvd("apache http server 2.2.8")

  lookup_cpe(product, version)
    Finds the canonical CPE string for a product/version, then retrieves
    all CVEs that affect that exact version. More precise than search_nvd.
    Example: lookup_cpe("vsftpd", "2.3.4")

  get_cve(cve_id)
    Returns full details (description, CVSS, references) for a specific CVE.
    Queries both NVD and CIRCL for richer data including EPSS score.
    Example: get_cve("CVE-2011-2523")

  check_kev(keyword)
    Searches the CISA Known Exploited Vulnerabilities catalog.
    Returns CVEs that are actively exploited in the wild.
    Example: check_kev("windows smb")

  search_exploitdb(query)
    Searches Exploit-DB for PUBLIC EXPLOITS matching the query.
    Returns exploit IDs and CVE references. Use when you need to confirm
    whether a working exploit is publicly available.
    Example: search_exploitdb("vsftpd 2.3.4")

  search_osv(query)
    Queries the OSV (Google Open Source Vulnerability) database.
    Excellent for open-source software: Apache, OpenSSH, Samba, MySQL,
    PostgreSQL, ProFTPD. Often finds CVEs that NVD misses for OSS.
    Example: search_osv("samba")

  search_circl(cve_id)
    Queries the CIRCL CVE Search API (Luxembourg/EU NVD mirror).
    Returns CVSS, CWE classification, and vendor references.
    Example: search_circl("CVE-2007-2447")

  search_epss(cve_id)
    Queries the FIRST.org EPSS API for exploitation probability.
    Returns the probability (0-100%) that this CVE will be exploited in the
    next 30 days, and whether that probability is HIGH/MEDIUM/LOW urgency.
    Use this on your most important findings to distinguish theoretically
    severe CVEs from ones that are actively targeted in the wild.
    Example: search_epss("CVE-2021-44228")

FORMAT — strict plain text, no markdown. Do NOT use asterisks, bold, bullet
points, headers, or any other markdown formatting. Every response must follow
this exact structure:

Thought: <your reasoning about what you know and what you need to do next>
Action: <tool_name>
Action Input: <json object with the tool's parameters>

WRONG (do not do this):
**Thought:** I need to check ProFTPD
**Action:** search_nvd
**Action Input:** {"query": "proftpd"}

CORRECT:
Thought: I need to check ProFTPD
Action: search_nvd
Action Input: {"query": "proftpd"}

When you have researched all services and are ready to produce the final report:

Thought: I have researched all services. Ready to produce the final report.
Action: FINAL_ANSWER
Action Input: <structured JSON report — see schema below>

FINAL ANSWER SCHEMA (FORMAT REFERENCE ONLY — DO NOT COPY THESE VALUES):
{
  "findings": [
    {
      "port": "<PORT FROM SCAN>",
      "service": "<SERVICE FROM SCAN>",
      "severity": "<Critical|High|Medium|Low|Informational>",
      "cvss": "<SCORE FROM TOOL RESULTS>",
      "cves": ["<CVE-ID FROM TOOL RESULTS>"],
      "analysis": "<your analysis based on tool observations>",
      "remediation": "<step1> | <step2> | <step3>"
    }
  ]
}

CRITICAL: Your FINAL_ANSWER must contain ONLY the ports present in the scan
you received. Never include ports or services not listed in the scan summary.
Never copy CVE identifiers from this schema — only cite CVEs returned by tools.

SEVERITY RULES — follow the CVSS base score strictly:
- Critical: CVSS >= 9.0  (e.g. unauthenticated RCE, backdoors, CVSS 9.0–10.0)
            ALSO Critical regardless of CVSS: bindshell/root shell, unauthenticated
            protocols (Modbus 502, DNP3 20000, Docker API 2375, Jupyter 8888)
- High:     CVSS 7.0–8.9 (e.g. authentication bypass, privilege escalation)
            ALSO High regardless of CVSS: cleartext credential protocols
            (Telnet, plain FTP, VNC, SNMP v1/v2) — these are High by design
- Medium:   CVSS 4.0–6.9
- Low:      CVSS 0.1–3.9
- Informational: CVSS N/A, no CVEs, no protocol risk

IMPORTANT: A service with CVSS 7.5 is HIGH, not Critical.
           A service with CVSS 5.0 is MEDIUM, not High.
           Never up-grade severity beyond what the CVSS score dictates,
           unless the service falls into an explicit override category above.

IMPORTANT RULES:
- Investigate every open port/service in the scan
- Use lookup_cpe before search_nvd when you know the exact product and version
- For open-source services (Apache, Samba, OpenSSH, MySQL, ProFTPD, vsftpd), also call search_osv — it often finds CVEs NVD misses
- Always check check_kev for any service with a CVE — it may be actively exploited
- When you find a critical or high CVE, also call search_exploitdb to check for public exploits
- For every finding rated Critical or High, you MUST call search_epss(cve_id) on the primary CVE.
  EPSS tells you whether a vulnerability is being actively exploited right now (HIGH urgency = >10% probability).
  This is required — do not skip it for Critical/High findings.
- Use search_circl(cve_id) on your most important findings for CWE classification and additional details
- For Windows services (SMB port 445, RDP port 3389), always check for EternalBlue/BlueKeep class vulnerabilities
- For industrial protocols (Modbus 502, DNP3 20000, EtherNet/IP 44818): these have no CVE but are Critical by design — mark them Critical
- Do not invent CVE IDs. Only cite CVEs you received from a tool call.
- When researching Samba, ignore CVEs that mention "Sambar Server" — Sambar is
  a completely different product. Only cite CVEs that explicitly mention "Samba"
  or "smbd" or "winbind" in their description.
- Produce FINAL_ANSWER only after investigating all services.
"""


# ─────────────────────────────────────────────────────────────────────────────
# VAAgentReAct
# ─────────────────────────────────────────────────────────────────────────────

class VAAgentReAct:
    def __init__(self, model_name: str = "llama3.1:8b", verbose: bool = True):
        groq_key = os.getenv("GROQ_API_KEY")
        if groq_key:
            groq_model = os.getenv("VA_GROQ_MODEL", "llama-3.3-70b-versatile")
            self.llm = ChatGroq(model=groq_model, temperature=0.0, api_key=groq_key)
            print(f"[*] Backend: Groq cloud ({groq_model})")
        else:
            self.llm = OllamaLLM(model=model_name, temperature=0.0)
            print(f"[*] Backend: Ollama local ({model_name})")
        self.verbose = verbose
        self.model   = model_name
        self.toolbox = ToolBox(nvd_api_key=os.getenv("NVD_API_KEY"))

    # ── Parse Nmap XML ─────────────────────────────────────────────────────────

    @staticmethod
    def _normalise_version(version: str) -> str:
        """
        Normalise Nmap version strings before CPE lookup.

        Two patterns are addressed:
        - Range notation:  "12.14 - 12.18"  →  "12.14"   (lower bound)
        - Distro suffix:   "8.2p1 Ubuntu 4ubuntu0.13"  →  "8.2p1"

        These normalised strings are embedded in the scan summary so
        the model uses them when formulating CPE and NVD queries.
        """
        if not version or version.lower() in ("n/a", "unknown", ""):
            return version

        # Range: "X.Y - X.Z"  →  take first token
        range_m = re.match(r'(\S+)\s*-\s*\S+', version)
        if range_m:
            version = range_m.group(1)

        # Distro suffix: keep only the upstream version before the
        # first space that is followed by a capital letter (distro name)
        # e.g. "8.2p1 Ubuntu 4ubuntu0.13"  →  "8.2p1"
        distro_m = re.match(r'(\S+)\s+[A-Z][a-z]', version)
        if distro_m:
            version = distro_m.group(1)

        return version.strip()

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
                raw_ver = f.get("version", "")
                version = self._normalise_version(raw_ver)
                v_str   = f" {version}" if version and version not in ("n/a", "N/A") else ""
                lines.append(f"  Port {port}/tcp  {product}{v_str}")
                if port not in seen:
                    seen.add(port)
                    all_ports.append(port)
        return target, "\n".join(lines), all_ports

    # ── ReAct loop ─────────────────────────────────────────────────────────────

    def _react_loop(self, scan_summary: str, all_ports: list) -> dict:
        """Run the ReAct loop. Returns the parsed FINAL_ANSWER dict."""
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

        # Build prefix → SET of ports (fixes single-overwrite bug for shared
        # services like Samba on 139+445, or mountd on 38641+40255+55567).
        prod_ports: dict[str, set] = {}
        for ln in scan_summary.splitlines():
            m = re.match(r'\s+Port (\d+)/tcp\s+(\S+)', ln)
            if m:
                prefix = m.group(2).lower()[:8]
                prod_ports.setdefault(prefix, set()).add(m.group(1))
        # Alias: smbd / netbios share the same ports as samba
        for alias in ("smbd", "netbios"):
            if alias not in prod_ports and "samba" in prod_ports:
                prod_ports[alias] = prod_ports["samba"]

        history        = [("user", user_message)]
        covered_ports: set = set()
        executed_calls: set = set()   # (tool_name, json_input) deduplication
        consecutive_alldedup: int = 0  # break loop when 8B model is stuck

        print(f"\n[ReAct] Starting agent loop (max {MAX_STEPS} steps)...")
        print(f"[ReAct] Port-product map: { {k: sorted(v) for k,v in prod_ports.items()} }")
        print(f"[ReAct] Scan summary:\n{scan_summary}\n")

        for step in range(1, MAX_STEPS + 1):
            # Compress history to stay within token budget
            KEEP_RECENT = 6
            if len(history) > KEEP_RECENT + 1:
                compressed = []
                for i, (role, text) in enumerate(history):
                    if i == 0:
                        compressed.append((role, text))
                    elif i >= len(history) - KEEP_RECENT:
                        compressed.append((role, text))
                    else:
                        if role == "user" and text.startswith("Observation"):
                            compressed.append((role, text.split("\n")[0][:120] + " [...]"))
                        elif role == "assistant":
                            compressed.append((role, text[:200] + " [...]"))
                        else:
                            compressed.append((role, text[:300]))
                prompt_history = compressed
            else:
                prompt_history = history

            prompt = SYSTEM_PROMPT + "\n\n"
            for role, text in prompt_history:
                prefix = "USER" if role == "user" else "ASSISTANT"
                prompt += f"{prefix}:\n{text}\n\n"
            prompt += "ASSISTANT:\n"

            raw      = self.llm.invoke(prompt)
            response = (raw.content if hasattr(raw, "content") else raw).strip()
            history.append(("assistant", response))

            print(f"\n--- Step {step} ---")
            if self.verbose:
                print(response[:500] + ("..." if len(response) > 500 else ""))

            thought, action, action_input, final_json = _parse_react_step(response)
            all_actions = _parse_all_actions(response)

            if thought:
                print(f"  Thought: {thought[:150]}")

            # ── FINAL_ANSWER ───────────────────────────────────────────────────
            if action == "FINAL_ANSWER":
                if not final_json:
                    # JSON was truncated or unparseable — ask for clean resubmission
                    history.append(("user",
                        f"Your FINAL_ANSWER JSON was incomplete or malformed and could not be parsed.\n"
                        f"Please resubmit the complete FINAL_ANSWER in a single response.\n"
                        f"Your scan has ONLY these ports: {', '.join(all_ports)}\n"
                        f"Use this flat schema:\n{simple_schema}"
                    ))
                    print(f"  [!] FINAL_ANSWER JSON unparseable — requesting clean resubmission")
                    continue
                # Validate against scan ports — reject hallucinated ports
                reported = {str(f.get("port","")) for f in final_json.get("findings",[])}
                hallucinated = [p for p in reported if p not in all_ports]
                if hallucinated:
                    history.append(("user",
                        f"FINAL_ANSWER rejected: it contains ports not present in the scan: "
                        f"{', '.join(hallucinated)}.\n"
                        f"Your scan contains ONLY these ports: {', '.join(all_ports)}.\n"
                        f"Remove those entries and resubmit with ONLY the actual scan ports."
                    ))
                    print(f"  [!] Hallucinated ports detected {hallucinated} — rejecting FINAL_ANSWER")
                    continue
                missing = [p for p in all_ports if p not in reported]
                if missing:
                    history.append(("user",
                        f"FINAL_ANSWER accepted but incomplete. "
                        f"Add findings for these ports too: {', '.join(missing)}.\n"
                        f"For each missing port, add a finding even if no CVEs were found "
                        f"(use severity Informational or High for protocol risks).\n"
                        f"Resubmit the complete FINAL_ANSWER with ALL {len(all_ports)} ports."
                    ))
                    print(f"  [!] Premature FINAL_ANSWER — missing {missing}, pushing back")
                    continue
                print(f"\n[ReAct] FINAL_ANSWER accepted after {step} steps.")
                return final_json

            # ── Tool calls ─────────────────────────────────────────────────────
            KNOWN_TOOLS = {
                "search_nvd", "lookup_cpe", "get_cve", "check_kev",
                "search_exploitdb", "search_osv", "search_circl", "search_epss",
            }
            executed_any = False
            observations = []

            for act, act_input in all_actions:
                if act == "FINAL_ANSWER":
                    continue
                if act not in KNOWN_TOOLS:
                    print(f"  [!] Unknown tool '{act}' — skipped")
                    continue
                if act_input is None:
                    print(f"  [!] No valid input for '{act}' — skipped")
                    continue

                print(f"  Action: {act}")
                inp_lower = json.dumps(act_input).lower()

                # Deduplication: skip identical tool+input pairs already executed
                call_key = (act, json.dumps(act_input, sort_keys=True))
                if call_key in executed_calls:
                    print(f"  [dedup] Skipping duplicate call: {act}({act_input})")
                    executed_any = True   # don't trigger nudge
                    continue
                executed_calls.add(call_key)

                # Coverage: mark ALL ports sharing this service prefix as covered
                for prefix, ports in prod_ports.items():
                    if prefix in inp_lower:
                        covered_ports.update(ports)
                # Special aliases
                if "telnet" in inp_lower:
                    covered_ports.update(p for p in all_ports if p == "23")
                if any(k in inp_lower for k in ("bindshell","metasploit","root shell","1524")):
                    covered_ports.update(p for p in all_ports if p == "1524")
                # Samba: if either 139 or 445 is researched, cover both
                if any(k in inp_lower for k in ("samba", "smbd", "netbios")):
                    for p in all_ports:
                        if p in ("139", "445"):
                            covered_ports.add(p)
                # mountd: cover all mountd ports when any mountd query is made
                if "mountd" in inp_lower or "mount" in inp_lower:
                    covered_ports.update(prod_ports.get("mountd", set()))

                obs       = self.toolbox.execute(act, act_input)
                obs_short = obs if len(obs) <= 300 else obs[:300] + " [truncated]"
                observations.append(f"Observation ({act}): {obs_short}")
                print(f"  Obs: {obs[:200]}...")
                executed_any = True

            uncovered = [p for p in all_ports if p not in covered_ports]

            if executed_any:
                if not observations:  # all calls were deduped
                    consecutive_alldedup += 1
                else:
                    consecutive_alldedup = 0
                combined = "\n".join(observations)
                if len(combined) > 3500:
                    kept     = observations[:1] + observations[-7:]
                    combined = "[Earlier observations omitted for brevity]\n" + "\n".join(kept)
                # If model is stuck in all-dedup loop, force immediate FINAL_ANSWER
                if consecutive_alldedup >= 2 and not uncovered:
                    print(f"  [!] Stuck in dedup loop ({consecutive_alldedup}x) — forcing FINAL_ANSWER extraction")
                    force_msg = (
                        f"STOP. All ports have been researched. You MUST emit FINAL_ANSWER now. "
                        f"Your scan has ONLY these ports: {', '.join(all_ports)}. "
                        f"Emit the complete FINAL_ANSWER JSON immediately. No more tool calls. "
                        f"{simple_schema}"
                    )
                    history.append(("user", force_msg))
                    consecutive_alldedup = 0
                    continue
                combined += (
                    f"\n\n[System] Ports still needing research: {', '.join(uncovered)}"
                    if uncovered else
                    f"\n\n[System] All ports researched. "
                    f"Emit FINAL_ANSWER using the flat schema:\n{simple_schema}"
                )
                history.append(("user", combined))
                print(f"  [Coverage] covered={sorted(covered_ports)} | remaining={uncovered}")
            else:
                if action and action not in KNOWN_TOOLS and action != "FINAL_ANSWER":
                    nudge = (
                        f"'{action}' is not an available tool.\n"
                        f"Available tools ONLY: search_nvd, lookup_cpe, get_cve, "
                        f"check_kev, search_exploitdb, search_osv, search_circl\n\n"
                        f"Ports still needing research: "
                        f"{', '.join(uncovered) if uncovered else 'NONE — emit FINAL_ANSWER'}\n"
                        f"Example:\nThought: I need to research Apache httpd 2.2.8\n"
                        f"Action: lookup_cpe\n"
                        f'Action Input: {{"product": "apache", "version": "2.2.8"}}'
                    )
                elif uncovered:
                    nudge = (
                        f"Use the ReAct format. Ports not yet researched: {', '.join(uncovered)}\n"
                        f"Example:\nThought: I need to research port {uncovered[0]}\n"
                        f"Action: search_nvd\n"
                        f'Action Input: {{"query": "<product> <version>"}}\n'
                        f"Available tools: search_nvd, lookup_cpe, get_cve, "
                        f"check_kev, search_exploitdb, search_epss"
                    )
                else:
                    nudge = (
                        f"All ports researched. Emit FINAL_ANSWER now.\n"
                        f"Your scan contains EXACTLY these ports: {', '.join(all_ports)}\n"
                        f"Include ONLY these ports in your findings. "
                        f"Do NOT add ports not listed above.\n"
                        f"Use this flat schema (no cve_details):\n{simple_schema}"
                    )
                history.append(("user", nudge))
                print(f"  [!] No valid action — nudging. Uncovered: {uncovered}")
                consecutive_alldedup = 0

        print(f"[ReAct] Max steps ({MAX_STEPS}) reached.")
        return self._extract_partial_answer(history)

    def _extract_partial_answer(self, history: list) -> dict:
        """Fallback if the loop times out."""
        for role, text in reversed(history):
            if role == "assistant" and "FINAL_ANSWER" in text:
                _, _, _, final = _parse_react_step(text)
                if final:
                    return final
        print("[ReAct] Building fallback report from tool cache...")
        return {"findings": [
            {
                "port":        meta.get("port", "unknown"),
                "service":     meta.get("service", "unknown"),
                "severity":    "High",
                "cvss":        str(meta.get("cvss", "N/A")),
                "cves":        [cve_id],
                "analysis":    f"Found via tool call: {meta.get('description','')[:200]}",
                "remediation": "Review and patch.",
            }
            for cve_id, meta in self.toolbox._cve_cache.items()
        ]}

    # ── Entry point ────────────────────────────────────────────────────────────

    def run(self, scan_path: str) -> tuple[list, dict, str]:
        """Returns (findings, cve_sources, target)."""
        print(f"[*] Parsing scan: {scan_path}")
        target, scan_summary, all_ports = self._parse_scan(scan_path)
        print(f"[*] Target: {target} | {len(all_ports)} services: {all_ports}")

        final        = self._react_loop(scan_summary, all_ports)
        raw_findings = final.get("findings", [])
        print(f"\n[*] Raw findings from LLM: {len(raw_findings)}")

        findings = _sanitize_findings(raw_findings, self.toolbox)

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

        # ── Enforce CVSS→severity mapping (Python safety net) ─────────────
        def _enforce_severity(sev: str, cvss_raw) -> str:
            """Correct LLM severity based on CVSS score; preserve protocol overrides."""
            protocol_critical = {"bindshell", "root shell", "modbus", "dnp3",
                                 "docker api", "jupyter"}
            protocol_high     = {"telnet", "ftp", "vnc", "snmp v1", "snmp v2"}

            # Don't downgrade explicit protocol overrides
            sev_lower = sev.lower()
            if any(k in sev_lower for k in protocol_critical):
                return "Critical"

            try:
                score = float(str(cvss_raw).replace(",", "."))
            except (ValueError, TypeError):
                return sev  # keep LLM value if no numeric CVSS

            if score >= 9.0:  return "Critical"
            if score >= 7.0:  return "High"
            if score >= 4.0:  return "Medium"
            if score >  0.0:  return "Low"
            return "Informational"

        normalised = []
        for f in findings:
            cve_ids  = f.get("cves", [])
            cve_refs = [
                {
                    "id":                 cid,
                    "url":                f.get("cve_details", {}).get(cid, {}).get(
                                              "url", f"https://nvd.nist.gov/vuln/detail/{cid}"),
                    "cvss":               f.get("cve_details", {}).get(cid, {}).get("cvss", "N/A"),
                    "sources":            [f.get("cve_details", {}).get(cid, {}).get("source", "nvd")],
                    "has_exploit":        f.get("cve_details", {}).get(cid, {}).get("has_exploit", False),
                    "actively_exploited": f.get("cve_details", {}).get(cid, {}).get("actively_exploited", False),
                }
                for cid in cve_ids
            ]
            normalised.append({
                "port":               str(f.get("port", "?")),
                "service":            f.get("service", "unknown"),
                "target":             target,
                "severity":           _enforce_severity(
                                          f.get("severity", "Informational"),
                                          f.get("cvss", "N/A")
                                      ),
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