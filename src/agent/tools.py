"""
Tool definitions for the LLM-driven VA Agent.
"""
import json
from langchain.tools import tool

_downloader    = None
_vsm           = None
_policies      = []
_findings_store: list = []
_cve_sources:   dict  = {}


def init_tools(parser_mod, downloader_obj, vsm_obj, policies_list):
    global _parser, _downloader, _vsm, _policies
    _parser     = parser_mod
    _downloader = downloader_obj
    _vsm        = vsm_obj
    _policies   = policies_list


@tool
def read_scan_file(file_path: str) -> str:
    """Parse a Nmap XML or Nessus CSV scan file. Returns JSON with hosts and open ports."""
    try:
        from src.utils.parsers import ParserFactory
        hosts = ParserFactory.get_parser(file_path)
        summary = []
        for host in hosts:
            services, seen = [], set()
            for f in host["findings"]:
                port = str(f.get("port", "?"))
                if port in seen:
                    continue
                seen.add(port)
                services.append({
                    "port":    port,
                    "service": f.get("service", "unknown"),
                    "product": f.get("product", ""),
                    "version": f.get("version", "n/a"),
                })
            summary.append({"target": host["target"], "services": services})
        return json.dumps(summary, indent=2)
    except Exception as e:
        return f"ERROR: {e}"


@tool
def search_cve(query: str) -> str:
    """Search NVD for CVEs related to a product. Input: 'product version' e.g. 'vsftpd 2.3.4'."""
    global _cve_sources
    import re as _re
    # Clean query: remove OS suffixes like "Debian 8ubuntu1", "Ubuntu", quotes
    query = query.strip().strip("'\"")
    query = _re.sub(r'\b(Debian|Ubuntu|debian|ubuntu|linux|Linux)\s*[\w.+-]*', '', query).strip()
    # Also remove trailing "n/a" or "N/A"
    query = _re.sub(r'\bn/?a\b', '', query, flags=_re.IGNORECASE).strip()
    if not query:
        return "No CVEs found."
    try:
        raw = _downloader.fetch_by_keyword(query, results_per_page=10)
        if not raw:
            return "No CVEs found."

        results = []
        rag_texts = []

        for item in raw:
            # Handle both CVEEntry objects and plain strings
            if isinstance(item, str):
                # legacy string format: "Source: X | ID: CVE-... | Description: ..."
                import re
                cve_id = re.search(r'ID:\s*(CVE-[\d-]+)', item)
                if cve_id:
                    cid = cve_id.group(1)
                    _cve_sources[cid] = {"source": query, "cvss": "N/A", "exploit": False}
                    results.append({"id": cid, "cvss": "N/A", "has_exploit": False,
                                    "description": item[:200]})
                rag_texts.append(item)
            else:
                # CVEEntry object
                cid = item.id
                cvss = str(item.cvss_score) if item.cvss_score else "N/A"
                _cve_sources[cid] = {"source": item.source, "cvss": cvss,
                                     "exploit": item.has_exploit}
                results.append({"id": cid, "cvss": cvss, "has_exploit": item.has_exploit,
                                 "description": item.description[:200]})
                rag_texts.append(item.to_rag_text() if hasattr(item, 'to_rag_text')
                                 else str(item))

        # Index in vector store
        if rag_texts and _vsm is not None:
            try:
                if _vsm.db is None:
                    _vsm.initialize_db(rag_texts)
                else:
                    _vsm.db.add_texts(rag_texts)
            except Exception:
                pass

        return json.dumps(results, indent=2) if results else "No CVEs found."
    except Exception as e:
        return f"ERROR: {e}"


@tool
def check_policy(service_name: str) -> str:
    """Check if a service violates organizational security policy. Input: service name e.g. 'ftp'."""
    alerts = []
    sname  = service_name.lower().strip()
    for p in _policies:
        if any(sname == svc.lower() for svc in p.get("services", [])):
            alerts.append(
                f"POLICY_ALERT: {p['category']} | Service: {sname} "
                f"| Risk: {p['risk']} | {p['description']}"
            )
    return "\n".join(alerts) if alerts else "No policy violations found."


@tool
def retrieve_context(query: str) -> str:
    """Retrieve CVE context from the local vector database. Input: search query string."""
    try:
        if _vsm is None or _vsm.db is None:
            return "No CVE context available yet."
        return _vsm.search_context(query, k=5)
    except Exception as e:
        return f"ERROR: {e}"


@tool
def save_finding(finding_json: str) -> str:
    """Save the analysis for one service. Input: JSON with port, service, severity, cves, analysis, remediation, policy_violation."""
    try:
        # Try to extract JSON even if LLM adds trailing text
        import re
        m = re.search(r'\{.*\}', finding_json, re.S)
        if m:
            finding = json.loads(m.group(0))
        else:
            finding = json.loads(finding_json)
        _findings_store.append(finding)
        return f"OK: finding saved for port {finding.get('port')}. Total: {len(_findings_store)}"
    except Exception as e:
        return f"ERROR: {e} — make sure input is valid JSON"


@tool
def get_all_findings() -> str:
    """Return all findings saved so far."""
    return json.dumps(_findings_store, indent=2) if _findings_store else "No findings yet."