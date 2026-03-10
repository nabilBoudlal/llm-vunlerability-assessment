"""
CVE Research Agent  (v3 — Grounded Autonomous Research)
---------------------------------------------------------
Stage 1 — Deterministic CPE retrieval  (version-accurate candidates)
Stage 2 — LLM autonomous evaluation    (filters candidates, proposes extra queries)
Stage 3 — Deterministic execution      (runs LLM-proposed extra queries)
"""

import json
import re
import time

from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate


_NOISE_SERVICES = {
    "tcpwrapped", "unknown", "bindshell", "status",
    "nlockmgr", "mountd", "rpcbind", "exec", "login",
}

# Prefixes the LLM sometimes adds to queries — strip them before querying NVD
_QUERY_STRIP_PREFIXES = ("search ", "query ", "lookup ", "find ")


def _clean_query(q):
    """Remove any natural-language prefix the LLM added to a search query."""
    q = q.strip()
    lower = q.lower()
    for prefix in _QUERY_STRIP_PREFIXES:
        if lower.startswith(prefix):
            q = q[len(prefix):]
            break
    return q.strip()


class CVEResearchAgent:
    def __init__(self, nvd_downloader, model_name="llama3:8b"):
        self.downloader = nvd_downloader
        self.llm = OllamaLLM(model=model_name, temperature=0.0)

    # ------------------------------------------------------------------
    # Stage 1 — CPE-based candidate retrieval
    # ------------------------------------------------------------------

    def _fetch_cpe_candidates(self, hosts_data, api_key_present=False):
        candidates     = []
        seen_cpes      = set()

        for host in hosts_data:
            for finding in host.get("findings", []):
                s_name = finding.get("service", "unknown").lower()
                if any(n in s_name for n in _NOISE_SERVICES):
                    continue

                for cpe_obj in finding.get("cpe_list", []):
                    raw = cpe_obj.get("raw", "")
                    if not raw or raw in seen_cpes:
                        continue
                    seen_cpes.add(raw)

                    # Inject the human-readable product name so Tier 3
                    # keyword fallback uses "Apache httpd" not "http_server"
                    enriched_cpe = dict(cpe_obj)
                    enriched_cpe["product_name"] = finding.get("product", "")

                    print(f"    > [Stage-1] CPE: {raw}")
                    entries = self.downloader.fetch_by_cpe(enriched_cpe)
                    candidates.extend(entries)

                    time.sleep(2 if api_key_present else 8)

        print(f"[*] Stage 1 complete: {len(candidates)} CVE candidates.")
        return candidates

    # ------------------------------------------------------------------
    # Stage 2 — LLM autonomous evaluation
    # ------------------------------------------------------------------

    def _build_findings_summary(self, hosts_data):
        lines = []
        for host in hosts_data:
            ip = host.get("target", "unknown")
            for f in host.get("findings", []):
                svc  = f.get("service", "unknown")
                prod = f.get("product", "")
                ver  = f.get("version", "n/a")
                port = f.get("port", "unk")
                cve  = f.get("cve", "N/A")
                cpes = ", ".join(c["raw"] for c in f.get("cpe_list", []))

                if any(n in svc.lower() for n in _NOISE_SERVICES):
                    continue

                line = f"[{ip}] Port {port}: {prod or svc} {ver}"
                if cpes:
                    line += f"  CPE: {cpes}"
                if cve and cve != "N/A":
                    line += f"  (scanner CVE: {cve})"
                lines.append(line)
        return "\n".join(lines)

    def _build_candidates_summary(self, candidates):
        lines = []
        for c in candidates[:60]:
            lines.append(
                f"  {c['id']} | CVSS {c.get('cvss_score','N/A')} | "
                f"{c['keyword']} | {c['description'][:120]}..."
            )
        return "\n".join(lines) if lines else "  (none retrieved)"

    def _llm_evaluate_and_extend(self, hosts_data, candidates):
        """
        Ask the LLM to:
          a) Filter candidates to only genuinely relevant CVEs.
          b) Propose additional NVD keyword queries for any gaps.
        """
        findings_text   = self._build_findings_summary(hosts_data)
        candidates_text = self._build_candidates_summary(candidates)

        template = """\
[SYSTEM]: You are a senior cybersecurity analyst performing an autonomous \
Vulnerability Assessment following NIST SP 800-115.

[SCAN FINDINGS]:
{findings}

[CVE CANDIDATES PRE-FETCHED FOR THESE SERVICES]:
{candidates}

[YOUR TASKS]:

TASK A — Relevance Filtering
Select only the CVE IDs that are genuinely relevant to the exact service \
versions detected. Exclude CVEs targeting a different OS or a version range \
that clearly does not include the detected version.

TASK B — Gap Detection
Identify services with no useful candidates or important vulnerability classes \
you know are missing. For each gap, propose ONE precise NVD keyword search query.
The query must be a plain search string (e.g. "Apache httpd 2.4.41 path traversal") \
— do NOT add the word "search" or any other prefix.

[OUTPUT — return ONLY valid JSON, no prose, no markdown fences]:
{{
  "relevant_cve_ids": ["CVE-XXXX-YYYY", ...],
  "additional_queries": [
    {{"service": "service name", "reason": "short reason", "query": "plain search string"}}
  ]
}}
"""
        prompt = PromptTemplate(
            input_variables=["findings", "candidates"], template=template
        )
        raw = (prompt | self.llm).invoke({
            "findings":   findings_text,
            "candidates": candidates_text,
        })

        try:
            match = re.search(r"\{.*\}", raw, re.DOTALL)
            if match:
                return json.loads(match.group())
        except Exception as e:
            print(f"[!] LLM evaluation parse failed: {e}")
            print(f"    Raw snippet: {raw[:300]}")

        # Fallback: accept all candidates, no extra queries
        return {
            "relevant_cve_ids":   [c["id"] for c in candidates],
            "additional_queries": [],
        }

    # ------------------------------------------------------------------
    # Stage 3 — Execute LLM-requested extra queries
    # ------------------------------------------------------------------

    def _execute_additional_queries(self, queries, api_key_present=False):
        texts      = []
        references = {}
        seen_q     = set()
        sleep_time = 6 if api_key_present else 30

        for item in queries:
            q      = _clean_query(item.get("query", ""))
            reason = item.get("reason", "")
            if not q or q.lower() in seen_q:
                continue
            if any(n in q.lower() for n in _NOISE_SERVICES):
                continue
            seen_q.add(q.lower())

            print(f"    > [Stage-3] '{q}'  — {reason}")
            for e in self.downloader.fetch_structured(q):
                texts.append(e["text"])
                references[e["id"]] = e["url"]

            time.sleep(sleep_time)

        return texts, references

    # ------------------------------------------------------------------
    # Main entry-point
    # ------------------------------------------------------------------

    def research(self, hosts_data, api_key_present=False):
        """
        Returns
        -------
        all_cve_texts : list[str]   — for ChromaDB
        cve_references : dict       — CVE_ID -> NVD URL for the report
        """
        print("\n[*] CVEResearchAgent — Stage 1: CPE candidate retrieval")
        candidates = self._fetch_cpe_candidates(hosts_data, api_key_present)

        print("\n[*] CVEResearchAgent — Stage 2: LLM autonomous evaluation")
        evaluation         = self._llm_evaluate_and_extend(hosts_data, candidates)
        relevant_ids       = set(evaluation.get("relevant_cve_ids", []))
        additional_queries = evaluation.get("additional_queries", [])

        print(f"    LLM: {len(relevant_ids)} relevant CVEs selected, "
              f"{len(additional_queries)} extra queries proposed.")

        selected = [c for c in candidates if c["id"] in relevant_ids] if relevant_ids else candidates

        print("\n[*] CVEResearchAgent — Stage 3: executing LLM-proposed queries")
        extra_texts, extra_refs = self._execute_additional_queries(
            additional_queries, api_key_present
        )

        # Merge — CPE results overwrite keyword results on ID collision
        all_texts  = [c["text"] for c in selected] + extra_texts
        references = {**extra_refs, **{c["id"]: c["url"] for c in selected}}

        print(
            f"\n[+] Research complete: {len(all_texts)} entries, "
            f"{len(references)} unique CVE IDs  "
            f"[CPE-selected: {len(selected)} | LLM-extra: {len(extra_texts)}]"
        )
        return all_texts, references