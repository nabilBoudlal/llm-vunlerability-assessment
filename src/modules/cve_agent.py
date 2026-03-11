"""
CVE Research Agent — 3-Stage autonomous pipeline.

Stage 1: Deterministic multi-source retrieval (NVD + OSV + Exploit-DB)
Stage 2: LLM filters candidates and proposes additional queries
Stage 3: Execute LLM-proposed extra queries across all sources

cve_sources return format: {CVE_ID: {"source": str, "cvss": str, "exploit": bool}}
"""
import json
import re
from langchain_ollama import OllamaLLM

from src.utils.multi_source_api import MultiSourceCVEDownloader, CVEEntry


class CVEResearchAgent:

    def __init__(self, downloader: MultiSourceCVEDownloader,
                 model_name: str = "qwen3:8b"):
        self.downloader = downloader
        self.llm        = OllamaLLM(model=model_name, temperature=0.0, verbose=False)

    def research(self, hosts_data: list) -> tuple[list[str], dict]:
        """
        Returns:
          rag_texts  : list of strings ready for ChromaDB
          cve_sources: dict {CVE_ID -> {"source": str, "cvss": str, "exploit": bool}}
        """
        # ── Stage 1 ────────────────────────────────────────────────────
        print("[*] CVEResearchAgent — Stage 1: multi-source CPE retrieval")
        stage1_entries: dict[str, CVEEntry] = {}

        unique_cpes = {}
        unique_kws  = set()

        for host in hosts_data:
            for finding in host["findings"]:
                for cpe in finding.get("cpe_list", []):
                    raw = cpe.get("raw", "")
                    if raw and raw not in unique_cpes:
                        cpe_enriched = dict(cpe)
                        cpe_enriched.setdefault(
                            "human_product",
                            f"{finding.get('product', '')} {finding.get('version', '')}".strip()
                        )
                        unique_cpes[raw] = cpe_enriched

                if not finding.get("cpe_list"):
                    product = finding.get("product", finding.get("service", ""))
                    version = finding.get("version", "")
                    if product and product.lower() not in ("unknown", ""):
                        unique_kws.add(f"{product} {version}".strip())

        for raw, cpe_obj in unique_cpes.items():
            print(f"    > [Stage-1] CPE: {raw}")
            entries = self.downloader.fetch_by_cpe(cpe_obj)
            for e in entries:
                if e.id not in stage1_entries:
                    stage1_entries[e.id] = e
                elif e.has_exploit:
                    stage1_entries[e.id].has_exploit = True
            print(f"              → {len(stage1_entries)} total unique CVEs so far")

        for kw in unique_kws:
            print(f"    > [Stage-1] KW fallback: {kw}")
            entries = self.downloader.fetch_structured(kw)
            for e in entries:
                if e.id not in stage1_entries:
                    stage1_entries[e.id] = e
            print(f"              → {len(stage1_entries)} total unique CVEs so far")

        print(f"[*] Stage 1 complete: {len(stage1_entries)} CVE candidates.")

        # ── Stage 2 ────────────────────────────────────────────────────
        print("[*] CVEResearchAgent — Stage 2: LLM autonomous evaluation")
        stage1_summary = self._build_summary(hosts_data, stage1_entries)
        llm_result     = self._llm_evaluate(stage1_summary)

        relevant_ids  = set(llm_result.get("relevant_cve_ids", []))
        extra_queries = llm_result.get("additional_queries", [])

        if stage1_entries and len(relevant_ids) < max(4, len(stage1_entries) * 0.3):
            print(f"    [!] LLM kept only {len(relevant_ids)}/{len(stage1_entries)} CVEs "
                  f"— safety net: keeping all Stage 1 entries.")
            relevant_ids = set(stage1_entries.keys())

        print(f"    LLM: {len(relevant_ids)} relevant CVEs selected, "
              f"{len(extra_queries)} extra queries proposed.")

        # ── Stage 3 ────────────────────────────────────────────────────
        print("[*] CVEResearchAgent — Stage 3: executing LLM-proposed queries")
        stage3_entries: dict[str, CVEEntry] = {}
        for raw_q in extra_queries:
            query = self._clean_query(raw_q)
            if not query:
                continue
            print(f"    > [Stage-3] '{query}'")
            entries = self.downloader.fetch_structured(query)
            for e in entries:
                if e.id not in stage1_entries and e.id not in stage3_entries:
                    stage3_entries[e.id] = e

        # ── Merge ──────────────────────────────────────────────────────
        all_entries: dict[str, CVEEntry] = {**stage3_entries, **stage1_entries}
        final_entries: dict[str, CVEEntry] = {
            cve_id: entry
            for cve_id, entry in all_entries.items()
            if cve_id in relevant_ids or cve_id in stage3_entries
        }

        exploit_count = sum(1 for e in final_entries.values() if e.has_exploit)
        print(
            f"[+] Research complete: {len(final_entries)} entries  "
            f"[CPE-selected: {len(stage1_entries)} | "
            f"LLM-extra: {len(stage3_entries)} | "
            f"With public exploit: {exploit_count}]"
        )

        rag_texts = [e.to_rag_text() for e in final_entries.values()]

        # Enriched sources dict — includes CVSS and exploit flag for the reporter
        cve_sources = {
            e.id: {
                "source":  "exploitdb" if e.has_exploit else e.source,
                "cvss":    e.cvss_score,
                "exploit": e.has_exploit,
            }
            for e in final_entries.values()
        }

        return rag_texts, cve_sources

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _build_summary(self, hosts_data: list,
                       candidates: dict[str, CVEEntry]) -> str:
        findings_lines = []
        for host in hosts_data:
            for f in host["findings"]:
                svc = f.get("service", "unknown")
                ver = f.get("version", "n/a")
                prt = f.get("port", "?")
                prd = f.get("product", "")
                findings_lines.append(f"  port {prt}: {prd or svc} {ver}".rstrip())

        cve_lines = []
        for e in list(candidates.values())[:60]:
            exploit_tag = " [PUBLIC EXPLOIT]" if e.has_exploit else ""
            cvss_tag    = f" CVSS:{e.cvss_score}" if e.cvss_score != "N/A" else ""
            cve_lines.append(
                f"  [{e.source.upper()}{exploit_tag}{cvss_tag}] {e.id}: "
                f"{e.description[:120]}"
            )

        return (
            "SCAN FINDINGS:\n" + "\n".join(findings_lines) +
            "\n\nCVE CANDIDATES:\n" + "\n".join(cve_lines)
        )

    def _llm_evaluate(self, summary: str) -> dict:
        prompt = f"""
You are a cybersecurity expert evaluating CVE relevance for a Linux vulnerability assessment.

{summary}

TASK A — Filter CVEs:
Keep a CVE if ANY of these conditions are met:
  1. The CVE description mentions the same product name as a scan finding.
  2. The CVE describes a vulnerability type plausible for that service version.
  3. The CVE is marked [PUBLIC EXPLOIT] — ALWAYS keep these.
Remove a CVE ONLY if it clearly targets a different OS (e.g. Windows-only)
or an entirely unrelated product. When in doubt, KEEP the CVE.

TASK B — Gap queries:
Identify 1-3 vulnerability classes NOT covered by the candidates above.
Write SHORT, simple keyword queries (3-6 words max, NO boolean operators,
NO AND/OR/NOT, NO parentheses, NO CVE IDs in the query).
Example good queries: "OpenSSH 8.2 authentication bypass", "Samba remote code execution"

Respond ONLY with valid JSON, no explanation, no markdown fences:
{{
  "relevant_cve_ids": ["CVE-XXXX-XXXXX", ...],
  "additional_queries": ["short query 1", "short query 2"]
}}
"""
        raw = self.llm.invoke(prompt)
        return self._parse_json(raw)

    @staticmethod
    def _parse_json(raw: str) -> dict:
        try:
            clean = re.sub(r"```(?:json)?|```", "", raw).strip()
            start = clean.find("{")
            end   = clean.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(clean[start:end])
        except Exception:
            pass
        return {"relevant_cve_ids": [], "additional_queries": []}

    @staticmethod
    def _clean_query(raw: str) -> str:
        prefixes = [
            "search for ", "search ", "query for ", "query: ",
            "keyword: ", "look up ", "find ", "investigate ",
        ]
        q = raw.strip().strip('"').strip("'")
        for p in prefixes:
            if q.lower().startswith(p):
                q = q[len(p):]
        q = re.sub(r'\b(AND|OR|NOT)\b', '', q)
        q = re.sub(r'[()"\']', '', q)
        q = re.sub(r'\s+', ' ', q).strip()
        if re.match(r'^CVE-\d{4}-\d+$', q):
            return ""
        return q