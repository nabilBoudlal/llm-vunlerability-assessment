"""
Multi-Source CVE Downloader
Queries NVD, OSV (Google), and Exploit-DB and merges results.
Each CVEEntry now carries cvss_score extracted from the NVD metrics block.
"""
import requests
from dataclasses import dataclass, field


@dataclass
class CVEEntry:
    id:          str
    description: str
    source:      str           # "nvd" | "osv" | "exploitdb"
    cvss_score:  str = "N/A"  # base score from NVD (e.g. "9.8")
    has_exploit: bool = False  # True if found in Exploit-DB

    def to_rag_text(self) -> str:
        exploit_flag = " [PUBLIC EXPLOIT AVAILABLE]" if self.has_exploit else ""
        return (
            f"Source: {self.source}{exploit_flag} | "
            f"ID: {self.id} | "
            f"CVSS: {self.cvss_score} | "
            f"Description: {self.description}"
        )


def _extract_cvss(metrics: dict) -> str:
    """Try CVSSv3.1, CVSSv3.0, CVSSv2 in order — return first valid base score."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            try:
                return str(metrics[key][0]["cvssData"]["baseScore"])
            except (KeyError, IndexError):
                pass
    return "N/A"


class MultiSourceCVEDownloader:
    """
    Aggregates CVE data from NVD, OSV, and Exploit-DB.
    Deduplicated by CVE ID; Exploit-DB hits set has_exploit=True.
    CVSS score is extracted from NVD metrics when available.
    """

    def __init__(self, nvd_api_key: str = None):
        self.nvd_api_key = nvd_api_key
        self.nvd_base    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.nvd_headers = {"apiKey": nvd_api_key} if nvd_api_key else {}
        self.osv_base    = "https://api.osv.dev/v1/query"
        self.edb_base    = "https://www.exploit-db.com/search"

    # ------------------------------------------------------------------ #
    # Public interface                                                     #
    # ------------------------------------------------------------------ #

    def fetch_by_cpe(self, cpe_obj: dict, results_per_page: int = 20) -> list:
        cpe23         = cpe_obj.get("cpe23", "")
        product       = cpe_obj.get("product", "")
        version       = cpe_obj.get("version", "")
        human_product = cpe_obj.get("human_product", "")

        entries: dict[str, CVEEntry] = {}

        # Tier 1 — NVD CPE (version-pinned)
        if cpe23:
            print(f"    [Tier-1 NVD-CPE] {cpe23}")
            nvd = self._nvd_cpe(cpe23, results_per_page)
            for e in nvd:
                entries[e.id] = e
            print(f"              → {len(nvd)} CVEs from NVD-CPE")

        # Tier 2 — NVD keyword fallback
        kw_product = human_product if human_product else product
        if not entries and kw_product:
            kw = f"{kw_product} {version}".strip()
            for placeholder in (" None", " n/a", " N/A", " unknown"):
                kw = kw.replace(placeholder, "")
            kw = kw.strip()
            print(f"    [Tier-2 NVD-KW]  '{kw}'  (Tier 1 empty — fallback)")
            nvd_kw = self._nvd_keyword(kw, results_per_page)
            for e in nvd_kw:
                entries[e.id] = e
            print(f"              → {len(nvd_kw)} CVEs from NVD-KW fallback")

        # Tier 3 — OSV
        if product:
            osv = self._osv_keyword(product, version)
            new = 0
            for e in osv:
                if e.id not in entries:
                    entries[e.id] = e
                    new += 1
            if new:
                print(f"    [OSV]  +{new} new CVEs from OSV")

        # Tier 4 — Exploit-DB (marks has_exploit)
        if product:
            kw = f"{product} {version}".strip()
            exploit_ids = self._exploitdb_search(kw)
            marked = 0
            for cve_id in exploit_ids:
                if cve_id in entries:
                    entries[cve_id].has_exploit = True
                    marked += 1
            if exploit_ids:
                print(f"    [Exploit-DB]  {len(exploit_ids)} exploits found"
                      f" ({marked} matched existing CVEs)")

        return list(entries.values())

    def fetch_by_keyword(self, keyword: str, results_per_page: int = 20) -> list:
        """Backward-compatible — returns plain strings."""
        return [e.to_rag_text() for e in self.fetch_structured(keyword, results_per_page)]

    def fetch_structured(self, keyword: str, results_per_page: int = 20) -> list:
        entries: dict[str, CVEEntry] = {}
        for e in self._nvd_keyword(keyword, results_per_page):
            entries[e.id] = e
        for e in self._osv_keyword(keyword):
            if e.id not in entries:
                entries[e.id] = e
        for cve_id in self._exploitdb_search(keyword):
            if cve_id in entries:
                entries[cve_id].has_exploit = True
        return list(entries.values())

    # ------------------------------------------------------------------ #
    # NVD                                                                  #
    # ------------------------------------------------------------------ #

    def _nvd_cpe(self, cpe23: str, n: int) -> list:
        try:
            r = requests.get(
                self.nvd_base,
                params={"cpeName": cpe23, "resultsPerPage": n},
                headers=self.nvd_headers, timeout=30,
            )
            if r.status_code == 404:
                print(f"    [NVD-CPE] HTTP 404 — cpeName={cpe23}")
                return []
            if r.status_code != 200:
                print(f"    [NVD-CPE] HTTP {r.status_code}")
                return []
            return self._parse_nvd(r.json())
        except Exception as ex:
            print(f"    [NVD-CPE] error: {ex}")
            return []

    def _nvd_keyword(self, keyword: str, n: int) -> list:
        try:
            r = requests.get(
                self.nvd_base,
                params={"keywordSearch": keyword, "resultsPerPage": n},
                headers=self.nvd_headers, timeout=30,
            )
            if r.status_code != 200:
                print(f"    [NVD-KW] HTTP {r.status_code} for '{keyword}'")
                return []
            return self._parse_nvd(r.json())
        except Exception as ex:
            print(f"    [NVD-KW] error for '{keyword}': {ex}")
            return []

    @staticmethod
    def _parse_nvd(data: dict) -> list:
        results = []
        for vuln in data.get("vulnerabilities", []):
            cve     = vuln["cve"]
            desc    = next(
                (d["value"] for d in cve["descriptions"] if d["lang"] == "en"), ""
            )
            cvss    = _extract_cvss(cve.get("metrics", {}))
            results.append(
                CVEEntry(id=cve["id"], description=desc, source="nvd", cvss_score=cvss)
            )
        return results

    # ------------------------------------------------------------------ #
    # OSV                                                                  #
    # ------------------------------------------------------------------ #

    def _osv_keyword(self, product: str, version: str = "") -> list:
        try:
            payload = {"query": product}
            if version:
                payload["version"] = version
            r = requests.post(self.osv_base, json=payload, timeout=20)
            if r.status_code != 200:
                return []
            results = []
            for v in r.json().get("vulns", []):
                cve_id = None
                for alias in v.get("aliases", []):
                    if alias.startswith("CVE-"):
                        cve_id = alias
                        break
                if not cve_id:
                    continue
                summary = v.get("summary", v.get("details", ""))[:300]
                results.append(CVEEntry(id=cve_id, description=summary, source="osv"))
            return results
        except Exception as ex:
            print(f"    [OSV] error for '{product}': {ex}")
            return []

    # ------------------------------------------------------------------ #
    # Exploit-DB                                                           #
    # ------------------------------------------------------------------ #

    def _exploitdb_search(self, keyword: str) -> list:
        try:
            r = requests.get(
                self.edb_base,
                params={"q": keyword, "json": "true"},
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (research tool)",
                    "X-Requested-With": "XMLHttpRequest",
                },
                timeout=15,
            )
            if r.status_code != 200:
                return []
            exploits = r.json().get("data", [])
            cve_ids  = []
            for exp in exploits:
                for code in exp.get("codes", "").split(";"):
                    code = code.strip()
                    if code.startswith("CVE-"):
                        cve_ids.append(code)
            return list(set(cve_ids))
        except Exception as ex:
            print(f"    [Exploit-DB] error for '{keyword}': {ex}")
            return []