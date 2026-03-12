"""
Multi-Source CVE Downloader
Sources:
  Tier 1 — NVD CPE  (version-pinned, most precise)
  Tier 2 — NVD keyword fallback
  Tier 3 — OSV / Google (open-source ecosystem)
  Tier 4 — Exploit-DB (public exploit flag)
  Tier 5 — CIRCL CVE Search (CERT Luxembourg, good version matching)
  Tier 6 — CISA KEV  (actively-exploited-in-the-wild flag, no API key needed)
"""
import requests
import time
from dataclasses import dataclass, field


@dataclass
class CVEEntry:
    id:                 str
    description:        str
    source:             str           # "nvd" | "osv" | "exploitdb" | "circl" | "cisa_kev"
    cvss_score:         str  = "N/A"
    has_exploit:        bool = False  # True if found in Exploit-DB
    actively_exploited: bool = False  # True if in CISA KEV catalog

    def to_rag_text(self) -> str:
        flags = []
        if self.has_exploit:
            flags.append("PUBLIC EXPLOIT AVAILABLE")
        if self.actively_exploited:
            flags.append("ACTIVELY EXPLOITED IN THE WILD (CISA KEV)")
        flag_str = (" [" + " | ".join(flags) + "]") if flags else ""
        return (
            f"Source: {self.source}{flag_str} | "
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
    Aggregates CVE data from NVD, OSV, Exploit-DB, CIRCL, and CISA KEV.
    Deduplicated by CVE ID across all sources.
    CISA KEV is fetched once at startup and cached in memory.
    """

    def __init__(self, nvd_api_key: str = None):
        self.nvd_api_key = nvd_api_key
        self.nvd_base    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.nvd_headers = {"apiKey": nvd_api_key} if nvd_api_key else {}
        self.osv_base    = "https://api.osv.dev/v1/query"
        self.edb_base    = "https://www.exploit-db.com/search"
        self.circl_base  = "https://cve.circl.lu/api/search"
        self.cisa_kev_url = (
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json"
        )

        # Pre-load CISA KEV catalog into a set of CVE IDs
        self._kev_ids: set[str] = self._load_cisa_kev()

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
            for e in self._nvd_cpe(cpe23, results_per_page):
                entries[e.id] = e
            print(f"              → {len(entries)} CVEs from NVD-CPE")

        # Tier 2 — NVD keyword fallback
        kw_product = human_product if human_product else product
        if not entries and kw_product:
            kw = f"{kw_product} {version}".strip()
            for placeholder in (" None", " n/a", " N/A", " unknown"):
                kw = kw.replace(placeholder, "")
            kw = kw.strip()
            print(f"    [Tier-2 NVD-KW]  '{kw}'  (Tier-1 empty — fallback)")
            for e in self._nvd_keyword(kw, results_per_page):
                entries[e.id] = e
            print(f"              → {len(entries)} CVEs from NVD-KW fallback")

        # Tier 3 — OSV
        if product:
            new = 0
            for e in self._osv_keyword(product, version):
                if e.id not in entries:
                    entries[e.id] = e
                    new += 1
            if new:
                print(f"    [Tier-3 OSV]  +{new} new CVEs")

        # Tier 4 — Exploit-DB (sets has_exploit flag)
        if product:
            kw = f"{product} {version}".strip()
            exploit_ids = self._exploitdb_search(kw)
            marked = 0
            for cve_id in exploit_ids:
                if cve_id in entries:
                    entries[cve_id].has_exploit = True
                    marked += 1
            if exploit_ids:
                print(f"    [Tier-4 Exploit-DB]  {len(exploit_ids)} exploits"
                      f" ({marked} matched existing CVEs)")

        # Tier 5 — CIRCL CVE Search
        if product:
            new = 0
            for e in self._circl_search(product, version):
                if e.id not in entries:
                    entries[e.id] = e
                    new += 1
            if new:
                print(f"    [Tier-5 CIRCL]  +{new} new CVEs")

        # Tier 6 — CISA KEV enrichment (mark actively exploited)
        kev_marked = self._apply_kev(entries)
        if kev_marked:
            print(f"    [Tier-6 CISA KEV]  {kev_marked} CVE(s) flagged as actively exploited")

        return list(entries.values())

    def fetch_by_keyword(self, keyword: str, results_per_page: int = 20) -> list:
        """Backward-compatible — returns plain RAG strings."""
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

        for e in self._circl_search(keyword):
            if e.id not in entries:
                entries[e.id] = e

        self._apply_kev(entries)
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
            cve  = vuln["cve"]
            desc = next(
                (d["value"] for d in cve["descriptions"] if d["lang"] == "en"), ""
            )
            cvss = _extract_cvss(cve.get("metrics", {}))
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
            if version and version not in ("n/a", "N/A", "unknown", ""):
                payload["version"] = version
            r = requests.post(self.osv_base, json=payload, timeout=20)
            if r.status_code != 200:
                return []
            results = []
            for v in r.json().get("vulns", []):
                cve_id = next(
                    (a for a in v.get("aliases", []) if a.startswith("CVE-")), None
                )
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
            cve_ids = []
            for exp in r.json().get("data", []):
                for code in exp.get("codes", "").split(";"):
                    code = code.strip()
                    if code.startswith("CVE-"):
                        cve_ids.append(code)
            return list(set(cve_ids))
        except Exception as ex:
            print(f"    [Exploit-DB] error for '{keyword}': {ex}")
            return []

    # ------------------------------------------------------------------ #
    # CIRCL CVE Search (Tier 5)                                           #
    # ------------------------------------------------------------------ #

    def _circl_search(self, product: str, version: str = "") -> list:
        """
        CIRCL CVE Search API — https://cve.circl.lu
        Endpoint: GET /api/search/{product}/{version}
        Free, no API key, operated by CERT Luxembourg.
        """
        try:
            # Clean product name for URL
            product_clean = product.lower().replace(" ", "_")
            version_clean = version.strip() if version and version not in (
                "n/a", "N/A", "unknown", "") else ""

            url = f"{self.circl_base}/{product_clean}"
            if version_clean:
                url += f"/{version_clean}"

            r = requests.get(url, timeout=15)
            if r.status_code != 200:
                return []

            data = r.json()
            # CIRCL returns a list of CVE objects directly
            if isinstance(data, dict):
                data = data.get("results", [])

            results = []
            for item in data[:20]:  # cap at 20 per source
                cve_id = item.get("id", "")
                if not cve_id.startswith("CVE-"):
                    continue
                desc = item.get("summary", "")[:300]
                # CIRCL includes cvss field directly
                cvss = str(item.get("cvss", "N/A"))
                results.append(
                    CVEEntry(id=cve_id, description=desc, source="circl",
                             cvss_score=cvss)
                )
            return results
        except Exception as ex:
            print(f"    [CIRCL] error for '{product}': {ex}")
            return []

    # ------------------------------------------------------------------ #
    # CISA KEV — Known Exploited Vulnerabilities (Tier 6)                 #
    # ------------------------------------------------------------------ #

    def _load_cisa_kev(self) -> set:
        """
        Downloads the CISA KEV catalog once at startup.
        Returns a set of CVE IDs that are known to be actively exploited.
        Falls back to empty set on network error.
        """
        try:
            r = requests.get(self.cisa_kev_url, timeout=20)
            if r.status_code != 200:
                print(f"[!] CISA KEV: HTTP {r.status_code} — skipping")
                return set()
            vulns = r.json().get("vulnerabilities", [])
            kev_ids = {v["cveID"] for v in vulns if "cveID" in v}
            print(f"[*] CISA KEV loaded: {len(kev_ids)} known-exploited CVEs cached")
            return kev_ids
        except Exception as ex:
            print(f"[!] CISA KEV load failed: {ex} — skipping")
            return set()

    def _apply_kev(self, entries: dict) -> int:
        """Mark entries that appear in the CISA KEV catalog. Returns count marked."""
        marked = 0
        for cve_id, entry in entries.items():
            if cve_id in self._kev_ids:
                entry.actively_exploited = True
                marked += 1
        return marked