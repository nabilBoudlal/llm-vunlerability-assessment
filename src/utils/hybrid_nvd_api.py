"""
Hybrid CVE Downloader
---------------------
Two-tier lookup strategy:

  Tier 1 — NVD cpeName={cpe23}
            Version-pinned search using the exact CPE 2.3 string from Nmap.
            Most accurate — returns only CVEs matching the specific version.

  Tier 2 — NVD keywordSearch  (fallback)
            Used when Tier 1 returns nothing (e.g. generic CPEs like linux_kernel
            with no version, or services without a recognised NVD CPE entry).
            Uses the human-readable product name from the Nmap service banner
            (e.g. "Apache httpd 2.4.41") rather than the CPE internal field name
            ("http_server") for better NVD index matching.

Note: CIRCL CVE Search was evaluated as an additional source but removed due to
unreliable availability (frequent 404s — the /cvefor endpoint does not accept
wildcard characters in CPE 2.3 strings). NVD cpeName provides equivalent
version-pinned accuracy with better reliability.
"""

import requests
import time
from typing import Optional

NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/"
NVD_CVE_URL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _make_entry(cve_id, description, cvss_score, keyword):
    return {
        "text":        f"Source: {keyword} | ID: {cve_id} | CVSS: {cvss_score} | Description: {description}",
        "id":          cve_id,
        "url":         f"{NVD_DETAIL_URL}{cve_id}",
        "cvss_score":  cvss_score,
        "description": description,
        "keyword":     keyword,
    }


def _extract_cvss(metrics: dict) -> str:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            try:
                return str(metrics[key][0]["cvssData"]["baseScore"])
            except (KeyError, IndexError):
                pass
    return "N/A"


def _parse_nvd_response(resp, source_label: str) -> list:
    results = []
    for vuln in resp.json().get("vulnerabilities", []):
        cve    = vuln["cve"]
        cve_id = cve["id"]
        desc   = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")
        cvss   = _extract_cvss(cve.get("metrics", {}))
        results.append(_make_entry(cve_id, desc, cvss, source_label))
    return results


# ---------------------------------------------------------------------------
# Tier 1 — NVD cpeName (version-pinned, requires CPE 2.3 format)
# ---------------------------------------------------------------------------

def _fetch_nvd_cpe(cpe23: str, headers: dict, max_results: int = 20) -> list:
    try:
        resp = requests.get(
            NVD_CVE_URL,
            params={"cpeName": cpe23, "resultsPerPage": max_results},
            headers=headers, timeout=30,
        )
        if resp.status_code != 200:
            print(f"    [NVD-CPE] HTTP {resp.status_code} — cpeName={cpe23}")
            return []
        return _parse_nvd_response(resp, cpe23)
    except Exception as e:
        print(f"    [NVD-CPE] Exception: {e}")
        return []


# ---------------------------------------------------------------------------
# Tier 2 — NVD keyword search (fallback)
# ---------------------------------------------------------------------------

def _fetch_nvd_keyword(keyword: str, headers: dict, max_results: int = 20) -> list:
    try:
        resp = requests.get(
            NVD_CVE_URL,
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            headers=headers, timeout=30,
        )
        if resp.status_code != 200:
            print(f"    [NVD-KW]  HTTP {resp.status_code} — keyword={keyword}")
            return []
        return _parse_nvd_response(resp, keyword)
    except Exception as e:
        print(f"    [NVD-KW]  Exception: {e}")
        return []


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

class HybridCVEDownloader:
    """Drop-in replacement for NVDDownloader."""

    def __init__(self, api_key: Optional[str] = None):
        self.headers = {"apiKey": api_key} if api_key else {}
        self._api_key_present = bool(api_key)

    # backward-compatible interface
    def fetch_by_keyword(self, keyword: str, results_per_page: int = 20) -> list:
        return [e["text"] for e in self.fetch_structured(keyword, results_per_page)]

    def fetch_structured(self, keyword: str, results_per_page: int = 20) -> list:
        """Keyword-only structured fetch — used by Stage 3 for LLM-proposed queries."""
        return _fetch_nvd_keyword(keyword, self.headers, results_per_page)

    def fetch_by_cpe(self, cpe_object: dict, max_results: int = 20) -> list:
        """
        Two-tier CPE-driven lookup.

        cpe_object keys (from NmapXMLParser + agent enrichment):
          cpe23        — CPE 2.3 string  (e.g. cpe:2.3:a:apache:http_server:2.4.41:*...)
          vendor       — CPE vendor token (e.g. "apache")
          product      — CPE product token (e.g. "http_server")
          version      — detected version  (e.g. "2.4.41")
          product_name — human banner name (e.g. "Apache httpd") for Tier 2 fallback
        """
        cpe23        = cpe_object.get("cpe23", "")
        vendor       = cpe_object.get("vendor", "")
        product      = cpe_object.get("product", "")
        version      = cpe_object.get("version")
        product_name = cpe_object.get("product_name") or product

        seen_ids = set()
        results  = []

        def _add(entries, src):
            added = 0
            for e in entries:
                if e["id"] not in seen_ids:
                    seen_ids.add(e["id"])
                    results.append(e)
                    added += 1
            print(f"              → {added} new CVEs from {src} ({len(seen_ids)} total unique)")

        # ── Tier 1: NVD cpeName (version-pinned) ───────────────────────────
        if cpe23:
            print(f"    [Tier-1 NVD-CPE] {cpe23}")
            _add(_fetch_nvd_cpe(cpe23, self.headers, max_results), "NVD-CPE")
            time.sleep(2 if self._api_key_present else 6)

        # ── Tier 2: NVD keyword fallback ───────────────────────────────────
        if len(results) == 0:
            kw_parts = [p for p in [product_name, version] if p and p not in ("n/a", "*", "-")]
            kw = " ".join(kw_parts).strip() or f"{vendor} {product}".strip()
            if kw:
                print(f"    [Tier-2 NVD-KW]  '{kw}'  (Tier 1 empty — fallback)")
                time.sleep(6 if self._api_key_present else 30)
                _add(_fetch_nvd_keyword(kw, self.headers, max_results), "NVD-KW fallback")

        return results