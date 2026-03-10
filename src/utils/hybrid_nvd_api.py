"""
Hybrid CVE Downloader
---------------------
  Tier 1 — CIRCL /api/cvefor/{cpe22}   version-pinned, no API key
  Tier 2 — NVD   cpeName={cpe23}        version-pinned, uses CPE 2.3
  Tier 3 — NVD   keywordSearch          fallback, uses human product name
"""

import requests
import time
from typing import Optional

NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/"


def _make_entry(cve_id, description, cvss_score, keyword):
    return {
        "text":        f"Source: {keyword} | ID: {cve_id} | CVSS: {cvss_score} | Description: {description}",
        "id":          cve_id,
        "url":         f"{NVD_DETAIL_URL}{cve_id}",
        "cvss_score":  cvss_score,
        "description": description,
        "keyword":     keyword,
    }


def _extract_cvss(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            try:
                return str(metrics[key][0]["cvssData"]["baseScore"])
            except (KeyError, IndexError):
                pass
    return "N/A"


# ---------------------------------------------------------------------------
# Tier 1 — CIRCL /api/cvefor/{cpe22}
# ---------------------------------------------------------------------------

def _fetch_circl(cpe22, label, max_results=20):
    url = f"https://cve.circl.lu/api/cvefor/{cpe22}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code != 200:
            print(f"    [CIRCL]  HTTP {resp.status_code} — {url}")
            return []
        records = resp.json()
        if not isinstance(records, list):
            records = records.get("results", [])
        results = []
        for rec in records[:max_results]:
            cve_id = rec.get("id", rec.get("CVE", ""))
            if not cve_id:
                continue
            desc = rec.get("summary", rec.get("description", ""))
            cvss = str(rec.get("cvss", "N/A"))
            results.append(_make_entry(cve_id, desc, cvss, label))
        return results
    except Exception as e:
        print(f"    [CIRCL]  Exception: {e}")
        return []


# ---------------------------------------------------------------------------
# Tier 2 — NVD cpeName (requires CPE 2.3 format)
# ---------------------------------------------------------------------------

def _fetch_nvd_cpe(cpe23, headers, max_results=20):
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cpeName": cpe23, "resultsPerPage": max_results},
            headers=headers, timeout=30,
        )
        if resp.status_code != 200:
            print(f"    [NVD-CPE] HTTP {resp.status_code} — cpeName={cpe23}")
            return []
        results = []
        for vuln in resp.json().get("vulnerabilities", []):
            cve    = vuln["cve"]
            cve_id = cve["id"]
            desc   = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")
            cvss   = _extract_cvss(cve.get("metrics", {}))
            results.append(_make_entry(cve_id, desc, cvss, cpe23))
        return results
    except Exception as e:
        print(f"    [NVD-CPE] Exception: {e}")
        return []


# ---------------------------------------------------------------------------
# Tier 3 — NVD keyword (uses human-readable product name, not CPE field)
# ---------------------------------------------------------------------------

def _fetch_nvd_keyword(keyword, headers, max_results=20):
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            headers=headers, timeout=30,
        )
        if resp.status_code != 200:
            print(f"    [NVD-KW]  HTTP {resp.status_code} — keyword={keyword}")
            return []
        results = []
        for vuln in resp.json().get("vulnerabilities", []):
            cve    = vuln["cve"]
            cve_id = cve["id"]
            desc   = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")
            cvss   = _extract_cvss(cve.get("metrics", {}))
            results.append(_make_entry(cve_id, desc, cvss, keyword))
        return results
    except Exception as e:
        print(f"    [NVD-KW]  Exception: {e}")
        return []


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

class HybridCVEDownloader:
    """Drop-in replacement for NVDDownloader."""

    def __init__(self, api_key=None):
        self.headers = {"apiKey": api_key} if api_key else {}
        self._api_key_present = bool(api_key)

    # backward-compatible interface
    def fetch_by_keyword(self, keyword, results_per_page=20):
        return [e["text"] for e in self.fetch_structured(keyword, results_per_page)]

    def fetch_structured(self, keyword, results_per_page=20):
        """Keyword-only fetch — used by Stage 3 for LLM-generated queries."""
        return _fetch_nvd_keyword(keyword, self.headers, results_per_page)

    def fetch_by_cpe(self, cpe_object, max_results=20):
        """
        Three-tier lookup.

        cpe_object keys (produced by NmapXMLParser):
          raw     — CPE 2.2 string  → used for CIRCL
          cpe23   — CPE 2.3 string  → used for NVD cpeName
          vendor, product, version
          product_name (optional)   → human name for keyword fallback
        """
        cpe22   = cpe_object.get("raw", "")
        cpe23   = cpe_object.get("cpe23", "")
        vendor  = cpe_object.get("vendor", "")
        product = cpe_object.get("product", "")
        version = cpe_object.get("version")
        # Human-readable name (e.g. "Apache httpd") — better for keyword search
        product_name = cpe_object.get("product_name", product)

        label = f"{vendor}/{product}" + (f" {version}" if version else "")

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

        # ── Tier 1: CIRCL ──────────────────────────────────────────────────
        if cpe22:
            print(f"    [Tier-1 CIRCL]   {cpe22}")
            _add(_fetch_circl(cpe22, label, max_results), "CIRCL")

        # ── Tier 2: NVD CPE 2.3 ────────────────────────────────────────────
        if cpe23:
            print(f"    [Tier-2 NVD-CPE] {cpe23}")
            time.sleep(2 if self._api_key_present else 6)
            _add(_fetch_nvd_cpe(cpe23, self.headers, max_results), "NVD-CPE")

        # ── Tier 3: NVD keyword — only if tiers 1+2 returned nothing ───────
        if len(results) == 0:
            # Build keyword from human product name + version (not CPE field names)
            kw_parts = [p for p in [product_name, version] if p and p not in ("n/a", "*", "-")]
            kw = " ".join(kw_parts).strip()
            if not kw:
                kw = f"{vendor} {product}".strip()
            if kw:
                print(f"    [Tier-3 NVD-KW]  '{kw}'  (tiers 1+2 empty)")
                time.sleep(6 if self._api_key_present else 30)
                _add(_fetch_nvd_keyword(kw, self.headers, max_results), "NVD-KW fallback")

        return results