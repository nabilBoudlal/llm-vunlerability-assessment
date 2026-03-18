"""
toolbox.py — Tool implementations for the ReAct agent.

Each public method corresponds to one tool the LLM can call.
All methods return a plain string — the LLM reads this as the Observation.

Tools:
  search_nvd(query)          — NVD keyword search
  lookup_cpe(product, ver)   — CPE-based version-pinned CVE lookup
  get_cve(cve_id)            — full details for a specific CVE
  check_kev(keyword)         — CISA Known Exploited Vulnerabilities check
  search_exploitdb(query)    — Exploit-DB public exploit search
  search_osv(query)          — OSV (Google) open-source vulnerability DB
  search_circl(cve_id)       — CIRCL CVE Search (EPSS, enriched metadata)
"""

import os
import time


# ── Product disambiguation filter ───────────────────────────────────────────
# Maps query keywords to strings that, if found in a CVE description, indicate
# the CVE belongs to a different product.  Applied after every NVD retrieval.
_NOISE_MARKERS: dict[str, list[str]] = {
    "samba":   ["sambar server", "sambar web", "securecrt"],
    "smbd":    ["sambar server", "sambar web", "securecrt"],
    "telnetd": ["interaccess telnetd", "interaccess telnet server"],
    "telnet":  ["interaccess telnetd", "interaccess telnet server"],
    "proftpd": ["wuarchive ftpd", "wu-ftpd"],
    "mysql":   ["microsoft sql", "mssql"],
    "redis":   ["aws elasticache"],
}

def _disambiguate(query: str, results: list) -> tuple[list, int]:
    """Strip CVEs that provably belong to a different product."""
    q = query.lower()
    markers: list[str] = []
    for key, noise in _NOISE_MARKERS.items():
        if key in q:
            markers.extend(noise)
    if not markers:
        return results, 0
    kept, removed = [], 0
    for r in results:
        desc = (r.get("description") or "").lower()
        if any(m in desc for m in markers):
            removed += 1
        else:
            kept.append(r)
    return kept, removed


class ToolBox:
    """
    Tool implementations backed by HybridCVEDownloader (hybrid_nvd_api.py).
    Maintains a shared CVE cache and KEV catalog used across all tool calls.
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

    # ── KEV bootstrap ──────────────────────────────────────────────────────────

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

    # ── Shared helpers ─────────────────────────────────────────────────────────

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

    # ── Tools ──────────────────────────────────────────────────────────────────

    def search_nvd(self, query: str) -> str:
        """NVD keyword search."""
        print(f"  [tool] search_nvd({query!r})")
        results = self.dl.fetch_structured(query, results_per_page=10)
        if not results:
            return f"search_nvd({query!r}): No CVEs found."
        results, removed = _disambiguate(query, results)
        if removed:
            print(f"    [disambig] Removed {removed} off-product CVE(s) for {query!r}")
        if not results:
            return f"search_nvd({query!r}): No relevant CVEs found (off-product results filtered)."
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
        results, removed = _disambiguate(product, results)
        if removed:
            print(f"    [disambig] Removed {removed} off-product CVE(s) for {product!r}")
        if not results:
            return f"lookup_cpe({product!r}, {version!r}): No relevant CVEs found (off-product results filtered)."
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
        Real Exploit-DB search: queries exploit-db.com/search for public exploits.
        Returns exploit IDs, titles, and any CVE references found.
        """
        import requests
        print(f"  [tool] search_exploitdb({query!r})")
        try:
            r = requests.get(
                "https://www.exploit-db.com/search",
                params={"q": query, "json": "true"},
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) research-tool/1.0",
                    "X-Requested-With": "XMLHttpRequest",
                },
                timeout=15,
            )
            if r.status_code != 200:
                return (f"search_exploitdb({query!r}): HTTP {r.status_code}. "
                        f"Exploit-DB may be temporarily unavailable.")
            data = r.json()
            exploits = data.get("data", [])
            if not exploits:
                return f"search_exploitdb({query!r}): No public exploits found."

            lines = []
            for exp in exploits[:10]:
                eid   = exp.get("id", "?")
                title = exp.get("description", "")[:80]
                etype = exp.get("type", {})
                if isinstance(etype, dict):
                    etype = etype.get("name", "")
                date  = exp.get("date_published", "")[:10]
                codes = exp.get("codes", "") or ""
                cves  = [c.strip() for c in codes.split(";") if c.strip().startswith("CVE-")]
                for cve in cves:
                    if cve in self._cve_cache:
                        self._cve_cache[cve]["has_exploit"] = True
                    else:
                        self._cve_cache[cve] = {
                            "cvss": "N/A", "description": title,
                            "url": f"https://www.exploit-db.com/exploits/{eid}",
                            "has_exploit": True,
                            "actively_exploited": cve in self._kev_ids,
                            "source": "exploitdb",
                        }
                cve_str = f" | CVEs: {', '.join(cves)}" if cves else " | CVEs: none listed"
                lines.append(f"  EDB-{eid} [{etype}] {date}: {title}{cve_str}")

            return (f"search_exploitdb({query!r}) → {len(exploits)} exploits found "
                    f"(showing top {min(len(exploits),10)}):\n" + "\n".join(lines))
        except Exception as ex:
            return f"search_exploitdb({query!r}): Error — {ex}"

    # OSV ecosystem mapping: product name prefix → ecosystems to try in order.
    # OSV requires a valid ecosystem — without it the API returns HTTP 400.
    # We try Ubuntu first (matching the test VM), then Debian, then Linux kernel.
    _OSV_ECOSYSTEMS: dict[str, list[str]] = {
        "openssh":    ["Ubuntu:20.04", "Debian:11", "Ubuntu:22.04"],
        "samba":      ["Ubuntu:20.04", "Debian:11", "Ubuntu:22.04"],
        "apache":     ["Ubuntu:20.04", "Debian:11", "Ubuntu:22.04"],
        "httpd":      ["Ubuntu:20.04", "Debian:11"],
        "postgresql": ["Ubuntu:20.04", "Debian:11"],
        "postgres":   ["Ubuntu:20.04", "Debian:11"],
        "mysql":      ["Ubuntu:20.04", "Debian:11"],
        "proftpd":    ["Ubuntu:20.04", "Debian:11"],
        "redis":      ["Ubuntu:20.04", "Debian:11"],
        "dovecot":    ["Ubuntu:20.04", "Debian:11"],
        "postfix":    ["Ubuntu:20.04", "Debian:11"],
        "nfs":        ["Ubuntu:20.04", "Debian:11", "Linux"],
        "linux":      ["Linux", "Ubuntu:20.04"],
        "openssl":    ["Ubuntu:20.04", "Debian:11"],
    }
    # OSV canonical package names (may differ from Nmap service banners)
    _OSV_PKG_NAME: dict[str, str] = {
        "apache":     "apache2",
        "httpd":      "apache2",
        "openssh":    "openssh",
        "postgresql": "postgresql",
        "postgres":   "postgresql",
        "proftpd":    "proftpd",
    }

    def search_osv(self, query: str) -> str:
        """
        OSV (Google Open Source Vulnerability) database query.
        Tries multiple Ubuntu/Debian ecosystems — the API requires an ecosystem
        field; bare package name queries return HTTP 400.
        Best source for: OpenSSH, PostgreSQL, Samba, Apache, Redis, MySQL.
        Example: search_osv("openssh")
        """
        import requests
        print(f"  [tool] search_osv({query!r})")

        # Extract base product name and optional version from query
        parts   = query.strip().lower().split()
        base    = parts[0] if parts else query.lower()
        version = parts[1] if len(parts) > 1 else None

        # Resolve canonical OSV package name
        pkg_name   = self._OSV_PKG_NAME.get(base, base)
        ecosystems = self._OSV_ECOSYSTEMS.get(base, ["Ubuntu:20.04", "Debian:11"])

        try:
            all_vulns: list = []
            tried: list[str] = []

            for eco in ecosystems:
                payload: dict = {"package": {"name": pkg_name, "ecosystem": eco}}
                if version:
                    payload["version"] = version
                r = requests.post(
                    "https://api.osv.dev/v1/query",
                    json=payload, timeout=15,
                )
                tried.append(f"{eco}→{r.status_code}")
                if r.status_code == 200:
                    vulns = r.json().get("vulns", [])
                    if vulns:
                        all_vulns = vulns
                        print(f"    [osv] Found {len(vulns)} results in {eco}")
                        break  # stop at first ecosystem that returns results

            if not all_vulns:
                return (f"search_osv({query!r}): No vulnerabilities found "
                        f"(tried: {', '.join(tried)}).")

            lines = []
            for v in all_vulns[:15]:
                osv_id      = v.get("id", "?")
                summary     = v.get("summary", v.get("details", ""))[:100]
                cve_aliases = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
                cve_str     = ", ".join(cve_aliases) if cve_aliases else osv_id
                cvss_str    = ""
                for sev in v.get("severity", []):
                    if sev.get("type") in ("CVSS_V3", "CVSS_V31", "CVSS_V2"):
                        cvss_str = f" | CVSS: {sev.get('score','?')}"
                        break
                for cve in cve_aliases:
                    if cve not in self._cve_cache:
                        self._cve_cache[cve] = {
                            "cvss":               "N/A",
                            "description":        summary,
                            "url":                f"https://osv.dev/vulnerability/{osv_id}",
                            "has_exploit":        False,
                            "actively_exploited": cve in self._kev_ids,
                            "source":             "osv",
                        }
                lines.append(f"  {cve_str} [{osv_id}]{cvss_str}: {summary}")

            return (f"search_osv({query!r}) → {len(all_vulns)} OSV entries "
                    f"(showing top {min(len(all_vulns),15)}):\n" + "\n".join(lines))
        except Exception as ex:
            return f"search_osv({query!r}): Error — {ex}"

    def search_circl(self, cve_id: str) -> str:
        """
        Real CIRCL CVE Search API (cve.circl.lu) — EU NVD mirror.
        Returns CVSS, EPSS exploitability score, CWE, vendor references.
        """
        import requests
        print(f"  [tool] search_circl({cve_id!r})")
        cve_id = cve_id.strip().upper()
        try:
            r = requests.get(
                f"https://cve.circl.lu/api/cve/{cve_id}",
                headers={"Accept": "application/json"},
                timeout=15,
            )
            if r.status_code == 404:
                return f"search_circl({cve_id}): CVE not found in CIRCL database."
            if r.status_code != 200:
                return f"search_circl({cve_id}): HTTP {r.status_code}."
            d = r.json()
            if not d:
                return f"search_circl({cve_id}): Empty response from CIRCL."

            summary   = d.get("summary", "No description")[:300]
            cvss2     = d.get("cvss", "N/A")
            cvss3     = d.get("cvss3", "N/A")
            epss      = d.get("epss", None)
            cwe       = d.get("cwe", "N/A")
            published = str(d.get("Published", ""))[:10]
            modified  = str(d.get("Modified", ""))[:10]
            refs      = d.get("references", [])[:5]

            epss_str = ""
            if epss is not None:
                epss_pct = float(epss) * 100 if float(epss) <= 1.0 else float(epss)
                epss_str = f" | EPSS: {epss_pct:.2f}% exploit probability"

            kev_str = " | ⚠ CISA KEV — actively exploited" if cve_id in self._kev_ids else ""

            if cve_id in self._cve_cache:
                if cvss3 and cvss3 != "N/A":
                    self._cve_cache[cve_id]["cvss"] = cvss3
                elif cvss2 and cvss2 != "N/A":
                    self._cve_cache[cve_id]["cvss"] = cvss2
            else:
                best_cvss = cvss3 if cvss3 not in ("N/A", None) else cvss2
                self._cve_cache[cve_id] = {
                    "cvss": best_cvss, "description": summary,
                    "url": f"https://cve.circl.lu/cve/{cve_id}",
                    "has_exploit": False,
                    "actively_exploited": cve_id in self._kev_ids,
                    "source": "circl",
                }

            refs_str = "\n  References: " + ", ".join(refs) if refs else ""
            return (
                f"search_circl({cve_id}):\n"
                f"  CVSS v2: {cvss2} | CVSS v3: {cvss3}{epss_str}{kev_str}\n"
                f"  CWE: {cwe} | Published: {published} | Modified: {modified}\n"
                f"  Summary: {summary}{refs_str}"
            )
        except Exception as ex:
            return f"search_circl({cve_id}): Error — {ex}"

    def search_epss(self, cve_id: str) -> str:
        """
        Query the FIRST.org EPSS API for exploitation probability.
        EPSS (Exploit Prediction Scoring System) gives the probability that
        a CVE will be exploited in the next 30 days, complementing CVSS severity.
        A low-CVSS CVE with high EPSS is more urgent than a high-CVSS CVE with
        low EPSS.
        Example: search_epss("CVE-2021-44228")
        """
        import requests
        print(f"  [tool] search_epss({cve_id!r})")
        try:
            r = requests.get(
                "https://api.first.org/data/v1/epss",
                params={"cve": cve_id},
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json().get("data", [])
                if data:
                    entry  = data[0]
                    epss   = float(entry.get("epss", 0)) * 100
                    pct    = float(entry.get("percentile", 0)) * 100
                    date   = entry.get("date", "unknown")
                    urgency = "HIGH" if epss >= 10 else ("MEDIUM" if epss >= 1 else "LOW")
                    return (
                        f"search_epss({cve_id}): "
                        f"EPSS={epss:.2f}% exploitation probability in next 30 days "
                        f"[{urgency} urgency, higher than {pct:.0f}% of all CVEs] "
                        f"— data as of {date}"
                    )
                return f"search_epss({cve_id}): No EPSS data found for this CVE."
            return f"search_epss({cve_id}): API error {r.status_code}."
        except Exception as e:
            return f"search_epss({cve_id}): Request failed ({e})."

    # ── Dispatcher ─────────────────────────────────────────────────────────────

    def execute(self, tool_name: str, tool_input: dict) -> str:
        """Route a tool call from the LLM to the correct method."""
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
                return self.check_kev(tool_input.get("keyword") or tool_input.get("query", ""))
            elif tool_name == "search_exploitdb":
                return self.search_exploitdb(tool_input.get("query", ""))
            elif tool_name == "search_osv":
                return self.search_osv(tool_input.get("query", ""))
            elif tool_name == "search_circl":
                return self.search_circl(tool_input.get("cve_id", ""))
            elif tool_name == "search_epss":
                return self.search_epss(tool_input.get("cve_id", ""))
            else:
                return f"Unknown tool: {tool_name}"
        except Exception as e:
            return f"Tool error ({tool_name}): {e}"