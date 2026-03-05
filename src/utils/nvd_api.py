"""
NVD API Downloader with version-aware CVE filtering.

Key improvements over previous version:
- fetch_by_keyword() now accepts an optional target_version parameter.
- When target_version is provided, each CVE is checked against NVD's
  CPE match data (configurations block) to verify whether the detected
  version falls within the vulnerable version range declared by NVD.
- CVEs that explicitly exclude the target version are filtered out,
  preventing false positives from unrelated versions (e.g. a CVE fixed
  in Apache 2.4.42 will not be reported for a host running 2.4.41 only
  if NVD's range data confirms it is not affected).
- When version_confidence is low (no version detected by scanner),
  all CVEs are kept but tagged with version_match=False so the
  summarizer prompt can communicate the uncertainty to the LLM.
- Falls back gracefully: if CPE data is absent or unparseable, the CVE
  is kept (fail-open) to avoid silently dropping real vulnerabilities.
"""

import requests
from packaging.version import Version, InvalidVersion


def _parse_version(v: str) -> Version | None:
    """Attempt to parse a version string; return None on failure."""
    try:
        return Version(v)
    except InvalidVersion:
        return None


def _version_in_range(
    target: str,
    start_including: str,
    start_excluding: str,
    end_including: str,
    end_excluding: str,
) -> bool:
    """
    Returns True if *target* falls within the CPE version range defined by NVD.
    Any bound that is empty string is treated as unbounded.
    """
    tv = _parse_version(target)
    if tv is None:
        # Cannot parse target version — keep the CVE (fail-open).
        return True

    if start_including:
        sv = _parse_version(start_including)
        if sv and tv < sv:
            return False

    if start_excluding:
        sv = _parse_version(start_excluding)
        if sv and tv <= sv:
            return False

    if end_including:
        ev = _parse_version(end_including)
        if ev and tv > ev:
            return False

    if end_excluding:
        ev = _parse_version(end_excluding)
        if ev and tv >= ev:
            return False

    return True


def _cve_affects_version(cve_data: dict, target_version: str) -> bool:
    """
    Checks NVD configurations (CPE match data) to determine whether
    target_version is within any of the declared vulnerable ranges.

    Returns True  → version is affected (keep the CVE).
    Returns True  → CPE data is missing or unparseable (fail-open).
    Returns False → version is explicitly outside all vulnerable ranges.
    """
    configurations = cve_data.get("configurations", [])
    if not configurations:
        return True  # No CPE data — keep (fail-open).

    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue

                if _version_in_range(
                    target_version,
                    cpe_match.get("versionStartIncluding", ""),
                    cpe_match.get("versionStartExcluding", ""),
                    cpe_match.get("versionEndIncluding", ""),
                    cpe_match.get("versionEndExcluding", ""),
                ):
                    return True

    # Target version did not match any declared vulnerable range.
    return False


class NVDDownloader:

    def __init__(self, api_key: str | None = None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers  = {"apiKey": api_key} if api_key else {}

    def fetch_by_keyword(
        self,
        keyword:        str,
        target_version: str | None = None,
        results_per_page: int = 20,
    ) -> list[str]:
        """
        Fetches CVEs matching *keyword* from NVD and returns them as
        plain-text strings ready for embedding.

        Parameters
        ----------
        keyword         : search term (e.g. "apache httpd", "ProFTPD")
        target_version  : version string detected by the scanner
                          (e.g. "2.4.41").  When provided, CVEs are
                          filtered by CPE version range data.
                          When None / empty, all CVEs are returned
                          (used when version_confidence is "low").
        results_per_page: max CVEs to fetch per keyword.
        """
        params = {
            "keywordSearch":  keyword,
            "resultsPerPage": results_per_page,
        }

        try:
            response = requests.get(
                self.base_url,
                params=params,
                headers=self.headers,
                timeout=30,
            )
        except Exception as e:
            print(f"[!] Request failed for '{keyword}': {e}")
            return []

        if response.status_code != 200:
            print(f"[!] NVD API error {response.status_code} for keyword: '{keyword}'")
            return []

        data = response.json()
        vulnerabilities = []
        skipped = 0

        for vuln in data.get("vulnerabilities", []):
            cve      = vuln["cve"]
            cve_id   = cve["id"]
            desc     = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "",
            )

            # --- Version-aware filtering ---
            if target_version and target_version not in ("n/a", ""):
                if not _cve_affects_version(vuln["cve"], target_version):
                    skipped += 1
                    continue

            vulnerabilities.append(
                f"Source: {keyword} | ID: {cve_id} | Description: {desc}"
            )

        if skipped:
            print(
                f"    [filter] Dropped {skipped} CVE(s) outside version "
                f"{target_version} range for '{keyword}'."
            )

        return vulnerabilities