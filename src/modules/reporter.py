import os
import re
from datetime import datetime

# CVE pattern
_CVE_RE = re.compile(r'\b(CVE-\d{4}-\d{4,})\b')

# Source URL templates per CVE source
_SOURCE_URLS = {
    "nvd":       "https://nvd.nist.gov/vuln/detail/{cve}",
    "osv":       "https://osv.dev/vulnerability/{cve}",
    "exploitdb": "https://www.exploit-db.com/search?q={cve}",
}

def _cve_url(cve_id: str, source: str = "nvd") -> str:
    template = _SOURCE_URLS.get(source.lower(), _SOURCE_URLS["nvd"])
    return template.format(cve=cve_id)


def _linkify_cves(text: str, cve_sources: dict) -> str:
    """
    Replace the FIRST occurrence of each CVE-XXXX-XXXXX with a Markdown hyperlink.
    All subsequent occurrences of the same CVE remain as plain text.
    This keeps references clean — the link appears once (Section 1) and is not
    repeated in the Service Inventory, Policy Issues, and Remediation sections.
    """
    linked: set[str] = set()  # CVEs already linked once

    def replace(m):
        cve = m.group(1)
        # Skip if already inside a Markdown link []()
        return m.group(0)  # handled by pre-scan below

    # Pre-scan: mark CVEs that are already linked in the raw text
    already_linked = set(re.findall(r'\[(CVE-\d{4}-\d{4,})\]\(', text))
    linked.update(already_linked)

    def replace_once(m):
        cve = m.group(1)
        # If this match is already inside [](...), leave it alone
        # (the regex matches the bare ID even inside links — skip those)
        pos = m.start()
        # Check if preceded by "["
        if pos > 0 and text[pos - 1] == "[":
            return cve
        if cve in linked:
            return cve          # plain text for 2nd+ occurrence
        linked.add(cve)
        source = cve_sources.get(cve, "nvd")
        url = _cve_url(cve, source)
        return f"[{cve}]({url})"

    return _CVE_RE.sub(replace_once, text)


class RiskReporter:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def save_report(self, report_name: str, report_content: str,
                    cve_sources: dict = None) -> str:
        """
        Save the LLM-generated report as Markdown.

        cve_sources: optional dict  {CVE_ID: source_name}
                     e.g. {"CVE-2017-9461": "nvd", "CVE-2021-26855": "exploitdb"}
                     Determines which URL is used for inline links.
                     Defaults to NVD for any CVE not in the dict.
        """
        if cve_sources is None:
            cve_sources = {}

        # Remove LLM-generated __url__ italic syntax and invented links
        clean_content = re.sub(r'__([^_]+)__', r'\1', report_content)
        clean_content = re.sub(
            r'\[(CVE-\d{4}-\d{4,})\]\([^)]+\)',
            r'\1',
            clean_content,
        )

        # Linkify CVEs ONLY inside Section 1 — all other sections stay plain text.
        # We split on section headers, linkify only the first section block,
        # then reassemble.
        sec1_marker  = "## 1."
        sec2_marker  = "## 2."
        idx1 = clean_content.find(sec1_marker)
        idx2 = clean_content.find(sec2_marker)

        if idx1 != -1 and idx2 != -1 and idx2 > idx1:
            before_sec1 = clean_content[:idx1]
            sec1_block  = clean_content[idx1:idx2]
            after_sec1  = clean_content[idx2:]
            linked_sec1 = _linkify_cves(sec1_block, cve_sources)
            linked_content = before_sec1 + linked_sec1 + after_sec1
        else:
            # Fallback: linkify entire document if section markers not found
            linked_content = _linkify_cves(clean_content, cve_sources)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename  = f"{report_name}_report_{timestamp}.md"
        filepath  = os.path.join(self.output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"# Vulnerability Assessment Report: {report_name}\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(linked_content)

        return filepath