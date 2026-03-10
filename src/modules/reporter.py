import os
import re
from datetime import datetime


class RiskReporter:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_cve_ids(text):
        """Return all unique CVE IDs found anywhere in *text*."""
        return sorted(set(re.findall(r"CVE-\d{4}-\d+", text, re.IGNORECASE)))

    @staticmethod
    def _build_references_section(cve_ids, cve_references):
        """
        Build a Markdown references block.

        For every CVE ID mentioned in the report:
          - If the NVD URL is in cve_references, render a hyperlink.
          - Otherwise, render a plain NVD search URL as a fallback.
        """
        if not cve_ids:
            return ""

        NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"
        lines = ["", "---", "## References", ""]
        for cve_id in cve_ids:
            url = cve_references.get(cve_id, f"{NVD_DETAIL}{cve_id}")
            lines.append(f"- [{cve_id}]({url}) — National Vulnerability Database")
        lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save_report(self, report_name, report_content, cve_references=None):
        """
        Save an LLM-generated Markdown report to disk.

        Parameters
        ----------
        report_name : str
            Base name (no extension) used in the filename.
        report_content : str
            Markdown text produced by the LLM summariser / consolidator.
        cve_references : dict[str, str] | None
            Optional mapping of CVE_ID -> NVD URL produced by CVEResearchAgent.
            When provided, a "References" section is appended that links every
            CVE mentioned in the report back to its NVD entry.
        """
        if cve_references is None:
            cve_references = {}

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{report_name}_report_{timestamp}.md"
        filepath = os.path.join(self.output_dir, filename)

        # Collect all CVE IDs mentioned anywhere in the report
        cve_ids = self._extract_cve_ids(report_content)

        # Build the references appendix
        references_section = self._build_references_section(cve_ids, cve_references)

        with open(filepath, "w", encoding="utf-8") as f:
            # Header
            f.write(f"# Vulnerability Assessment Report: {report_name}\n")
            f.write(
                f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            )

            # Main LLM-generated body
            f.write(report_content)

            # Append references if any CVEs were found
            if references_section:
                f.write(references_section)

        return filepath