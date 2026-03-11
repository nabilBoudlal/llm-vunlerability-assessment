import xml.etree.ElementTree as ET
import os
import csv
import re


class ParserFactory:
    @staticmethod
    def get_parser(file_path):
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".xml":
            return NmapXMLParser.parse(file_path)
        elif ext == ".csv":
            return NessusCSVParser.parse(file_path)
        else:
            raise ValueError(f"Estensione non supportata: {ext}")


class NmapXMLParser:
    @staticmethod
    def parse(file_path):
        tree = ET.parse(file_path)
        root = tree.getroot()
        hosts = []

        for host in root.findall('host'):
            addr = host.find('address')
            ip = addr.get('addr') if addr is not None else "unknown"
            findings = []

            for port in host.findall('.//port'):
                state = port.find('state')
                if state is None or state.get('state') != 'open':
                    continue

                srv     = port.find('service')
                portid  = port.get('portid', 'unk')
                sname   = srv.get('name', 'unknown')   if srv is not None else "unknown"
                product = srv.get('product', '')        if srv is not None else ""
                version = srv.get('version', 'n/a')    if srv is not None else "n/a"

                # Build CPE list from <cpe> child elements
                cpe_list = []
                if srv is not None:
                    for cpe_el in srv.findall('cpe'):
                        raw = cpe_el.text.strip() if cpe_el.text else ""
                        if not raw:
                            continue

                        parsed_cpe = NmapXMLParser._parse_cpe(raw, product, version)
                        if parsed_cpe:
                            cpe_list.append(parsed_cpe)

                findings.append({
                    "service":      sname,
                    "product":      product,
                    "version":      version,
                    "port":         portid,
                    "cve":          "N/A",
                    "cpe_list":     cpe_list,
                })

            if findings:
                hosts.append({"source": "Nmap", "target": ip, "findings": findings})

        return hosts

    @staticmethod
    def _parse_cpe(raw: str, product: str, version: str) -> dict | None:
        """
        Convert CPE 2.2 string to CPE 2.3 format for NVD queries.

        Rules:
        - CPEs without a version (e.g. cpe:/o:linux:linux_kernel) get version '*'
          in CPE 2.3 — NVD will 404 on these, so we rely on keyword fallback.
        - The human_product field is set to the Nmap product banner (e.g.
          "Linux telnetd") so the keyword fallback uses a meaningful string
          instead of the CPE internal vendor/product name.
        - Version is taken from the CPE string itself, NOT from the Nmap service
          version field, to avoid cross-contamination between multiple CPEs on
          the same port (e.g. openssh and linux_kernel sharing the SSH version).
        """
        # CPE 2.2 format: cpe:/part:vendor:product:version:...
        parts = raw.split(':')
        # parts[0] = "cpe"
        # parts[1] = "/a", "/o", "/h"
        # parts[2] = vendor
        # parts[3] = product
        # parts[4] = version (optional)

        if len(parts) < 4:
            return None

        cpe_part    = parts[1].lstrip('/')          # a, o, h
        cpe_vendor  = parts[2] if len(parts) > 2 else '*'
        cpe_product = parts[3] if len(parts) > 3 else '*'
        # Version from CPE string only — ignore Nmap service version
        cpe_version = parts[4] if len(parts) > 4 and parts[4] else '*'

        # Sanitize version: reject strings that are clearly not version numbers
        # (e.g. "3.X - 4.X", "4.7p1 Debian 8ubuntu1") — use '*' instead
        if cpe_version != '*':
            if re.search(r'[A-Z].*\s', cpe_version) or ' - ' in cpe_version:
                cpe_version = '*'

        cpe23 = (
            f"cpe:2.3:{cpe_part}:{cpe_vendor}:{cpe_product}:"
            f"{cpe_version}:*:*:*:*:*:*:*"
        )

        return {
            "raw":          raw,
            "cpe23":        cpe23,
            "vendor":       cpe_vendor,
            "product":      cpe_product,
            "version":      cpe_version,
            "human_product": product,   # Nmap banner e.g. "Linux telnetd"
        }


class NessusCSVParser:
    @staticmethod
    def parse(file_path):
        hosts_dict = {}
        with open(file_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get('IP Address', row.get('Host', 'unknown'))
                if ip not in hosts_dict:
                    hosts_dict[ip] = []

                hosts_dict[ip].append({
                    "service":   row.get('Plugin Name', row.get('Name', 'Unknown')),
                    "product":   row.get('Plugin Name', ''),
                    "version":   "n/a",
                    "port":      row.get('Port', 'unk'),
                    "cve":       row.get('CVE', 'N/A'),
                    "severity":  row.get('Severity', 'info'),
                    "description": row.get('Description', ''),
                    "cpe_list":  [],
                })

        standardized_data = []
        for ip, findings in hosts_dict.items():
            standardized_data.append({
                "source":   "Nessus",
                "target":   ip,
                "findings": findings,
            })
        return standardized_data