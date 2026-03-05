"""
Scanner output parsers.
Supports: Nmap XML, Nessus CSV.

Improvements over previous version:
- Extracts 'product' field from Nmap (e.g. "ProFTPD", "Postfix smtpd", "Dovecot pop3d")
  so NVD queries use the real software name instead of the generic protocol name.
- Adds 'version_confidence' flag: "high" when Nmap detected a version string, "low" otherwise.
  Downstream components use this to avoid hallucinated version numbers.
- Extracts 'tunnel' field (e.g. "ssl") to correctly identify IMAPS / POP3S services
  and avoid treating them as duplicates of their plaintext counterparts.
- Preserves Nmap script output in 'description' for richer LLM context.
"""

import xml.etree.ElementTree as ET
import os
import csv


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

                srv = port.find('service')
                port_id = port.get('portid', 'unk')

                # --- Service name (protocol-level, e.g. "http", "ftp") ---
                service_name = srv.get('name', 'unknown') if srv is not None else 'unknown'

                # --- Product name (software-level, e.g. "Apache httpd", "ProFTPD") ---
                # This is the key field for accurate NVD queries.
                product = srv.get('product', '') if srv is not None else ''

                # --- Version string ---
                version_raw = srv.get('version', '') if srv is not None else ''
                version = version_raw if version_raw else 'n/a'

                # Nmap sometimes returns a version range (e.g. "12.14 - 12.18").
                # Normalize to the lower bound for accurate NVD CPE queries.
                if version != 'n/a' and ' - ' in version:
                    version = version.split(' - ')[0].strip()

                # Nmap sometimes appends OS/distro info to the version string,
                # e.g. "8.2p1 Ubuntu 4ubuntu0.13" or "2.4.41 (Ubuntu)".
                # Strip everything after the first OS keyword to keep only the
                # upstream version number, which is what NVD expects.
                if version != 'n/a':
                    import re as _re
                    # Remove parenthesised OS hints: "2.4.41 (Ubuntu)" → "2.4.41"
                    version = _re.sub(r'\s*\(.*?\)', '', version).strip()
                    # Remove trailing distro words: "8.2p1 Ubuntu 4ubuntu0.13" → "8.2p1"
                    version = _re.split(
                        r'\s+(?:Ubuntu|Debian|CentOS|Fedora|RHEL|openSUSE|Alpine)',
                        version, maxsplit=1, flags=_re.IGNORECASE
                    )[0].strip()
                    if not version:
                        version = 'n/a'

                # Samba: Nmap often reports just the major version "4" or "3.X - 4.X".
                # A single-digit version is too vague for NVD queries — treat as unknown.
                if product and 'samba' in product.lower() and version != 'n/a':
                    if _re.fullmatch(r'\d', version):
                        version = 'n/a'

                # --- Version confidence ---
                version_confidence = 'high' if (version != 'n/a') else 'low'

                # --- SSL/TLS tunnel ---
                tunnel = srv.get('tunnel', '') if srv is not None else ''

                # --- RPC auxiliary services filter ---
                # mountd, nlockmgr, status are NFS/RPC ancillary daemons with no
                # independent CVEs. Skip them to avoid noise in the report.
                # They are already represented by the parent 'nfs' and 'rpcbind' entries.
                RPC_NOISE = {'mountd', 'nlockmgr', 'status', 'nfs_acl'}
                if service_name.lower() in RPC_NOISE:
                    continue

                # --- Nmap script output (e.g. http-enum, http-vuln*) ---
                script_data = ""
                for script in port.findall('script'):
                    script_id     = script.get('id', '')
                    script_output = script.get('output', '')
                    script_data  += f"[{script_id}]: {script_output}\n"

                findings.append({
                    "service": service_name,          # generic protocol name
                    "product": product,               # real software name (may be empty)
                    "version": version,               # version string or 'n/a'
                    "version_confidence": version_confidence,
                    "tunnel": tunnel,                 # 'ssl' or ''
                    "port": port_id,
                    "cve": "N/A",
                    "description": script_data.strip() if script_data else ""
                })

            if findings:
                hosts.append({"source": "Nmap", "target": ip, "findings": findings})

        return hosts


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

                # Nessus already provides the plugin name as the real software identifier.
                # 'product' mirrors it for pipeline consistency with the Nmap parser.
                plugin_name = row.get('Plugin Name', row.get('Name', 'Unknown'))

                hosts_dict[ip].append({
                    "service": plugin_name,
                    "product": plugin_name,
                    "version": "n/a",
                    "version_confidence": "low",
                    "tunnel": "",
                    "port": row.get('Port', 'unk'),
                    "cve": row.get('CVE', 'N/A'),
                    "severity": row.get('Severity', 'info'),
                    "description": row.get('Description', '')
                })

        standardized_data = []
        for ip, findings in hosts_dict.items():
            standardized_data.append({
                "source": "Nessus",
                "target": ip,
                "findings": findings
            })

        return standardized_data