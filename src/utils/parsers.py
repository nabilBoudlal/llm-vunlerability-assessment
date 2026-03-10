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
    def _parse_cpe(cpe_string, service_version=None):
        """
        Parse a CPE string (2.2 or 2.3) into a structured dict AND
        produce a CPE 2.3 string for NVD cpeName queries.

        CPE 2.2: cpe:/a:vendor:product:version
        CPE 2.3: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        """
        if not cpe_string:
            return None
        try:
            parts = cpe_string.split(":")

            # ── CPE 2.3 ────────────────────────────────────────────────────
            if len(parts) > 2 and parts[1] == "2.3":
                vendor  = parts[3] if len(parts) > 3 else None
                product = parts[4] if len(parts) > 4 else None
                version = parts[5] if len(parts) > 5 and parts[5] not in ("*", "-", "") else None
                cpe23   = cpe_string   # already 2.3
                cpe22   = f"cpe:/{parts[2]}:{vendor}:{product}" + (f":{version}" if version else "")

            # ── CPE 2.2 ────────────────────────────────────────────────────
            else:
                inner   = cpe_string.lstrip("cpe:/").split(":")
                part    = inner[0] if inner else "a"   # a / o / h
                vendor  = inner[1] if len(inner) > 1 else None
                product = inner[2] if len(inner) > 2 else None
                version = inner[3] if len(inner) > 3 and inner[3] not in ("*", "-", "") else None

                # Use service banner version if CPE has none
                if not version and service_version and service_version != "n/a":
                    version = service_version

                cpe22 = cpe_string
                # Build CPE 2.3 for NVD
                ver23 = version if version else "*"
                cpe23 = f"cpe:2.3:{part}:{vendor}:{product}:{ver23}:*:*:*:*:*:*:*"

            return {
                "raw":    cpe22,    # used for CIRCL /cvefor
                "cpe23":  cpe23,    # used for NVD cpeName
                "vendor":  vendor,
                "product": product,
                "version": version,
            }
        except Exception:
            return None

    @staticmethod
    def parse(file_path):
        tree = ET.parse(file_path)
        root = tree.getroot()
        hosts = []

        for host in root.findall("host"):
            addr = host.find("address")
            ip   = addr.get("addr") if addr is not None else "unknown"
            findings = []

            for port in host.findall(".//port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue

                srv = port.find("service")
                service_name    = srv.get("name",    "unknown") if srv is not None else "unknown"
                service_version = srv.get("version", "n/a")     if srv is not None else "n/a"
                # "product" is the human-readable product name (e.g. "Apache httpd")
                service_product = srv.get("product", "")        if srv is not None else ""

                cpe_objects = []
                for cpe_el in port.findall(".//cpe"):
                    parsed = NmapXMLParser._parse_cpe(cpe_el.text, service_version)
                    if parsed:
                        cpe_objects.append(parsed)

                findings.append({
                    "service":  service_name,
                    "product":  service_product,   # e.g. "Apache httpd", "Samba smbd"
                    "version":  service_version,   # e.g. "2.4.41"
                    "port":     port.get("portid", "unk"),
                    "cve":      "N/A",
                    "cpe_list": cpe_objects,
                })

            if findings:
                hosts.append({"source": "Nmap", "target": ip, "findings": findings})

        return hosts


class NessusCSVParser:
    @staticmethod
    def parse(file_path):
        hosts_dict = {}
        with open(file_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get("IP Address", row.get("Host", "unknown"))
                if ip not in hosts_dict:
                    hosts_dict[ip] = []
                hosts_dict[ip].append({
                    "service":  row.get("Plugin Name", row.get("Name", "Unknown")),
                    "product":  "",
                    "version":  "n/a",
                    "port":     row.get("Port", "unk"),
                    "cve":      row.get("CVE", "N/A"),
                    "severity": row.get("Severity", "info"),
                    "description": row.get("Description", ""),
                    "cpe_list": [],
                })

        return [
            {"source": "Nessus", "target": ip, "findings": findings}
            for ip, findings in hosts_dict.items()
        ]