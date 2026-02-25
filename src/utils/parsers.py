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
                if state is not None and state.get('state') == 'open':
                    srv = port.find('service')
                    findings.append({
                        "service": srv.get('name', 'unknown') if srv is not None else "unknown",
                        "version": srv.get('version', 'n/a') if srv is not None else "n/a",
                        "port": port.get('portid', 'unk'),
                        "cve": "N/A" # Nmap base non fornisce CVE
                    })
            if findings:
                hosts.append({"source": "Nmap", "target": ip, "findings": findings})
        return hosts

class NessusCSVParser:
    @staticmethod
    def parse(file_path):
        hosts_dict = {} # Usiamo un dizionario per raggruppare per IP
        with open(file_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get('IP Address', row.get('Host', 'unknown'))
                if ip not in hosts_dict:
                    hosts_dict[ip] = []
                
                hosts_dict[ip].append({
                    "service": row.get('Plugin Name', row.get('Name', 'Unknown')),
                    "version": "n/a",
                    "port": row.get('Port', 'unk'),
                    "cve": row.get('CVE', 'N/A'),
                    "severity": row.get('Severity', 'info'),
                    "description": row.get('Description', '')
                })
        
        # Convertiamo il dizionario nella lista standard richiesta dal main
        standardized_data = []
        for ip, findings in hosts_dict.items():
            standardized_data.append({
                "source": "Nessus",
                "target": ip,
                "findings": findings
            })
        return standardized_data