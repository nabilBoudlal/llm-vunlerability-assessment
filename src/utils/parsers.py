import xml.etree.ElementTree as ET
import pandas as pd
import os
import csv

from .base_parser import BaseScannerParser

class ParserFactory:
    
    @staticmethod
    def get_parser(file_path):
        """Detects file type and returns standardized data."""
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext == ".xml":
            return NmapXMLParser.parse(file_path)
        elif ext == ".csv":
            return NessusCSVParser.parse(file_path)
        else:
            raise ValueError(f"Unsupported file extension: {ext}")

class NmapXMLParser:
    @staticmethod
    def parse(file_path):
        tree = ET.parse(file_path)
        root = tree.getroot()
        hosts = []
        for host in root.findall('host'):
            ip = host.find('address').get('addr')
            
            findings = []
            for port in host.findall('.//port'):
                if port.find('state').get('state') == 'open':
                    findings.append({
                        "item": port.get('portid'),
                        "service": port.find('service').get('name', 'unknown'),
                        "version": port.find('service').get('version', 'n/a')
                        })
                    hosts.append({
                        "source": "Nmap",
                        "target": ip,
                        "findings": findings
                    })
        return hosts
    
class NessusCSVParser:
    @staticmethod
    def parse(file_path):
        # Implementation for basic CSV parsing
        standardized_data = []
        with open(file_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Standardizing Nessus columns (adjust based on your export)
                standardized_data.append({
                    "source": "Nessus",
                    "target": row.get('Host', 'unknown'),
                    "findings": [{
                        "cve": row.get('CVE', 'N/A'),
                        "risk": row.get('Risk', 'unknown'),
                        "description": row.get('Description', '')
                    }]
                })
        return standardized_data

