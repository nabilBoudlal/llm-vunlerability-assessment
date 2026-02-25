import xml.etree.ElementTree as ET
import os
import csv
from .base_parser import BaseScannerParser

class ParserFactory:
    @staticmethod
    def get_parser(file_path):
        """Rileva l'estensione del file e restituisce i dati standardizzati."""
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext == ".xml":
            return NmapXMLParser.parse(file_path)
        elif ext == ".csv":
            return NessusCSVParser.parse(file_path)
        else:
            raise ValueError(f"Estensione file non supportata: {ext}")

class NmapXMLParser:
    @staticmethod
    def parse(file_path):
        """Parsa l'output XML di Nmap in un formato standardizzato."""
        tree = ET.parse(file_path)
        root = tree.getroot()
        hosts = []
        
        for host in root.findall('host'):
            # Estrazione dell'indirizzo IP
            addr_elem = host.find('address')
            if addr_elem is None:
                continue
            ip = addr_elem.get('addr')
            
            findings = []
            # Iterazione su tutte le porte trovate per l'host corrente
            for port in host.findall('.//port'):
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
                    service_elem = port.find('service')
                    
                    # Estrazione sicura dei metadati del servizio
                    service_name = "unknown"
                    version = "n/a"
                    
                    if service_elem is not None:
                        service_name = service_elem.get('name', 'unknown')
                        # Alcuni servizi hanno 'product' e 'version', li uniamo se necessario
                        product = service_elem.get('product', '')
                        ver = service_elem.get('version', '')
                        if product or ver:
                            version = f"{product} {ver}".strip() or "n/a"

                    findings.append({
                        "item": port.get('portid'),
                        "service": service_name,
                        "version": version
                    })
            
            # CORREZIONE: Aggiungiamo l'host alla lista SOLO dopo aver processato tutte le sue porte.
            # Questo evita la duplicazione dell'host nella lista finale (causa del loop nel main).
            if findings:
                hosts.append({
                    "source": "Nmap",
                    "target": ip,
                    "findings": findings
                })
        
        return hosts
    
class NessusCSVParser:
    @staticmethod
    def parse(file_path):
        """Parsa l'export CSV di Nessus."""
        standardized_data = []
        if not os.path.exists(file_path):
            return standardized_data

        with open(file_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
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