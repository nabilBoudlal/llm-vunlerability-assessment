import requests
import time

class NVDDownloader:
    def __init__(self, api_key=None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {"apiKey": api_key} if api_key else {}

    def fetch_by_keyword(self, keyword, results_per_page=20):
        """
        Fetches CVEs filtered by a specific keyword (e.g., 'Apache 2.4.49').
        """
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": results_per_page
        }
        
        try:
            response = requests.get(self.base_url, params=params, headers=self.headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []
                for vuln in data.get('vulnerabilities', []):
                    cve = vuln['cve']
                    desc = next((d['value'] for d in cve['descriptions'] if d['lang'] == 'en'), "")
                    vulnerabilities.append(f"Source: {keyword} | ID: {cve['id']} | Description: {desc}")
                return vulnerabilities
            else:
                print(f"[!] API Error {response.status_code} for keyword: {keyword}")
                return []
        except Exception as e:
            print(f"[!] Request failed for {keyword}: {e}")
            return []