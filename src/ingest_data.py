import os
from dotenv import load_dotenv
from src.utils.nvd_api import NVDDownloader
from src.utils.vectore_store import VectorStoreManager

load_dotenv()

def main():
    api_key = os.getenv("NVD_API_KEY")
    downloader = NVDDownloader(api_key=api_key)
    vsm = VectorStoreManager()

    keywords = ["vsftpd 2.3.4", "Apache 2.4.49", "MySQL 5.7"]
    all_cves = []

    for kw in keywords:
        print(f"Fetching targeted data for: {kw}")
        results = downloader.fetch_by_keyword(kw) 
        all_cves.extend(results)

    vsm.initialize_db(all_cves)

if __name__ == "__main__":
    main()