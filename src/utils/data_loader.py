import json
import os

def load_vulnerabilities_from_json(file_path):
    """
    Load vulnerability data from a JSON file.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data
    