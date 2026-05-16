"""
Create Kibana Index Pattern via API
Run after pushing data to Elasticsearch
"""

import requests
import json

KIBANA_URL = "http://localhost:5601"
INDEX_PATTERN_NAME = "dionaea-malware-intel*"

# Create index pattern
payload = {
    "attributes": {
        "title": INDEX_PATTERN_NAME,
        "timeFieldName": "@timestamp"
    }
}

try:
    response = requests.post(
        f"{KIBANA_URL}/api/saved_objects/index-pattern",
        headers={"kbn-xsrf": "true", "Content-Type": "application/json"},
        json=payload
    )
    
    if response.status_code in [200, 201]:
        print(f"[✓] Index pattern '{INDEX_PATTERN_NAME}' created!")
    else:
        print(f"[!] Response: {response.status_code}")
        print(f"    If pattern already exists, ignore this error")
        
except Exception as e:
    print(f"[!] Could not create pattern: {e}")
    print("    Create manually in Kibana UI")