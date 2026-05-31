

import pandas as pd
import ast
from elasticsearch import Elasticsearch, helpers
from datetime import datetime
import os

ES_HOST = "http://localhost:9200"
INDEX_NAME = "dionaea-malware-intel"
CSV_PATH = "data/dionaea/processed/vt_results.csv"

def parse_threat_label(threat_label):
    """Extract just the malware name from the dictionary string"""
    if pd.isna(threat_label) or threat_label == 'Unknown':
        return 'Unknown'
    
    if isinstance(threat_label, str) and threat_label.startswith("{'count'"):
        try:
            parsed = ast.literal_eval(threat_label)
            return parsed.get('value', 'Unknown')
        except:
            return 'Unknown'
    return str(threat_label)

def push_vt_results():
    if not os.path.exists(CSV_PATH):
        print(f"[!] File not found: {CSV_PATH}")
        return False
    
    df = pd.read_csv(CSV_PATH)
    print(f"[*] Loading {len(df)} VirusTotal results")
    
    es = Elasticsearch(ES_HOST)
    
    if not es.ping():
        print("[!] Elasticsearch not running")
        return False
    
    if es.indices.exists(index=INDEX_NAME):
        es.indices.delete(index=INDEX_NAME)
        print(f"[*] Deleted old {INDEX_NAME}")
    
    actions = []
    for _, row in df.iterrows():
        raw_threat_label = row.get('threat_label', 'Unknown')
        malware_name = parse_threat_label(raw_threat_label)
        
        doc = {
            'sha256_hash': str(row.get('sha256_hash', '')),
            'detection_rate': float(row.get('detection_rate', 0)),
            'malicious_count': int(row.get('malicious_count', 0)),
            'total_engines': int(row.get('total_engines', 0)),
            'threat_label': malware_name,
            'file_type': str(row.get('file_type', 'Unknown')),
            'is_malicious': bool(row.get('is_malicious', False)),
            'severity': str(row.get('severity', 'UNKNOWN')),
            '@timestamp': datetime.now().isoformat()
        }
        actions.append({"_index": INDEX_NAME, "_source": doc})
    
    if actions:
        success, _ = helpers.bulk(es, actions, raise_on_error=False)
        print(f"[✓] Pushed {success} docs to [{INDEX_NAME}]")
        
        malicious = sum(1 for a in actions if a['_source']['is_malicious'])
        print(f"[✓] Malicious: {malicious}, Clean: {len(actions) - malicious}")
        
        families = set(a['_source']['threat_label'] for a in actions if a['_source']['is_malicious'])
        print(f"[✓] Malware families: {', '.join(list(families)[:5])}")
        return True
    
    return False

if __name__ == "__main__":
    push_vt_results()

