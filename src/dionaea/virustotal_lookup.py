#!/usr/bin/env python3
"""
COMPLETE VIRUSTOTAL INTEGRATION FOR DIONAEA
Does everything: Get hashes → Query VT → Push to Elasticsearch → Find zero-days
"""

import os
import time
import requests
import pandas as pd
from datetime import datetime, timezone
from elasticsearch import Elasticsearch, helpers
from dotenv import load_dotenv

# Load API key from .env
load_dotenv()

# ============================================================
# CONFIGURATION - CHANGE THESE IF NEEDED
# ============================================================
VT_API_KEY = os.getenv("VT_API_KEY")
VT_API_URL = "https://www.virustotal.com/api/v3/files/"
ES_HOST = "http://localhost:9200"
INDEX_NAME = "dionaea-malware-intel"
REQUEST_DELAY = 15  # Seconds between API calls (4 per minute max)

# ============================================================
# PART 1: GET HASHES FROM DIONAEA
# ============================================================

def get_hashes_from_dionaea(limit=20):
    """Extract SHA256 hashes from Dionaea raw data"""
    
    raw_csv = "data/dionaea/raw/dionaea_raw.csv"
    
    if not os.path.exists(raw_csv):
        print(f"[!] File not found: {raw_csv}")
        return []
    
    df = pd.read_csv(raw_csv)
    
    # Get unique hashes, remove empty ones
    hashes = df['sha256_hash'].dropna().unique().tolist()
    hashes = [h for h in hashes if h != "" and h != "nan" and len(str(h)) > 10]
    
    print(f"[*] Found {len(hashes)} total unique hashes")
    
    # Limit for API rate limits
    if len(hashes) > limit:
        print(f"[!] Limiting to first {limit} hashes")
        hashes = hashes[:limit]
    
    return hashes

# ============================================================
# PART 2: QUERY VIRUSTOTAL API
# ============================================================

def query_virustotal(file_hash):
    """Query VirusTotal API for a single hash"""
    
    headers = {"x-apikey": VT_API_KEY}
    url = f"{VT_API_URL}{file_hash}"
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return None  # Hash not found in database
        else:
            print(f"    API Error: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"    Connection error: {e}")
        return None

def parse_vt_response(data, file_hash):
    """Extract useful information from VT response"""
    
    if not data:
        return {
            'sha256_hash': file_hash,
            'is_malicious': False,
            'malicious_count': 0,
            'total_engines': 0,
            'detection_rate': 0,
            'severity': 'UNKNOWN',
            'threat_label': 'NOT_FOUND',
            'file_type': 'Unknown'
        }
    
    attributes = data.get('data', {}).get('attributes', {})
    stats = attributes.get('last_analysis_stats', {})
    
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    undetected = stats.get('undetected', 0)
    harmless = stats.get('harmless', 0)
    
    total = malicious + suspicious + undetected + harmless
    detection_rate = (malicious / total * 100) if total > 0 else 0
    
    # Get malware name
    popular = attributes.get('popular_threat_classification', {})
    threat_label = popular.get('popular_threat_name', ['Unknown'])[0] if popular else 'Unknown'
    
    # Determine severity
    if malicious > 20:
        severity = 'CRITICAL'
    elif malicious > 5:
        severity = 'HIGH'
    elif malicious > 0:
        severity = 'MEDIUM'
    else:
        severity = 'CLEAN'
    
    return {
        'sha256_hash': file_hash,
        'is_malicious': malicious > 0,
        'malicious_count': malicious,
        'total_engines': total,
        'detection_rate': round(detection_rate, 2),
        'severity': severity,
        'threat_label': threat_label if malicious > 0 else 'Clean',
        'file_type': attributes.get('type_description', 'Unknown')
    }

# ============================================================
# PART 3: PUSH TO ELASTICSEARCH
# ============================================================

def push_to_elasticsearch(results):
    """Push VirusTotal results to Elasticsearch"""
    
    es = Elasticsearch(ES_HOST)
    
    if not es.ping():
        print("[!] Cannot connect to Elasticsearch")
        print("    Make sure it's running: docker compose up -d")
        return False
    
    # Delete old index to start fresh (optional)
    if es.indices.exists(index=INDEX_NAME):
        print(f"[*] Deleting old {INDEX_NAME} index...")
        es.indices.delete(index=INDEX_NAME)
    
    actions = []
    for result in results:
        doc = {
            **result,
            '@timestamp': datetime.now(timezone.utc).isoformat(),
            'honeypot': 'dionaea',
            'zero_day_candidate': result['malicious_count'] == 0 and result['severity'] == 'UNKNOWN'
        }
        actions.append({"_index": INDEX_NAME, "_source": doc})
    
    if actions:
        success, failed = helpers.bulk(es, actions, raise_on_error=False)
        print(f"[✓] Pushed {success} results to [{INDEX_NAME}]")
        return True
    
    return False

# ============================================================
# PART 4: CREATE KIBANA INDEX PATTERN VIA API
# ============================================================

def create_kibana_index_pattern():
    """Create index pattern in Kibana automatically"""
    
    kibana_url = "http://localhost:5601"
    
    payload = {
        "attributes": {
            "title": "dionaea-malware-intel*",
            "timeFieldName": "@timestamp"
        }
    }
    
    try:
        response = requests.post(
            f"{kibana_url}/api/saved_objects/index-pattern",
            headers={"kbn-xsrf": "true", "Content-Type": "application/json"},
            json=payload,
            timeout=10
        )
        
        if response.status_code in [200, 201]:
            print("[✓] Kibana index pattern created automatically!")
        else:
            print("[!] Could not auto-create index pattern")
            print("    Create manually: Stack Management → Index Patterns → Create")
            
    except Exception as e:
        print("[!] Could not reach Kibana API")
        print("    Create index pattern manually in Kibana UI")

# ============================================================
# PART 5: PRINT SUMMARY
# ============================================================

def print_summary(results):
    """Print a nice summary of results"""
    
    if not results:
        print("[!] No results to summarize")
        return
    
    malicious = sum(1 for r in results if r['is_malicious'])
    clean = sum(1 for r in results if not r['is_malicious'] and r['severity'] == 'CLEAN')
    unknown = sum(1 for r in results if r['severity'] == 'UNKNOWN')
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total hashes analyzed: {len(results)}")
    print(f"  🟠 MALICIOUS: {malicious}")
    print(f"  🟢 CLEAN: {clean}")
    print(f"  ⚪ UNKNOWN/NOT FOUND: {unknown}")
    
    if malicious > 0:
        print("\n⚠️  MALICIOUS HASHES FOUND:")
        for r in results:
            if r['is_malicious']:
                print(f"    {r['sha256_hash'][:32]}... | {r['malicious_count']}/{r['total_engines']} engines | {r['threat_label']}")
    
    # Zero-day candidates
    zero_day = [r for r in results if r['malicious_count'] == 0 and r['severity'] == 'UNKNOWN']
    if zero_day:
        print(f"\n🔬 POTENTIAL ZERO-DAY CANDIDATES ({len(zero_day)}):")
        for r in zero_day[:5]:
            print(f"    {r['sha256_hash'][:32]}... - NOT IN ANY DATABASE")
        if len(zero_day) > 5:
            print(f"    ... and {len(zero_day) - 5} more")
    
    print(f"\n✅ Data ready in Elasticsearch index: {INDEX_NAME}")
    print("✅ Go to Kibana and create your malware dashboard!")

# ============================================================
# MAIN FUNCTION
# ============================================================

def main():
    print("=" * 60)
    print("DIONAEA VIRUSTOTAL INTEGRATION - COMPLETE")
    print("=" * 60)
    
    # Check API key
    if not VT_API_KEY:
        print("\n[!] ERROR: No VirusTotal API key found!")
        print("\n    Create a .env file with:")
        print("    VT_API_KEY=your_api_key_here")
        print("\n    Get your key from: https://www.virustotal.com/gui/my-apikey")
        return
    
    print(f"[✓] API Key loaded")
    
    # Get hashes
    print("\n[1/4] Getting hashes from Dionaea...")
    hashes = get_hashes_from_dionaea(limit=20)  # Change limit to 10 for faster test
    
    if not hashes:
        print("[!] No hashes found. Make sure Dionaea has captured files.")
        return
    
    print(f"[✓] Found {len(hashes)} hashes to check")
    
    # Query VirusTotal
    print("\n[2/4] Querying VirusTotal API...")
    print(f"    (Rate limited: 4 requests/minute = {REQUEST_DELAY}s delay)\n")
    
    results = []
    
    for i, file_hash in enumerate(hashes, 1):
        print(f"  [{i}/{len(hashes)}] {file_hash[:32]}...", end=" ")
        
        vt_data = query_virustotal(file_hash)
        intel = parse_vt_response(vt_data, file_hash)
        results.append(intel)
        
        if intel['is_malicious']:
            print(f"✅ MALICIOUS ({intel['malicious_count']} engines)")
        elif intel['severity'] == 'UNKNOWN':
            print(f"❓ NOT IN DATABASE (zero-day candidate)")
        else:
            print(f"⭕ CLEAN")
        
        if i < len(hashes):
            time.sleep(REQUEST_DELAY)
    
    # Push to Elasticsearch
    print("\n[3/4] Pushing to Elasticsearch...")
    push_to_elasticsearch(results)
    
    # Create index pattern
    print("\n[4/4] Setting up Kibana...")
    create_kibana_index_pattern()
    
    # Print summary
    print_summary(results)
    
    print("\n" + "=" * 60)
    print("NEXT STEPS:")
    print("=" * 60)
    print("1. Go to Kibana: http://localhost:5601")
    print("2. Stack Management → Index Patterns → dionaea-malware-intel*")
    print("3. Dashboard → Create dashboard → Add panel")
    print("4. Add your malware panels!")

if __name__ == "__main__":
    main()