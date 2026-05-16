#!/usr/bin/env python3
"""
COMPLETE ZERO-DAY HUNTER
Finds, analyzes, and reports zero-day malware candidates
"""

import os
import subprocess
import requests
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

def find_new_hashes():
    """Find hashes not yet checked"""
    
    # Get all hashes from raw data
    df = pd.read_csv("data/dionaea/raw/dionaea_raw.csv")
    all_hashes = set(df['sha256_hash'].dropna().unique())
    all_hashes = {h for h in all_hashes if h != "" and len(str(h)) > 10}
    
    # Get already checked hashes
    checked_file = "data/dionaea/processed/checked_hashes.txt"
    checked = set()
    
    if os.path.exists(checked_file):
        with open(checked_file, 'r') as f:
            checked = set(line.strip() for line in f)
    
    new_hashes = all_hashes - checked
    return list(new_hashes), checked

def check_vt_status(file_hash):
    """Quick check if hash exists in VT"""
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    
    try:
        r = requests.get(url, headers=headers, timeout=30)
        return r.status_code == 200
    except:
        return False

def save_checked_hash(file_hash):
    """Save hash to checked list"""
    with open("data/dionaea/processed/checked_hashes.txt", "a") as f:
        f.write(f"{file_hash}\n")

def main():
    print("=" * 60)
    print("ZERO-DAY HUNTER")
    print("=" * 60)
    
    new_hashes, checked = find_new_hashes()
    
    print(f"[*] Total hashes: {len(checked) + len(new_hashes)}")
    print(f"[*] Already checked: {len(checked)}")
    print(f"[*] New hashes to check: {len(new_hashes)}")
    
    if not new_hashes:
        print("\n[✓] No new hashes! All have been checked.")
        return
    
    zero_days = []
    
    print("\n[*] Checking new hashes against VirusTotal...\n")
    
    for i, h in enumerate(new_hashes[:10], 1):  # Check first 10
        print(f"[{i}/10] {h[:32]}...", end=" ")
        
        found = check_vt_status(h)
        save_checked_hash(h)
        
        if not found:
            zero_days.append(h)
            print("🔴 ZERO-DAY CANDIDATE!")
        else:
            print("✅ Known file")
    
    # Results
    print("\n" + "=" * 60)
    if zero_days:
        print(f"🔴 FOUND {len(zero_days)} ZERO-DAY CANDIDATES!")
        print("=" * 60)
        for h in zero_days:
            print(f"\n  Hash: {h}")
            print(f"  Action: Extract and submit to VirusTotal")
    else:
        print("✅ No zero-day candidates found in this batch")
    
    print(f"\n[*] Checked {len(new_hashes[:10])} new hashes")
    print(f"[*] Total checked: {len(checked) + len(new_hashes[:10])}")

if __name__ == "__main__":
    main()