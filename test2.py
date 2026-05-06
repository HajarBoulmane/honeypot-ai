from elasticsearch import Elasticsearch
from datetime import datetime, timezone
import random
import time

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
ES_HOST = "http://localhost:9200"
INDEX = "dionaea-logs"

es = Elasticsearch(ES_HOST)

# ─────────────────────────────────────────────
# SAMPLE DATA
# ─────────────────────────────────────────────
IPS = [
    "1.1.1.1",
    "8.8.8.8",
    "185.220.101.10",
    "5.188.206.26",
    "103.124.104.50",
    "46.101.90.205"
]

FILE_TYPES = ["exe", "jar", "rar", "pdf", "doc", "unknown"]
SIGNATURES = ["trojan", "ransomware", "worm", "unknown", "botnet"]
PROTOCOLS = ["http", "ftp", "smtp"]

# ─────────────────────────────────────────────
# GENERATE ONE LOG
# ─────────────────────────────────────────────
def generate_log():
    return {
        "source_ip": random.choice(IPS),
        "file_type": random.choice(FILE_TYPES),
        "mime_type": "application/octet-stream",
        "protocol": random.choice(PROTOCOLS),
        "signature": random.choice(SIGNATURES),
        "malware_reporter": "vt",
        "vtpercent": random.randint(0, 100),
        "sha256_hash": "fakehash_" + str(random.randint(1000, 9999)),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_id": str(random.randint(100000, 999999))
    }

# ─────────────────────────────────────────────
# SEND LOGS
# ─────────────────────────────────────────────
def run(n=20, delay=0.5):
    print("[*] Injecting logs into Dionaea index...")

    for i in range(n):
        doc = generate_log()

        res = es.index(index=INDEX, document=doc)

        print(f"[{i+1}/{n}] sent → {doc['source_ip']} | {doc['signature']} | ES={res['result']}")

        time.sleep(delay)

    print("✔ Done injecting logs.")

# ─────────────────────────────────────────────
if __name__ == "__main__":
    run()