"""
predict.py — Dionaea
Polls dionaea-logs from Elasticsearch -> extracts features per source_ip ->
loads trained model -> predicts -> pushes to dionaea-alerts.

Changes vs original:
  - Per-IP sliding window buffer (deque maxlen=50)
  - Poll loop runs in a daemon thread — terminal stays free
  - SCORE_THRESHOLD overrides model label — tune via env var
  - Rolling local alert history (last 500) saved to JSONL file

Usage:
    python src/dionaea/predict.py
"""

import os
import json
import time
import threading
import statistics
import joblib
import pandas as pd
from datetime import datetime, timezone
from collections import defaultdict, deque
from elasticsearch import Elasticsearch

ES_HOST          = os.getenv("ES_HOST",          "http://localhost:9200")
SOURCE_INDEX     = os.getenv("SOURCE_INDEX",     "dionaea-logs")
TARGET_INDEX     = os.getenv("TARGET_INDEX",     "dionaea-alerts")
POLL_SECONDS     = int(os.getenv("POLL_SECONDS",     "5"))
WINDOW_SIZE      = int(os.getenv("WINDOW_SIZE",      "50"))
SCORE_THRESHOLD  = float(os.getenv("SCORE_THRESHOLD", "0.64"))
ALERTS_FILE      = os.getenv("ALERTS_FILE",      "data/dionaea/alerts/alerts.jsonl")
MAX_ALERTS       = int(os.getenv("MAX_ALERTS",       "500"))

MODEL_PATH  = "models/dionaea_model.pkl"
SCALER_PATH = "models/dionaea_scaler.pkl"

FEATURE_COLS = [
    "total_uploads",
    "unique_file_types",
    "unique_mime_types",
    "unique_protocols",
    "unique_signatures",
    "unique_reporters",
    "avg_vtpercent",
    "max_vtpercent",
    "known_malware",
    "files_with_hash",
    "exe_uploads",
    "jar_uploads",
    "rar_uploads",
    "malware_ratio",
    "hash_ratio",
    "high_risk_uploads",
    "suspicious_activity",
    "exe_ratio",
    "upload_rate",
    "burst_score",
]

print("[*] Loading Dionaea model ...")
model  = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
print("[OK] Model ready")
print(f"[*] Score threshold: {SCORE_THRESHOLD}")

es = Elasticsearch(ES_HOST)

# Global state
last_timestamp: str | None = None
ip_buffers: dict[str, deque] = defaultdict(lambda: deque(maxlen=WINDOW_SIZE))

# Rolling alert history — load from disk on startup
os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)
alert_history: deque = deque(maxlen=MAX_ALERTS)
if os.path.exists(ALERTS_FILE):
    with open(ALERTS_FILE) as f:
        for line in f:
            try:
                alert_history.append(json.loads(line))
            except Exception:
                pass
    print(f"[*] Loaded {len(alert_history)} existing alerts from {ALERTS_FILE}")


def save_alert(alert: dict):
    """Append alert to in-memory deque and rewrite JSONL file."""
    alert_history.append(alert)
    with open(ALERTS_FILE, "w") as f:
        for a in alert_history:
            f.write(json.dumps(a) + "\n")


def extract_features(logs: list) -> dict:
    """Mirror dionaea/features.py logic on raw ES log dicts."""
    total = len(logs)

    file_types = [l.get("file_type",        "unknown") for l in logs]
    mime_types = [l.get("mime_type",        "unknown") for l in logs]
    protocols  = [l.get("protocol",         "unknown") for l in logs]
    signatures = [l.get("signature",        "unknown") for l in logs]
    reporters  = [l.get("malware_reporter", "unknown") for l in logs]
    vtpcts     = [float(l.get("vtpercent", 0) or 0)   for l in logs]

    known_malware   = sum(1 for s in signatures if s and s != "unknown")
    files_with_hash = sum(1 for l in logs if l.get("sha256_hash"))
    exe_uploads     = sum(1 for t in file_types if t == "exe")
    jar_uploads     = sum(1 for t in file_types if t == "jar")
    rar_uploads     = sum(1 for t in file_types if t == "rar")
    avg_vt          = sum(vtpcts) / len(vtpcts) if vtpcts else 0
    max_vt          = max(vtpcts) if vtpcts else 0

    malware_ratio       = known_malware   / (total + 1)
    hash_ratio          = files_with_hash / (total + 1)
    high_risk_uploads   = int(max_vt > 70)
    suspicious_activity = malware_ratio + (avg_vt / 100)
    exe_ratio           = exe_uploads / (total + 1)

    # Time features
    try:
        ts_list = sorted(
            datetime.fromisoformat(l["timestamp"].replace("Z", "+00:00"))
            for l in logs if l.get("timestamp")
        )
        duration_min = max((ts_list[-1] - ts_list[0]).total_seconds() / 60, 1) if len(ts_list) > 1 else 1
        upload_rate  = total / duration_min
        gaps         = [(ts_list[i + 1] - ts_list[i]).total_seconds() for i in range(len(ts_list) - 1)]
        burst_score  = 1 / (statistics.stdev(gaps) + 1) if len(gaps) > 1 else 0
    except Exception:
        upload_rate = total
        burst_score = 0

    return {
        "total_uploads":       total,
        "unique_file_types":   len(set(file_types)),
        "unique_mime_types":   len(set(mime_types)),
        "unique_protocols":    len(set(protocols)),
        "unique_signatures":   len(set(signatures)),
        "unique_reporters":    len(set(reporters)),
        "avg_vtpercent":       round(avg_vt, 4),
        "max_vtpercent":       round(max_vt, 4),
        "known_malware":       known_malware,
        "files_with_hash":     files_with_hash,
        "exe_uploads":         exe_uploads,
        "jar_uploads":         jar_uploads,
        "rar_uploads":         rar_uploads,
        "malware_ratio":       round(malware_ratio, 4),
        "hash_ratio":          round(hash_ratio, 4),
        "high_risk_uploads":   high_risk_uploads,
        "suspicious_activity": round(suspicious_activity, 4),
        "exe_ratio":           round(exe_ratio, 4),
        "upload_rate":         round(upload_rate, 4),
        "burst_score":         round(burst_score, 4),
    }


def predict_features(features: dict) -> tuple[str, float]:
    X        = pd.DataFrame([features])[FEATURE_COLS].fillna(0)
    X_scaled = scaler.transform(X)
    score    = float(-model.score_samples(X_scaled)[0])
    label    = "malicious" if score >= SCORE_THRESHOLD else "normal"
    return label, round(score, 4)


def fetch_new_logs() -> list:
    global last_timestamp
    query = (
        {"range": {"timestamp": {"gt": last_timestamp}}}
        if last_timestamp else {"match_all": {}}
    )
    res = es.search(
        index=SOURCE_INDEX,
        body={"size": 1000, "sort": [{"timestamp": "asc"}], "query": query},
    )
    return res["hits"]["hits"]


def push_alert(src_ip: str, label: str, score: float, features: dict):
    alert = {
        "source_ip":     src_ip,
        "honeypot":      "dionaea",
        "prediction":    label,
        "anomaly_score": score,
        **features,
        "@timestamp":    datetime.now(timezone.utc).isoformat(),
    }
    es.index(index=TARGET_INDEX, document=alert)
    save_alert(alert)


def run():
    global last_timestamp

    hits = fetch_new_logs()
    if not hits:
        return

    latest_ts: str | None = last_timestamp
    seen_ips: set[str]    = set()

    for hit in hits:
        src = hit["_source"]
        ip  = src.get("source_ip", "unknown")
        ip_buffers[ip].append(src)
        seen_ips.add(ip)
        ts = src.get("timestamp")
        if ts and (latest_ts is None or ts > latest_ts):
            latest_ts = ts

    for ip in seen_ips:
        logs         = list(ip_buffers[ip])
        features     = extract_features(logs)
        label, score = predict_features(features)
        push_alert(ip, label, score, features)

        flag = "MALICIOUS" if label == "malicious" else "normal   "
        print(
            f"  [{flag}]  {ip:20s}  score={score:.4f}"
            f"  uploads={features['total_uploads']} (window={len(logs)})"
            f"  malware={features['known_malware']}"
            f"  vt_max={features['max_vtpercent']:.1f}%"
        )

    last_timestamp = latest_ts
    print(f"[->] {len(hits)} events | {len(seen_ips)} IPs | last_ts={last_timestamp}")


def poll_loop():
    print(f"[*] Dionaea predict loop  (poll every {POLL_SECONDS}s, window={WINDOW_SIZE} logs/IP)")
    while True:
        try:
            run()
        except Exception as e:
            print(f"[!] Error: {e}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    t = threading.Thread(target=poll_loop, daemon=True)
    t.start()
    print("[*] Predict loop running in background — terminal is free.")
    print("[*] Press Ctrl+C to stop.")
    try:
        t.join()
    except KeyboardInterrupt:
        print("\n[*] Stopped.")