"""
predict.py — Cowrie FINAL FIX (stable + correct scoring)
"""

import os
import time
import joblib
import pandas as pd
from datetime import datetime, timezone
from collections import defaultdict
from elasticsearch import Elasticsearch

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
ES_HOST = "http://localhost:9200"
SOURCE_INDEX = "cowrie-logs"
TARGET_INDEX = "cowrie-alerts"
POLL_SECONDS = 5

MODEL_PATH = "models/cowrie_model.pkl"
SCALER_PATH = "models/cowrie_scaler.pkl"
FEATURES_PATH = "models/feature_columns.pkl"

es = Elasticsearch(ES_HOST)

# ─────────────────────────────────────────────
# LOAD MODEL
# ─────────────────────────────────────────────
model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
FEATURE_COLS = joblib.load(FEATURES_PATH)

# ─────────────────────────────────────────────
# STATE
# ─────────────────────────────────────────────
last_ts = None
ip_cmds = defaultdict(list)


# ─────────────────────────────────────────────
# CLEAN COMMANDS
# ─────────────────────────────────────────────
def clean_list(lst):
    return [
        str(x).strip()
        for x in lst
        if x is not None and str(x).strip().lower() != "nan" and str(x).strip() != ""
    ]


# ─────────────────────────────────────────────
# FETCH LOGS
# ─────────────────────────────────────────────
def fetch_logs():
    global last_ts

    query = {"match_all": {}} if not last_ts else {
        "range": {"timestamp": {"gt": last_ts}}
    }

    res = es.search(
        index=SOURCE_INDEX,
        size=500,
        sort=[{"timestamp": "asc"}],
        query=query
    )

    logs = [h["_source"] for h in res["hits"]["hits"]]

    if logs:
        last_ts = logs[-1]["timestamp"]

    return logs


# ─────────────────────────────────────────────
# BUILD FEATURES (IMPORTANT FIX HERE)
# ─────────────────────────────────────────────
def build_features(g, ip):

    return {
        "total_events": len(g),
        "unique_sessions": g["session_id"].nunique(),

        "failed_logins": (g["login_success"] == False).sum(),
        "success_logins": (g["login_success"] == True).sum(),

        "unique_usernames": g["username"].nunique(),
        "unique_passwords": g["password"].nunique(),

        "unique_dst_ports": g["dst_port"].nunique(),
        "unique_protocols": g["protocol"].nunique(),

        "commands_executed": len(ip_cmds[ip]),

        "files_downloaded": (g["file_downloaded"] != "").sum(),
        "c2_connections": (g["c2_ip"] != "").sum(),
        "has_payload": g["sha256_payload"].notna().sum(),

        "avg_session_duration": g["session_duration_sec"].mean(),

        "total_bytes_sent": g["bytes_sent"].sum(),
        "total_bytes_received": g["bytes_received"].sum(),

        "high_severity_events": (g["severity"] == "high").sum(),
        "medium_severity_events": (g["severity"] == "medium").sum(),

        "unique_mitre_techniques": g["mitre_technique_id"].nunique(),
        "unique_attack_types": g["attack_type"].nunique(),

        "compromised_count": (g["alert_tag"] == "compromised_login").sum(),

        # derived (same logic as training)
        "fail_rate": (g["login_success"] == False).sum() / (len(g) + 1),
        "success_rate": (g["login_success"] == True).sum() / (len(g) + 1),

        "user_reuse_ratio": 1 - (g["username"].nunique() / ((g["login_success"] == False).sum() + 1)),

        "cmd_per_session": len(ip_cmds[ip]) / (g["session_id"].nunique() + 1),

        "bytes_ratio": g["bytes_sent"].sum() / (g["bytes_received"].sum() + 1),

        "threat_score": (
            (g["severity"] == "high").sum() * 2 +
            (g["severity"] == "medium").sum()
        ) / (len(g) + 1),

        "connection_rate": len(g),
        "burst_score": len(g) / (g["session_id"].nunique() + 1),
    }


# ─────────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────────
def run():

    logs = fetch_logs()
    if not logs:
        return

    df = pd.DataFrame(logs)

    for ip, g in df.groupby("src_ip"):

        # ── COMMAND CLEANING ──
        for _, r in g.iterrows():
            cmd = r.get("command")
            if cmd:
                ip_cmds[ip].append(cmd)

        ip_cmds[ip] = clean_list(ip_cmds[ip])

        # ── FEATURE BUILD ──
        features = build_features(g, ip)

        X = pd.DataFrame([features]).reindex(columns=FEATURE_COLS, fill_value=0)

        Xs = scaler.transform(X)
        score = float(-model.score_samples(Xs)[0])

        label = "attacker" if score > 0.61 else "normal"

        alert = {
            "src_ip": ip,
            "label": label,
            "score": score,
            "commands": ip_cmds[ip],
            "unique_commands": len(set(ip_cmds[ip])),
            "@timestamp": datetime.now(timezone.utc).isoformat()
        }

        es.index(index=TARGET_INDEX, document=alert)

        print(f"{ip} → {label} {score:.4f}")


# ─────────────────────────────────────────────
# LOOP
# ─────────────────────────────────────────────
print("[*] Predicting SOC engine running...")

while True:
    try:
        run()
    except Exception as e:
        print("[ERR]", e)

    time.sleep(POLL_SECONDS)