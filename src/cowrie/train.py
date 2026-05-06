import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import joblib

FEATURES_CSV = "data/cowrie/processed/cowrie_features.csv"

MODEL_PATH = "models/cowrie_model.pkl"
SCALER_PATH = "models/cowrie_scaler.pkl"
FEATURES_PATH = "models/feature_columns.pkl"

os.makedirs("models", exist_ok=True)

FEATURE_COLS = [
    "total_events","unique_sessions","failed_logins","success_logins",
    "unique_usernames","unique_passwords","unique_dst_ports","unique_protocols",
    "commands_executed","files_downloaded","c2_connections","has_payload",
    "avg_session_duration","total_bytes_sent","total_bytes_received",
    "high_severity_events","medium_severity_events",
    "unique_mitre_techniques","unique_attack_types","compromised_count",
    "fail_rate","success_rate","user_reuse_ratio","cmd_per_session",
    "bytes_ratio","threat_score","connection_rate","burst_score"
]


def make_normal(n=1500):
    rng = np.random.default_rng(42)

    return pd.DataFrame({
        "total_events": rng.integers(1, 10, n),
        "unique_sessions": rng.integers(1, 4, n),
        "failed_logins": rng.integers(0, 2, n),
        "success_logins": rng.integers(1, 3, n),

        "unique_usernames": rng.integers(1, 3, n),
        "unique_passwords": rng.integers(1, 3, n),

        "unique_dst_ports": rng.integers(1, 2, n),
        "unique_protocols": np.ones(n),

        "commands_executed": rng.integers(0, 3, n),

        "files_downloaded": np.zeros(n),
        "c2_connections": np.zeros(n),
        "has_payload": np.zeros(n),

        "avg_session_duration": rng.uniform(30, 300, n),

        "total_bytes_sent": rng.uniform(500, 10000, n),
        "total_bytes_received": rng.uniform(500, 10000, n),

        "high_severity_events": np.zeros(n),
        "medium_severity_events": rng.integers(0, 2, n),

        "unique_mitre_techniques": np.zeros(n),
        "unique_attack_types": np.zeros(n),
        "compromised_count": np.zeros(n),

        "fail_rate": rng.uniform(0, 0.4, n),
        "success_rate": rng.uniform(0.5, 1.0, n),
        "user_reuse_ratio": rng.uniform(0, 0.3, n),

        "cmd_per_session": rng.uniform(0, 2, n),
        "bytes_ratio": rng.uniform(0.5, 2, n),

        "threat_score": rng.uniform(0, 0.2, n),

        "connection_rate": rng.uniform(0.1, 5, n),
        "burst_score": rng.uniform(0, 0.3, n),
    })


def train():

    df_attack = pd.read_csv(FEATURES_CSV)

    df_normal = make_normal()

    df_attack["_label"] = 1
    df_normal["_label"] = 0

    df = pd.concat([df_attack, df_normal], ignore_index=True)

    X = df[FEATURE_COLS].fillna(0)

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(Xs)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(FEATURE_COLS, FEATURES_PATH)

    print("[✔] Model trained")


if __name__ == "__main__":
    train()