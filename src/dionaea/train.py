"""
train.py — Dionaea
Reads processed features CSV → mixes in synthetic normal traffic →
trains IsolationForest → saves model + scaler.

Usage:
    python src/dionaea/train.py
    NORMAL_SAMPLES=1500 python src/dionaea/train.py
"""

import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import joblib

FEATURES_CSV   = "data/dionaea/processed/dionaea_features.csv"
MODEL_PATH     = "models/dionaea_model.pkl"
SCALER_PATH    = "models/dionaea_scaler.pkl"
PRED_CSV       = "data/dionaea/predictions/train_predictions.csv"
NORMAL_SAMPLES = int(os.getenv("NORMAL_SAMPLES", "1500"))

os.makedirs("models", exist_ok=True)
os.makedirs("data/dionaea/predictions", exist_ok=True)

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


def make_normal_traffic(n: int = 1500) -> pd.DataFrame:
    """
    Synthetic normal Dionaea traffic with realistic noise.
    Normal clients connect but don't upload malware —
    occasional benign files, no known signatures, low vtpercent.
    """
    rng = np.random.default_rng(42)
    return pd.DataFrame({
        # volume — normal clients make a few connections
        "total_uploads":       rng.integers(1, 8, n),
        # diversity — normal clients use 1-2 file/mime types
        "unique_file_types":   rng.integers(1, 3, n),
        "unique_mime_types":   rng.integers(1, 3, n),
        "unique_protocols":    rng.integers(1, 2, n),
        # signatures/reporters — normal traffic has none or very few
        "unique_signatures":   rng.integers(1, 2, n),
        "unique_reporters":    rng.integers(0, 2, n),
        # vt scores — normal files score low
        "avg_vtpercent":       rng.uniform(0.0, 15.0, n),
        "max_vtpercent":       rng.uniform(0.0, 25.0, n),
        # malware indicators — none for normal traffic
        "known_malware":       np.zeros(n),
        "files_with_hash":     rng.integers(0, 3, n),
        "exe_uploads":         rng.integers(0, 2, n),
        "jar_uploads":         np.zeros(n),
        "rar_uploads":         np.zeros(n),
        # derived — noisy but low
        "malware_ratio":       rng.uniform(0.0, 0.1, n),
        "hash_ratio":          rng.uniform(0.0, 0.4, n),
        "high_risk_uploads":   np.zeros(n),
        "suspicious_activity": rng.uniform(0.0, 0.15, n),
        "exe_ratio":           rng.uniform(0.0, 0.2, n),
        # time features
        "upload_rate":         rng.uniform(0.1, 4.0, n),
        "burst_score":         rng.uniform(0.0, 0.3, n),
    })


def train():
    print("[*] Loading Dionaea features from:", FEATURES_CSV)
    df_attack = pd.read_csv(FEATURES_CSV)

    missing = [c for c in FEATURE_COLS if c not in df_attack.columns]
    if missing:
        raise ValueError(f"Missing columns: {missing}")

    n_malicious = len(df_attack)
    print(f"[i] Malicious rows loaded: {n_malicious}")

    df_normal = make_normal_traffic(n=NORMAL_SAMPLES)
    df_normal["_label"] = "normal"
    df_attack["_label"] = "malicious"

    df = pd.concat([df_attack, df_normal], ignore_index=True)
    n_total = len(df)

    contamination = round(n_malicious / n_total, 4)
    contamination = max(0.01, min(contamination, 0.5))

    print(f"[i] Normal rows added:     {NORMAL_SAMPLES}")
    print(f"[i] Total rows:            {n_total}")
    print(f"[i] Contamination set to:  {contamination}")

    X = df[FEATURE_COLS].fillna(0)

    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print("[*] Training IsolationForest ...")
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
    )
    model.fit(X_scaled)

    df["anomaly_score"] = -model.score_samples(X_scaled)
    df["is_malicious"]  = (model.predict(X_scaled) == -1).astype(int)

    joblib.dump(model,  MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    df.to_csv(PRED_CSV, index=False)

    # Sanity check
    tp = ((df["_label"] == "malicious") & (df["is_malicious"] == 1)).sum()
    fp = ((df["_label"] == "normal")    & (df["is_malicious"] == 1)).sum()
    tn = ((df["_label"] == "normal")    & (df["is_malicious"] == 0)).sum()
    fn = ((df["_label"] == "malicious") & (df["is_malicious"] == 0)).sum()

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0

    print(f"\n[OK] Model  -> {MODEL_PATH}")
    print(f"[OK] Scaler -> {SCALER_PATH}")
    print(f"[OK] Train predictions -> {PRED_CSV}")
    print(f"\n[i] Confusion matrix (train set):")
    print(f"      TP={tp}  FP={fp}")
    print(f"      FN={fn}  TN={tn}")
    print(f"[i] Precision: {precision:.2f}  Recall: {recall:.2f}")

    # Score distribution to help tune SCORE_THRESHOLD in predict.py
    mal_scores = df.loc[df["_label"] == "malicious", "anomaly_score"]
    nrm_scores = df.loc[df["_label"] == "normal",    "anomaly_score"]
    print(f"\n[i] Anomaly score ranges:")
    print(f"      malicious → min={mal_scores.min():.4f}  mean={mal_scores.mean():.4f}  max={mal_scores.max():.4f}")
    print(f"      normal    → min={nrm_scores.min():.4f}  mean={nrm_scores.mean():.4f}  max={nrm_scores.max():.4f}")
    print(f"\n[i] Suggested SCORE_THRESHOLD: {(mal_scores.min() + nrm_scores.max()) / 2:.4f}")


if __name__ == "__main__":
    train()