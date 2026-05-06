"""
features.py — Dionaea
Reads raw Dionaea CSV → engineers features per source_ip → saves to processed CSV.

Real columns:
    timestamp, source_ip, destination_ip, protocol, honeypot, identifier,
    sha256_hash, md5_hash, sha1_hash, file_name, file_type, mime_type,
    signature, malware_reporter, vtpercent, source_honeypot, source_hashes

Usage:
    python src/dionaea/features.py
"""

import os
import pandas as pd

RAW_CSV = "data/dionaea/raw/dionaea_raw.csv"
OUT_CSV = "data/dionaea/processed/dionaea_features.csv"

os.makedirs("data/dionaea/processed", exist_ok=True)


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    # ── Clean ──────────────────────────────────────────────────────────────────
    df["timestamp"]        = pd.to_datetime(df["timestamp"], errors="coerce")
    df["source_ip"]        = df["source_ip"].fillna("0.0.0.0")
    df["signature"]        = df["signature"].fillna("unknown")
    df["file_type"]        = df["file_type"].fillna("unknown")
    df["mime_type"]        = df["mime_type"].fillna("unknown")
    df["protocol"]         = df["protocol"].fillna("unknown")
    df["malware_reporter"] = df["malware_reporter"].fillna("unknown")
    df["vtpercent"]        = pd.to_numeric(df["vtpercent"], errors="coerce").fillna(0)
    df["has_sha256"]       = df["sha256_hash"].notna().astype(int)
    df["has_signature"]    = (df["signature"] != "unknown").astype(int)

    # ── Base aggregation per source_ip ─────────────────────────────────────────
    features = df.groupby("source_ip").agg(
        total_uploads       = ("file_type",        "count"),
        unique_file_types   = ("file_type",        "nunique"),
        unique_mime_types   = ("mime_type",        "nunique"),
        unique_protocols    = ("protocol",         "nunique"),
        unique_signatures   = ("signature",        "nunique"),
        unique_reporters    = ("malware_reporter", "nunique"),
        avg_vtpercent       = ("vtpercent",        "mean"),
        max_vtpercent       = ("vtpercent",        "max"),
        known_malware       = ("has_signature",    "sum"),
        files_with_hash     = ("has_sha256",       "sum"),
        exe_uploads         = ("file_type",        lambda x: (x == "exe").sum()),
        jar_uploads         = ("file_type",        lambda x: (x == "jar").sum()),
        rar_uploads         = ("file_type",        lambda x: (x == "rar").sum()),
    ).reset_index()

    # ── Derived features ───────────────────────────────────────────────────────
    total = features["total_uploads"]
    features["malware_ratio"]       = features["known_malware"]   / (total + 1)
    features["hash_ratio"]          = features["files_with_hash"] / (total + 1)
    features["high_risk_uploads"]   = (features["max_vtpercent"] > 70).astype(int)
    features["suspicious_activity"] = (
        features["malware_ratio"] + (features["avg_vtpercent"] / 100)
    )
    features["exe_ratio"]           = features["exe_uploads"] / (total + 1)

    # ── Time-based: upload rate + burst ───────────────────────────────────────
    def time_features(group):
        ts = group["timestamp"].dropna().sort_values()
        if len(ts) < 2:
            return pd.Series({"upload_rate": 0.0, "burst_score": 0.0})
        duration_minutes = max((ts.iloc[-1] - ts.iloc[0]).total_seconds() / 60, 1)
        rate  = len(ts) / duration_minutes
        gaps  = ts.diff().dt.total_seconds().dropna()
        burst = 1 / (gaps.std() + 1)
        return pd.Series({"upload_rate": round(rate, 4), "burst_score": round(burst, 4)})

    time_feats = df.groupby("source_ip").apply(time_features).reset_index()
    features   = features.merge(time_feats, on="source_ip", how="left")
    features[["upload_rate", "burst_score"]] = (
        features[["upload_rate", "burst_score"]].fillna(0)
    )

    return features


def main():
    print("[*] Loading raw Dionaea data from:", RAW_CSV)
    df = pd.read_csv(RAW_CSV)
    print(f"    {len(df):,} raw rows | {df['source_ip'].nunique():,} unique IPs")

    features = build_features(df)
    features.to_csv(OUT_CSV, index=False)

    print(f"[✔] Dionaea features saved → {OUT_CSV}")
    print(f"    {len(features):,} IP rows | {len(features.columns)} feature columns")
    print(f"    Columns: {list(features.columns)}")


if __name__ == "__main__":
    main()