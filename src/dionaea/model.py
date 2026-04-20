import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

df = pd.read_csv("data/dionaea/processed/dionaea_features.csv")

feature_cols = [
    'total_uploads',
    'unique_file_types',
    'unique_protocols',
    'unique_signatures',
    'avg_vtpercent',
    'max_vtpercent',
    'known_malware',
    'malware_ratio'
]

X = df[feature_cols]

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

iso = IsolationForest(
    contamination=0.2,
    n_estimators=100,
    random_state=42
)
iso.fit(X_scaled)

df['anomaly_score'] = -iso.score_samples(X_scaled)
df['is_bot']        = (iso.predict(X_scaled) == -1).astype(int)

print("=== TOP 20 MOST SUSPICIOUS IPs ===")
print(df[df['is_bot'] == 1].sort_values('anomaly_score', ascending=False).head(20).to_string())

print("\n=== NORMAL IPs (sample) ===")
print(df[df['is_bot'] == 0].sort_values('anomaly_score').head(10).to_string())

print(f"\nTotal flagged: {df['is_bot'].sum()} / {len(df)}")

df.to_csv("data/dionaea/predictions/predictions.csv", index=False)
print("Saved to predictions.csv")