import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

input_file = "data/cowrie/processed/features.csv"
output_file = "data/cowrie/predictions/predictions.csv"

df = pd.read_csv(input_file)

feature_cols = [
    'commands_count',
    'unique_commands',
    'failed_logins',
    'success_login',
    'usernames_count',
    'passwords_count',
    'duration_proxy',
    'fail_rate',
    'pwd_per_user',
    'is_silent',
    'long_idle'
]

X = df[feature_cols]

# -----------------------------
# SCALE
# -----------------------------
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# -----------------------------
# MODEL
# -----------------------------
iso = IsolationForest(
    contamination=0.2,
    n_estimators=100,
    random_state=42
)

iso.fit(X_scaled)

# -----------------------------
# PREDICTIONS
# -----------------------------
df['anomaly_score'] = -iso.score_samples(X_scaled)
df['is_bot'] = (iso.predict(X_scaled) == -1).astype(int)

print("Bots detected:", df['is_bot'].sum())

df.to_csv(output_file, index=False)

print("✔ Predictions saved")