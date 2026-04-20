import pandas as pd

input_file = "data/cowrie/processed/sessions.csv"
output_file = "data/cowrie/processed/features.csv"

df = pd.read_csv(input_file)

# -----------------------------
# FEATURE ENGINEERING
# -----------------------------
df['fail_rate'] = df['failed_logins'] / (df['failed_logins'] + df['success_login'] + 1)
df['pwd_per_user'] = df['passwords_count'] / (df['usernames_count'] + 1)
df['is_silent'] = ((df['commands_count'] == 0) & (df['success_login'] == 1)).astype(int)
df['long_idle'] = ((df['success_login'] == 1) & (df['duration_proxy'] > 30)).astype(int)

df.to_csv(output_file, index=False)

print("✔ Features created:", len(df))