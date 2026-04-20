import pandas as pd

df = pd.read_csv("data/dionaea/processed/dionaea_sessions.csv")

# engineer features per source IP
features = df.groupby('source_ip').agg(
    total_uploads       = ('file_type', 'count'),
    unique_file_types   = ('file_type', 'nunique'),
    unique_protocols    = ('protocol', 'nunique'),
    unique_signatures   = ('signature', 'nunique'),
    avg_vtpercent       = ('vtpercent', 'mean'),
    max_vtpercent       = ('vtpercent', 'max'),
    known_malware       = ('signature', lambda x: (x != 'unknown').sum()),
).reset_index()

# ratio of known malware uploads
features['malware_ratio'] = features['known_malware'] / features['total_uploads']

print("Features shape:", features.shape)
print(features.head(10).to_string())

features.to_csv("/home/hajar/Downloads/honeypot-ai/data/dionaea/processed/dionaea_features.csv", index=False)
print("Saved.")