import pandas as pd

df = pd.read_csv("data/dionaea/raw/dionaea_raw.csv")

print("Shape:", df.shape)
print("Columns:", df.columns.tolist())
print(df.head())

# keep only useful columns
df = df[[
    'timestamp',
    'source_ip',
    'protocol',
    'file_type',    
    'mime_type',
    'signature',
    'vtpercent'
]]

# clean up
df['timestamp']  = pd.to_datetime(df['timestamp'], errors='coerce')
df['signature']  = df['signature'].fillna('unknown')
df['vtpercent']  = pd.to_numeric(df['vtpercent'], errors='coerce').fillna(0)
df['file_type']  = df['file_type'].fillna('unknown')
df['protocol']   = df['protocol'].fillna('unknown')

print("\nAfter cleaning:")
print(df.shape)
print(df['file_type'].value_counts())
print(df['protocol'].value_counts())

df.to_csv("/home/hajar/Downloads/honeypot-ai/data/dionaea/processed/dionaea_sessions.csv", index=False)
print("Saved.")