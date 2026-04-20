import json
import pandas as pd
from collections import defaultdict

input_file = "data/cowrie/raw/cowrie_raw.json"
output_file = "data/cowrie/processed/sessions.csv"

sessions = defaultdict(lambda: {
    "commands": [],
    "usernames": set(),
    "passwords": set(),
    "failed_logins": 0,
    "success_login": 0,
    "timestamps": []
})

# -----------------------------
# LOAD FILE
# -----------------------------
with open(input_file, "r") as f:
    data = json.load(f)

# -----------------------------
# PROCESS DATA
# -----------------------------
for entry in data:
    for session_id, events in entry.items():

        s = sessions[session_id]

        for event in events:
            eventid = event.get("eventid")

            if event.get("timestamp"):
                s["timestamps"].append(event["timestamp"])

            cmd = event.get("input")
            if cmd:
                s["commands"].append(cmd)

            if event.get("username"):
                s["usernames"].add(event["username"])

            if event.get("password"):
                s["passwords"].add(event["password"])

            if eventid == "cowrie.login.failed":
                s["failed_logins"] += 1

            if eventid == "cowrie.login.success":
                s["success_login"] = 1

# -----------------------------
# BUILD CSV
# -----------------------------
rows = []

for session_id, s in sessions.items():
    rows.append({
        "session_id": session_id,
        "commands_count": len(s["commands"]),
        "unique_commands": len(set(s["commands"])),
        "failed_logins": s["failed_logins"],
        "success_login": s["success_login"],
        "usernames_count": len(s["usernames"]),
        "passwords_count": len(s["passwords"]),
        "duration_proxy": len(s["timestamps"])
    })

df = pd.DataFrame(rows)
df.to_csv(output_file, index=False)

print("✔ Sessions created:", len(df))