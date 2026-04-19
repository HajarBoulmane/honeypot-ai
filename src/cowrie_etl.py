import json
import pandas as pd
from collections import defaultdict

input_file = "cowrie/logs/cowrie_raw.json"
output_file = "cowrie/logs/cowrie_sessions.csv"

sessions = defaultdict(lambda: {
    "commands": [],
    "usernames": set(),
    "passwords": set(),
    "failed_logins": 0,
    "success_login": 0,
    "timestamps": []
})

# -----------------------------
# 1. LOAD FILE (correct structure)
# -----------------------------
with open(input_file, "r") as f:
    data = json.load(f)   # IMPORTANT: your file is a JSON ARRAY, not JSONL

# -----------------------------
# 2. PROCESS DATA
# -----------------------------
for entry in data:
    for session_id, events in entry.items():

        s = sessions[session_id]

        for event in events:

            eventid = event.get("eventid")

            # timestamp
            if event.get("timestamp"):
                s["timestamps"].append(event["timestamp"])

            # commands (Cowrie uses "input")
            cmd = event.get("input")
            if cmd:
                s["commands"].append(cmd)

            # usernames/passwords
            if event.get("username"):
                s["usernames"].add(event["username"])

            if event.get("password"):
                s["passwords"].add(event["password"])

            # login events
            if eventid == "cowrie.login.failed":
                s["failed_logins"] += 1

            if eventid == "cowrie.login.success":
                s["success_login"] = 1

# -----------------------------
# 3. BUILD CSV
# -----------------------------
rows = []

for session_id, s in sessions.items():

    duration = len(s["timestamps"])

    rows.append({
        "session_id": session_id,
        "commands_count": len(s["commands"]),
        "unique_commands": len(set(s["commands"])),
        "failed_logins": s["failed_logins"],
        "success_login": s["success_login"],
        "usernames_count": len(s["usernames"]),
        "passwords_count": len(s["passwords"]),
        "duration_proxy": duration
    })

df = pd.DataFrame(rows)
df.to_csv(output_file, index=False)

print("Done ✔ Sessions:", len(df))