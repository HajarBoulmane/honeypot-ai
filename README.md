# Honeypot-AI — SSH Attack Detection with Machine Learning

A full ML pipeline that ingests raw Cowrie SSH honeypot logs, extracts session-level features, detects bot/attack sessions using IsolationForest, and visualizes results in a Kibana dashboard.

---

## Project Structure

```
honeypot-ai/
│
├── data/
│   └── cowrie/
│       ├── raw/
│       │   └── cowrie_raw.json          ← raw Cowrie logs (JSON array)
│       ├── processed/
│       │   ├── sessions.csv             ← output of ETL
│       │   └── features.csv            ← output of feature engineering
│       └── predictions/
│           └── predictions.csv          ← output of IsolationForest
│
├── src/
│   └── cowrie/
│       ├── etl/
│       │   ├── build_sessions.py        ← parses raw JSON → sessions CSV
│       │   └── labeling.py              ← creates heuristic bot_label
│       ├── features/
│       │   └── features.py              ← feature engineering + scaling
│       └── models/
│           ├── isolation_forest.py      ← unsupervised anomaly detection
│           └── random_forest.py         ← supervised classification (optional)
│
├── dashboards/                          ← Kibana dashboard exports
├── docker/                              ← docker configs (optional)
├── notebooks/                           ← Jupyter exploration notebooks
├── venv/                                ← Python virtual environment
├── requirements.txt
└── README.md
```

---

## How the Pipeline Works

```
cowrie_raw.json
      ↓
  [etl.py]         → parses sessions, extracts features
      ↓
  sessions.csv
      ↓
  [labeling.py]    → creates heuristic bot_label (for evaluation only)
      ↓
  labeled.csv
      ↓
  [features.py]    → engineers new features, scales data
      ↓
  features.csv
      ↓
  [isolation_forest.py]  → detects anomalies, outputs predictions
      ↓
  predictions.csv
      ↓
  [push_to_elastic.py]   → sends data to Elasticsearch
      ↓
  Kibana Dashboard        → visualizes attack patterns
```

---

## Features Used

| Feature | Description |
|---|---|
| `commands_count` | Total commands run in session |
| `unique_commands` | Number of distinct commands |
| `failed_logins` | Number of failed login attempts |
| `success_login` | Whether login succeeded (0 or 1) |
| `usernames_count` | Number of distinct usernames tried |
| `passwords_count` | Number of distinct passwords tried |
| `duration_proxy` | Session duration (event count proxy) |
| `fail_rate` | failed / (failed + success + 1) |
| `pwd_per_user` | passwords / (usernames + 1) |
| `is_silent` | logged in but ran zero commands |
| `long_idle` | successful login + long duration |

---

## Model — IsolationForest (Unsupervised)

We use IsolationForest because **we have no ground truth labels** for real bot sessions. The model finds anomalous sessions purely from feature distributions — no labels needed.

- Sessions that are **anomalous** (rare, unusual behavior) get flagged as bots
- `contamination=0.2` means we expect roughly 20% of sessions to be anomalous
- Output: `anomaly_score` (higher = more suspicious) and `is_bot` (0 or 1)

**What the model flags as bots:**
- Sessions with successful login but zero commands (`is_silent=1`)
- Long idle sessions with no activity (`long_idle=1`)
- Sessions with many password attempts across multiple usernames

**What the model considers normal:**
- Quick failed login attempts (common scanner background noise)
- Short sessions with single username/password attempt

---

## Setup — For Teammates

### 1. Clone the repo and create virtual environment

```bash
git clone <your-repo-url>
cd honeypot-ai
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the pipeline

```bash
# Step 1: ETL — parse raw logs into sessions
python -m src.cowrie.etl.build_sessions

# Step 2: Label sessions (heuristic rules)
python -m src.cowrie.etl.labeling

# Step 3: Feature engineering
python -m src.cowrie.features.features

# Step 4: Run IsolationForest
python -m src.cowrie.models.isolation_forest

# Step 5: Push to Elasticsearch
python -m src.cowrie.push_to_elastic
```

---

## Setup — Elasticsearch and Kibana

### Requirements
- Java is NOT needed (Elasticsearch 8 bundles its own JDK)
- At least 4GB RAM free
- Ubuntu/Debian Linux

### Step 1 — Download

```bash
cd ~
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.13.0-linux-x86_64.tar.gz
tar -xzf elasticsearch-8.13.0-linux-x86_64.tar.gz
cd elasticsearch-8.13.0

wget https://artifacts.elastic.co/downloads/kibana/kibana-8.13.0-linux-x86_64.tar.gz
tar -xzf kibana-8.13.0-linux-x86_64.tar.gz
```

### Step 2 — Start Elasticsearch (Terminal 1 — keep open)

```bash
cd ~/elasticsearch-8.13.0/elasticsearch-8.13.0
./bin/elasticsearch
```

Wait ~30 seconds until you see:
```
Cluster health status changed from [RED] to [GREEN]
```

On first run it will print:
```
Password for the elastic user: XXXXXXXXXX   ← COPY THIS
```

If you miss the password, reset it:
```bash
./bin/elasticsearch-reset-password -u elastic
```

### Step 3 — Verify Elasticsearch is running

```bash
curl -k -u elastic:YOUR_PASSWORD https://localhost:9200
```

You should see:
```json
{ "tagline": "You Know, for Search" }
```

### Step 4 — Generate Kibana enrollment token (Terminal 2)

```bash
cd ~/elasticsearch-8.13.0/elasticsearch-8.13.0
./bin/elasticsearch-create-enrollment-token -s kibana
```

Copy the token it prints.

### Step 5 — Start Kibana (Terminal 3 — keep open)

```bash
cd ~/elasticsearch-8.13.0/elasticsearch-8.13.0/kibana-8.13.0
./bin/kibana
```

Wait until you see:
```
Kibana is now available
```

### Step 6 — Open Kibana in browser

Go to: `http://localhost:5601`

- Paste the enrollment token when asked
- Enter the verification code shown in the Kibana terminal
- Log in with:
  - Username: `elastic`
  - Password: the one you copied in Step 2

### Step 7 — Push your data to Elasticsearch

```bash
pip install elasticsearch
python -m src.cowrie.push_to_elastic
```

### Step 8 — Build dashboard in Kibana

1. Go to `http://localhost:5601`
2. Click **Analytics → Discover** to verify your data is there
3. Click **Analytics → Dashboard → Create dashboard**
4. Add visualizations:
   - Bar chart: sessions by `is_bot`
   - Metric: total flagged sessions
   - Table: top suspicious sessions by `anomaly_score`
   - Histogram: `duration_proxy` distribution

---

## Requirements

```
pandas
numpy
scikit-learn
matplotlib
seaborn
elasticsearch
```

Install all:
```bash
pip install -r requirements.txt
```

---

## Important Notes

- The `bot_label` column created by `labeling.py` is based on heuristic rules — it is not ground truth. It is used only to roughly evaluate the model.
- IsolationForest does not need labels. It finds anomalies purely from the data distribution.
- `contamination=0.2` is a tunable parameter — if too many or too few sessions are flagged, adjust it between 0.05 and 0.5.
- All file paths in scripts use absolute paths for reliability. Update them to match your machine if needed.