# Honeypot-AI

A machine learning pipeline that ingests raw logs from two honeypots — Cowrie (SSH) and Dionaea (malware) — extracts session-level features, and detects anomalous/attack behavior using IsolationForest (unsupervised). No labels needed. Results are pushed to Elasticsearch and visualized in Kibana dashboards.

---

## Setup

```bash
git clone https://github.com/HajarBoulmane/honeypot-ai.git
cd honeypot-ai
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Create `.env` file:
```
ELASTIC_HOST=http://localhost:9200
ELASTIC_USER=elastic
ELASTIC_PASSWORD=honeypot123
```

Start Kibana and Elasticsearch:
```bash
cd docker && docker-compose up -d && cd ..
```

Push data and import dashboards:
```bash
bash docker/setup_kibana.sh
```

Open `http://localhost:5601` → Analytics → Dashboard

---


