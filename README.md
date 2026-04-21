# Honeypot-AI

Detects SSH attacks and malware drops from Cowrie and Dionaea honeypot logs using IsolationForest. Visualized in Kibana.

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
ELASTIC_HOST=http://localhost:9200
ELASTIC_USER=elastic
ELASTIC_PASSWORD=honeypot123

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

## Notes
- Ask the team for `cowrie_raw.json` and `dionaea_raw.csv` — place them in `data/cowrie/raw/` and `data/dionaea/raw/`
- Predictions are already committed — you can skip re-running the pipeline
- To re-run the pipeline check `src/cowrie/` and `src/dionaea/`
