# Honeypot AI SOC (Cowrie + Dionaea + ELK)

Lightweight SOC pipeline for detecting attacks using honeypots and machine learning.

## 🚀 Stack

* Cowrie (SSH honeypot)
* Dionaea (malware honeypot)
* Elasticsearch + Kibana (SIEM)
* Python (feature engineering + ML)

## ⚙️ Features

* Real-time log ingestion (Elastic)
* Per-IP behavioral analysis
* Anomaly detection (Isolation Forest)
* Alerts indexed to Kibana dashboards

## 📊 Dashboards

* Cowrie: SSH attacks, commands, brute force
* Dionaea: malware uploads, VT scores, risk metrics

## ▶️ Run

```bash
docker compose up -d
```

## 📁 Structure

* `src/` → ML + pipelines
* `docker/` → ELK stack
* `dashboards/` → exported Kibana dashboards

## 👨‍💻 Author

Hajar Boulmane
