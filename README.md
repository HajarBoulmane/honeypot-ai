# Honeypot-AI

An AI-powered honeypot system designed to collect, monitor, and analyze malicious network activity. The project combines multiple honeypots with the Elastic Stack for centralized log analysis and applies machine learning to identify anomalous attack behavior.

## Overview

The system deploys network honeypots to attract attackers and capture their activities. Collected logs are forwarded to Elasticsearch through Filebeat, visualized with Kibana, and analyzed using an Isolation Forest model to detect suspicious behaviors automatically.

## Features

- Deployment of Cowrie and Dionaea honeypots
- Centralized log collection with Filebeat
- Elasticsearch for log indexing and storage
- Kibana dashboards for attack visualization
- Machine learning-based anomaly detection using Isolation Forest
- Automated detection of abnormal attack patterns
- Cloud deployment using AWS EC2

## Architecture

```
Internet
      │
      ▼
+----------------+
| Honeypots      |
| Cowrie         |
| Dionaea        |
+----------------+
        │
        ▼
+----------------+
| Filebeat       |
+----------------+
        │
        ▼
+----------------+
| Elasticsearch  |
+----------------+
        │
        ▼
+----------------+
| Kibana         |
+----------------+
        │
        ▼
+---------------------------+
| Isolation Forest Model    |
| Anomaly Detection         |
+---------------------------+
```

## Technology Stack

| Category | Technologies |
|----------|--------------|
| Programming | Python |
| Honeypots | Cowrie, Dionaea |
| Log Collection | Filebeat |
| Data Storage | Elasticsearch |
| Visualization | Kibana |
| Machine Learning | Scikit-learn (Isolation Forest) |
| Data Processing | Pandas, NumPy |
| Cloud | AWS EC2 |

## Machine Learning Pipeline

1. Collect attack logs from deployed honeypots.
2. Parse and preprocess the collected events.
3. Extract relevant behavioral features.
4. Normalize the dataset.
5. Train an Isolation Forest model.
6. Detect anomalous attack activities.
7. Visualize detected events through Kibana dashboards.

## Project Structure

```
honeypot-ai/
├── data/
├── notebooks/
├── models/
├── scripts/
├── logs/
├── requirements.txt
└── README.md
```

## Getting Started

### Clone the repository

```bash
git clone https://github.com/HajarBoulmane/honeypot-ai.git
cd honeypot-ai
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run the analysis

```bash
python main.py
```

## Learning Objectives

This project demonstrates practical experience with:

- Cybersecurity monitoring
- Honeypot deployment
- Threat intelligence
- Log aggregation and analysis
- Machine learning for anomaly detection
- ELK Stack
- AWS cloud deployment
