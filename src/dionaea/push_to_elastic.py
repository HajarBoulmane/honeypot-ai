"""
push_to_elastic.py — Dionaea
Reads train predictions CSV → pushes each row to dionaea-predictions index in ES.
Run after train.py to make training results visible in Kibana.

Usage:
    python src/dionaea/push_to_elastic.py
"""

import os
import math
import pandas as pd
from datetime import datetime, timezone
from elasticsearch import Elasticsearch, helpers

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
INDEX   = os.getenv("DIONAEA_PRED_INDEX", "dionaea-predictions")
CSV     = "data/dionaea/predictions/train_predictions.csv"

es = Elasticsearch(ES_HOST)


def clean(val):
    if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
        return None
    return val


def push():
    print(f"[*] Loading predictions from: {CSV}")
    df = pd.read_csv(CSV)
    print(f"    {len(df):,} rows | malicious: {df['is_malicious'].sum()}")

    actions = []
    for _, row in df.iterrows():
        doc = {c: clean(row[c]) for c in df.columns}
        doc["honeypot"]   = "dionaea"
        doc["@timestamp"] = datetime.now(timezone.utc).isoformat()
        actions.append({"_index": INDEX, "_source": doc})

    success, failed = helpers.bulk(es, actions, raise_on_error=False, stats_only=False)
    errors = [r for r in failed] if isinstance(failed, list) else []

    print(f"[OK] Pushed {success} docs to [{INDEX}]")
    if errors:
        print(f"[!]  {len(errors)} errors — first: {errors[0]}")


if __name__ == "__main__":
    push()