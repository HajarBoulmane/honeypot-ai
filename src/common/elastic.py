import os
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

load_dotenv()

def push_to_elastic(df, index_name):
    es = Elasticsearch(
        os.getenv("ELASTIC_HOST"),
        basic_auth=(os.getenv("ELASTIC_USER"), os.getenv("ELASTIC_PASSWORD")),
        verify_certs=False
    )

    actions = [
        {
            "_index": index_name,
            "_source": row.to_dict()
        }
        for _, row in df.iterrows()
    ]

    bulk(es, actions)

    print(f"✔ Pushed {len(actions)} documents to {index_name}")