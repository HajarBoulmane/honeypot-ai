#!/bin/bash

echo "Waiting for Kibana to be ready..."
until curl -s http://localhost:5601/api/status | grep -q '"level":"available"'; do
  sleep 5
done

echo "Importing dashboards..."
curl -X POST http://localhost:5601/api/saved_objects/_import \
  -H "kbn-xsrf: true" \
  --form file=@/dashboards/kibana_export.ndjson

echo "Pushing Cowrie data..."
cd /app && python -m src.cowrie.push_to_elastic

echo "Pushing Dionaea data..."
cd /app && python -m src.dionaea.push_to_elastic

echo "Done. Go to http://localhost:5601"