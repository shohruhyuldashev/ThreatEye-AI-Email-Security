#!/usr/bin/env bash
#
# Provision the Elasticsearch + Kibana side of the SIEM integration.
#
#   ./scripts/siem-setup.sh
#
# Creates, idempotently:
#   1. an index template for `threateye-alerts*` with ECS-aligned mappings, so
#      fields get real types instead of whatever dynamic mapping guesses from
#      the first document (a wrong guess is permanent for that index);
#   2. the backing index;
#   3. a Kibana data view on @timestamp so the alerts are searchable in Discover.
#
# Env overrides: ES_URL, KIBANA_URL.
set -euo pipefail

ES_URL="${ES_URL:-http://localhost:9200}"
KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
INDEX="threateye-alerts"

wait_for() {
  local name="$1" url="$2" tries="${3:-60}"
  printf 'Waiting for %s ' "$name"
  for _ in $(seq 1 "$tries"); do
    if curl -fs -m 3 "$url" >/dev/null 2>&1; then echo " up"; return 0; fi
    printf '.'; sleep 3
  done
  echo " TIMEOUT"; return 1
}

wait_for Elasticsearch "$ES_URL/_cluster/health"

echo "==> index template"
curl -fs -X PUT "$ES_URL/_index_template/threateye-alerts" \
  -H 'Content-Type: application/json' -d '{
  "index_patterns": ["threateye-alerts*"],
  "priority": 200,
  "template": {
    "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
    "mappings": {
      "dynamic": true,
      "properties": {
        "@timestamp": { "type": "date" },
        "message":    { "type": "text" },
        "event": {
          "properties": {
            "kind":       { "type": "keyword" },
            "category":   { "type": "keyword" },
            "action":     { "type": "keyword" },
            "provider":   { "type": "keyword" },
            "risk_score": { "type": "float" }
          }
        },
        "email": {
          "properties": {
            "from":    { "properties": { "address": { "type": "keyword" } } },
            "to":      { "properties": { "address": { "type": "keyword" } } },
            "subject": { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 512 } } }
          }
        },
        "threat": {
          "properties": {
            "framework": { "type": "keyword" },
            "technique": { "properties": { "id": { "type": "keyword" }, "name": { "type": "keyword" } } },
            "tactic":    { "properties": { "name": { "type": "keyword" } } },
            "indicator": { "properties": { "type": { "type": "keyword" }, "value": { "type": "keyword" } } }
          }
        },
        "rule":         { "properties": { "name": { "type": "keyword" } } },
        "organization": { "properties": { "id": { "type": "keyword" } } },
        "labels":       { "properties": { "threat_type": { "type": "keyword" } } }
      }
    }
  }
}' >/dev/null && echo "    template ok"

echo "==> index"
if curl -fs -o /dev/null "$ES_URL/$INDEX"; then
  echo "    $INDEX already exists"
else
  curl -fs -X PUT "$ES_URL/$INDEX" -H 'Content-Type: application/json' >/dev/null && echo "    $INDEX created"
fi

# Kibana is optional — the ES side is what ThreatEye writes to.
if wait_for Kibana "$KIBANA_URL/api/status" 40; then
  echo "==> Kibana data view"
  if curl -fs "$KIBANA_URL/api/data_views" -H 'kbn-xsrf: true' 2>/dev/null | grep -q "\"title\":\"$INDEX\""; then
    echo "    data view already exists"
  else
    curl -fs -X POST "$KIBANA_URL/api/data_views/data_view" \
      -H 'Content-Type: application/json' -H 'kbn-xsrf: true' \
      -d "{\"data_view\":{\"title\":\"$INDEX*\",\"name\":\"ThreatEye Alerts\",\"timeFieldName\":\"@timestamp\"}}" \
      >/dev/null && echo "    data view created"
  fi
else
  echo "    (skipping Kibana data view — Kibana not reachable)"
fi

echo
echo "Done. Point ThreatEye at the SIEM in Settings -> Integrations:"
echo "  Webhook URL : http://elasticsearch:9200/$INDEX/_doc"
echo "  Format      : ECS (Elastic)"
echo "  API key     : (blank — security is disabled in this lab stack)"
echo "  Kibana      : $KIBANA_URL  -> Discover -> ThreatEye Alerts"
