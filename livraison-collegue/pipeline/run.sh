#!/usr/bin/env bash
# Lance le pipeline d'ingestion (genere par setup.sh)
export WAZUH_SSH="ubuntu@10.125.113.20"
export WAZUH_SSH_PORT="22"
export ALERTS_FILE="/var/ossec/logs/alerts/alerts.json"
export OLLAMA_URL="http://localhost:11434"
export OLLAMA_MODEL="soc-analyst-v2"
export BACKEND_URL="http://localhost:8000"
exec python3 "$(dirname "$0")/ingest_example.py"
