"""Settings for alert ingestion. Neo4j settings come from asset_kg.config (same .env, same database)."""
import os
from pathlib import Path

from asset_kg.config import ROOT  # noqa: F401  (also loads .env)

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "SecretPassword")
# The lab indexer uses a self-signed certificate (lab_env/wazuh). Point this at its root CA to verify:
#   WAZUH_INDEXER_CA=lab_env/wazuh/config/wazuh_indexer_ssl_certs/root-ca.pem
WAZUH_INDEXER_CA = os.getenv("WAZUH_INDEXER_CA") or False
ALERT_INDEX = os.getenv("WAZUH_ALERT_INDEX", "wazuh-alerts-*")
VULN_INDEX = os.getenv("WAZUH_VULN_INDEX", "wazuh-states-vulnerabilities-*")   # Wazuh vulnerability detection

# Wazuh server API (agent list, syscollector package inventory). Lab defaults from lab_env/docker-compose.yml.
WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://localhost:55000")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD", "MyS3cr37P450r.*-")

ALERTS = ROOT / "data" / "alerts"          # data/ is git-ignored
RAW_ALERTS = ALERTS / "raw.jsonl"           # output of `fetch`
CONTEXT_DIR = ALERTS / "context"            # output of `context`, one JSON per alert

# Hand-reviewed rule.id -> ATT&CK ids for Wazuh rules that carry no rule.mitre (PLAN.md section 4).
RULE_TECHNIQUES = Path(os.getenv("ALERT_RULE_TECHNIQUES", ROOT / "overrides" / "wazuh_rule_techniques.csv"))

SOURCE = "alert_kg"
