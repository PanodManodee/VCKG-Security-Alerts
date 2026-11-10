"""Pull alerts from the Wazuh indexer (OpenSearch `wazuh-alerts-*`) into data/alerts/raw.jsonl.

Reads the indexer, not the manager API, as PLAN.md section 4 proposes. Pages with search_after,
so the number of alerts is not limited by the 10 000-hit window.
"""
import json
from pathlib import Path

import requests
import urllib3

from . import config

PAGE = 1000


def search(body: dict, index: str = config.ALERT_INDEX) -> dict:
    if config.WAZUH_INDEXER_CA is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    r = requests.post(f"{config.WAZUH_INDEXER_URL}/{index}/_search", json=body,
                      auth=(config.WAZUH_INDEXER_USER, config.WAZUH_INDEXER_PASSWORD),
                      verify=config.WAZUH_INDEXER_CA, timeout=60)
    if r.status_code == 401:
        raise SystemExit("Wazuh indexer rejected the login (WAZUH_INDEXER_USER / WAZUH_INDEXER_PASSWORD)")
    r.raise_for_status()
    return r.json()


def fetch(since: str = "24h", min_level: int = 3, out: Path = config.RAW_ALERTS) -> int:
    """Write every alert from the last `since` with rule.level >= min_level. Returns the count."""
    body = {
        "size": PAGE,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": f"now-{since}"}}},
            {"range": {"rule.level": {"gte": min_level}}},
        ]}},
        "sort": [{"@timestamp": "asc"}, {"id": "asc"}],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".part")     # replace `out` only after a complete fetch: a failed one keeps the old file
    n = 0
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            while True:
                hits = search(body)["hits"]["hits"]
                for h in hits:
                    fh.write(json.dumps({"_id": h["_id"], "_index": h["_index"], "_source": h["_source"]}) + "\n")
                n += len(hits)
                if len(hits) < PAGE:
                    break
                body["search_after"] = hits[-1]["sort"]
    except requests.ConnectionError:
        tmp.unlink(missing_ok=True)
        raise SystemExit(f"cannot reach the Wazuh indexer at {config.WAZUH_INDEXER_URL} (is lab_env running?)")
    tmp.replace(out)
    print(f"fetched {n} alerts (last {since}, rule.level >= {min_level}) -> {out}")
    return n
