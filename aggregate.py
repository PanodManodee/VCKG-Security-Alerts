"""
Security data aggregator: pulls normalized events from Wazuh, Splunk,
Microsoft Sentinel, and AMiner, and merges them into one list/JSON file.

Configure credentials via environment variables (don't hardcode secrets).
Run:  python aggregate.py
"""
import os
import json
from datetime import datetime, timezone

from connectors.wazuh_connector import WazuhConnector
from connectors.splunk_connector import SplunkConnector
from connectors.sentinel_connector import SentinelConnector
from connectors.aminer_connector import AminerSocketConnector, AminerRestConnector


def collect_wazuh() -> list:
    try:
        wazuh = WazuhConnector(
            base_url=os.environ["WAZUH_URL"],
            username=os.environ["WAZUH_USER"],
            password=os.environ["WAZUH_PASSWORD"],
        )
        return wazuh.normalize_agents()
    except KeyError as e:
        print(f"[wazuh] skipped, missing env var: {e}")
        return []
    except Exception as e:
        print(f"[wazuh] error: {e}")
        return []


def collect_splunk() -> list:
    try:
        splunk = SplunkConnector(
            base_url=os.environ["SPLUNK_URL"],
            token=os.environ["SPLUNK_TOKEN"],
        )
        return splunk.normalize_alerts(index=os.environ.get("SPLUNK_INDEX", "notable"))
    except KeyError as e:
        print(f"[splunk] skipped, missing env var: {e}")
        return []
    except Exception as e:
        print(f"[splunk] error: {e}")
        return []


def collect_sentinel() -> list:
    try:
        sentinel = SentinelConnector(
            tenant_id=os.environ["AZURE_TENANT_ID"],
            client_id=os.environ["AZURE_CLIENT_ID"],
            client_secret=os.environ["AZURE_CLIENT_SECRET"],
            workspace_id=os.environ["SENTINEL_WORKSPACE_ID"],
        )
        return sentinel.normalize_incidents()
    except KeyError as e:
        print(f"[sentinel] skipped, missing env var: {e}")
        return []
    except Exception as e:
        print(f"[sentinel] error: {e}")
        return []


def collect_aminer() -> list:
    # Prefer the REST wrapper if configured; otherwise fall back to the
    # local Unix-socket connector.
    rest_url = os.environ.get("AMINER_REST_URL")
    try:
        if rest_url:
            aminer = AminerRestConnector(base_url=rest_url, token=os.environ.get("AMINER_TOKEN"))
            return aminer.normalize_events()
        else:
            aminer = AminerSocketConnector(
                socket_path=os.environ.get("AMINER_SOCKET", "/var/run/aminer-remote.socket")
            )
            components = aminer.list_analysis_components()
            return [{"source": "aminer", "type": "components", "raw": components}]
    except Exception as e:
        print(f"[aminer] error: {e}")
        return []


def main():
    all_events = []
    all_events.extend(collect_wazuh())
    all_events.extend(collect_splunk())
    all_events.extend(collect_sentinel())
    all_events.extend(collect_aminer())

    output = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "event_count": len(all_events),
        "events": all_events,
    }

    out_path = "aggregated_events.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"Collected {len(all_events)} events -> {out_path}")


if __name__ == "__main__":
    main()
