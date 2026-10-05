"""
Splunk REST API connector (management port, default 8089).

Auth model: a Splunk auth token (recommended: create one in
Settings > Tokens, or Data Inputs > HTTP Event Collector for ingestion only).
Search flow: create a search job -> poll until done -> fetch results.
Docs: https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch
"""
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SplunkConnector:
    def __init__(self, base_url: str, token: str, verify_ssl: bool = False):
        # base_url example: "https://splunk-host:8089"
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"}
        self.verify_ssl = verify_ssl

    def run_search(self, spl_query: str, earliest: str = "-24h", latest: str = "now",
                    poll_interval: float = 1.0, timeout: float = 60.0) -> list:
        """
        Run a blocking search and return results as a list of dicts.
        spl_query must start with 'search ' (or another generating command).
        """
        if not spl_query.strip().lower().startswith(("search", "|")):
            spl_query = f"search {spl_query}"

        create_resp = requests.post(
            f"{self.base_url}/services/search/jobs",
            headers=self.headers,
            data={
                "search": spl_query,
                "earliest_time": earliest,
                "latest_time": latest,
                "output_mode": "json",
            },
            verify=self.verify_ssl,
            timeout=15,
        )
        create_resp.raise_for_status()
        sid = create_resp.json()["sid"]

        # Poll until the job is done
        elapsed = 0.0
        while elapsed < timeout:
            status_resp = requests.get(
                f"{self.base_url}/services/search/jobs/{sid}",
                headers=self.headers,
                params={"output_mode": "json"},
                verify=self.verify_ssl,
                timeout=15,
            )
            status_resp.raise_for_status()
            props = status_resp.json()["entry"][0]["content"]
            if props.get("isDone"):
                break
            time.sleep(poll_interval)
            elapsed += poll_interval

        results_resp = requests.get(
            f"{self.base_url}/services/search/jobs/{sid}/results",
            headers=self.headers,
            params={"output_mode": "json", "count": 0},
            verify=self.verify_ssl,
            timeout=30,
        )
        results_resp.raise_for_status()
        return results_resp.json().get("results", [])

    def normalize_alerts(self, index: str = "notable", earliest: str = "-24h") -> list:
        """Example: pull notable/alert events from Splunk ES (or any index)."""
        raw = self.run_search(f'search index={index}', earliest=earliest)
        events = []
        for r in raw:
            events.append({
                "source": "splunk",
                "type": "alert",
                "time": r.get("_time"),
                "host": r.get("host"),
                "raw": r,
            })
        return events
