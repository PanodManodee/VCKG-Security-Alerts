"""
Wazuh server API connector.

Auth model: JWT. POST credentials to /security/user/authenticate,
then send the returned token as a Bearer token on every subsequent call.
Docs: https://documentation.wazuh.com/current/user-manual/api/reference.html
"""
import requests
import urllib3

# Wazuh's default install uses a self-signed cert. Disable the warning noise;
# in production, point verify= at your real CA bundle instead of False.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhConnector:
    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = False):
        # base_url example: "https://wazuh-manager:55000"
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self._token = None

    def _authenticate(self) -> str:
        resp = requests.post(
            f"{self.base_url}/security/user/authenticate",
            auth=(self.username, self.password),
            verify=self.verify_ssl,
            timeout=10,
        )
        resp.raise_for_status()
        self._token = resp.json()["data"]["token"]
        return self._token

    def _headers(self) -> dict:
        if not self._token:
            self._authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    def _get(self, path: str, params: dict = None) -> dict:
        url = f"{self.base_url}{path}"
        resp = requests.get(url, headers=self._headers(), params=params, verify=self.verify_ssl, timeout=15)
        # Token expired -> re-auth once and retry
        if resp.status_code == 401:
            self._authenticate()
            resp = requests.get(url, headers=self._headers(), params=params, verify=self.verify_ssl, timeout=15)
        resp.raise_for_status()
        return resp.json()

    # ---- capabilities ----

    def list_agents(self, status: str = None) -> list:
        params = {"status": status} if status else None
        data = self._get("/agents", params=params)
        return data["data"]["affected_items"]

    def get_fim_events(self, agent_id: str) -> list:
        """File Integrity Monitoring findings for a given agent."""
        data = self._get(f"/syscheck/{agent_id}")
        return data["data"]["affected_items"]

    def get_agent_vulnerabilities(self, agent_id: str) -> list:
        data = self._get(f"/vulnerability/{agent_id}")
        return data["data"]["affected_items"]

    def get_sca_results(self, agent_id: str) -> list:
        """Security Configuration Assessment results."""
        data = self._get(f"/sca/{agent_id}")
        return data["data"]["affected_items"]

    def manager_status(self) -> dict:
        data = self._get("/manager/status")
        return data["data"]["affected_items"][0]

    def normalize_agents(self) -> list:
        """Return agent data in a common shape for the aggregator."""
        events = []
        for a in self.list_agents():
            events.append({
                "source": "wazuh",
                "type": "agent_status",
                "id": a.get("id"),
                "name": a.get("name"),
                "status": a.get("status"),
                "ip": a.get("ip"),
                "os": (a.get("os") or {}).get("name"),
                "raw": a,
            })
        return events
