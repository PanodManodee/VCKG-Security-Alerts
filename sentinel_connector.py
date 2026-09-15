"""
Microsoft Sentinel connector.

There isn't a standalone "Sentinel data API" for reading events -- Sentinel
stores its data in a Log Analytics workspace, so you query that workspace
with KQL via the Azure Monitor Log Analytics Data API.

Auth model: Azure AD app registration (client id/secret/tenant) using the
OAuth2 client-credentials flow, scoped to the Log Analytics API.
Requires: pip install msal requests
Docs: https://learn.microsoft.com/azure/azure-monitor/logs/api/overview
"""
import requests
import msal


class SentinelConnector:
    LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"

    def __init__(self, tenant_id: str, client_id: str, client_secret: str, workspace_id: str):
        self.workspace_id = workspace_id
        self._app = msal.ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret,
        )
        self._token = None

    def _get_token(self) -> str:
        if self._token:
            return self._token
        result = self._app.acquire_token_for_client(scopes=[self.LOG_ANALYTICS_SCOPE])
        if "access_token" not in result:
            raise RuntimeError(f"Auth failed: {result.get('error_description')}")
        self._token = result["access_token"]
        return self._token

    def run_kql(self, query: str, timespan: str = "P1D") -> list:
        """
        Run a KQL query against the workspace.
        timespan uses ISO 8601 duration, e.g. 'P1D' = last 1 day.
        """
        url = f"https://api.loganalytics.io/v1/workspaces/{self.workspace_id}/query"
        headers = {"Authorization": f"Bearer {self._get_token()}"}
        resp = requests.post(
            url,
            headers=headers,
            json={"query": query, "timespan": timespan},
            timeout=30,
        )
        resp.raise_for_status()
        table = resp.json()["tables"][0]
        columns = [c["name"] for c in table["columns"]]
        return [dict(zip(columns, row)) for row in table["rows"]]

    def normalize_incidents(self) -> list:
        """
        Example query against the SecurityIncident table (requires the
        Sentinel/SecurityInsights solution enabled on the workspace).
        """
        rows = self.run_kql(
            "SecurityIncident | where TimeGenerated > ago(1d) | project TimeGenerated, Title, Severity, Status"
        )
        events = []
        for r in rows:
            events.append({
                "source": "sentinel",
                "type": "incident",
                "time": r.get("TimeGenerated"),
                "title": r.get("Title"),
                "severity": r.get("Severity"),
                "status": r.get("Status"),
                "raw": r,
            })
        return events
