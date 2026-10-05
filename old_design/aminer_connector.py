"""
AMiner (logdata-anomaly-miner) connector.

Important: AMiner does NOT ship a native REST API. Its control interface is
a Unix domain socket, driven by the 'AMinerRemoteControl' CLI tool, which
executes short Python snippets inside the running AMiner process and returns
the result. This connector shells out to that tool.

If you'd rather have real HTTP, deploy the community wrapper
'ait-aecid/aminer-rest' (FastAPI service) on the AMiner host and use the
AminerRestConnector class below instead -- it's a normal REST client.

Docs:
  - Remote control: https://manpages.ubuntu.com/manpages/jammy/man1/aminerremotecontrol.1.html
  - REST wrapper: https://github.com/ait-aecid/aminer-rest
"""
import json
import subprocess
import requests


class AminerSocketConnector:
    """Talks to AMiner directly over its Unix control socket."""

    def __init__(self, socket_path: str = "/var/run/aminer-remote.socket",
                 binary: str = "/usr/bin/AMinerRemoteControl"):
        self.socket_path = socket_path
        self.binary = binary

    def exec_snippet(self, python_snippet: str):
        """
        Run an arbitrary snippet inside the AMiner process and return the
        parsed result. The snippet must assign to 'remoteControlResponse'.
        """
        result = subprocess.run(
            [self.binary, "--ControlSocket", self.socket_path, "--Exec", python_snippet],
            capture_output=True, text=True, check=True,
        )
        return result.stdout.strip()

    def list_analysis_components(self):
        """Example: list the registered analysis component IDs."""
        return self.exec_snippet(
            "remoteControlResponse = analysisContext.getRegisteredComponentIds()"
        )


class AminerRestConnector:
    """Talks to the community 'aminer-rest' HTTP wrapper, if deployed."""

    def __init__(self, base_url: str, token: str = None, verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.verify_ssl = verify_ssl

    def get_events(self) -> list:
        resp = requests.get(f"{self.base_url}/events", headers=self.headers,
                             verify=self.verify_ssl, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def normalize_events(self) -> list:
        events = []
        for e in self.get_events():
            events.append({
                "source": "aminer",
                "type": "anomaly",
                "raw": e,
            })
        return events
