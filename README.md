This project is a WIP project. This repository is currently for backup and version control purpose only

# Security Data Aggregator

Pulls normalized security events from Wazuh, Splunk, Microsoft Sentinel,
and AMiner into a single JSON output.

## Install

```bash
pip install -r requirements.txt
```

## Configure (environment variables)

**Wazuh**
```bash
export WAZUH_URL="https://wazuh-manager:55000"
export WAZUH_USER="apiuser"
export WAZUH_PASSWORD="secret"
```

**Splunk**
```bash
export SPLUNK_URL="https://splunk-host:8089"
export SPLUNK_TOKEN="your-splunk-auth-token"
export SPLUNK_INDEX="notable"   # optional, defaults to 'notable'
```

**Microsoft Sentinel** (Azure AD app registration required; grant it
"Log Analytics Reader" on the workspace)
```bash
export AZURE_TENANT_ID="..."
export AZURE_CLIENT_ID="..."
export AZURE_CLIENT_SECRET="..."
export SENTINEL_WORKSPACE_ID="..."   # Log Analytics workspace ID (GUID)
```

**AMiner** (pick one)
```bash
# Option A: community REST wrapper (ait-aecid/aminer-rest) deployed on host
export AMINER_REST_URL="http://aminer-host:8000"
export AMINER_TOKEN="optional-token"

# Option B: direct Unix socket control (must run on/near the AMiner host)
export AMINER_SOCKET="/var/run/aminer-remote.socket"
```

Any connector whose env vars aren't set is skipped automatically, so you
can run this against just one or two systems while you're testing.

## Run

```bash
python aggregate.py
```

Produces `aggregated_events.json` with events from every configured source,
each tagged with a `"source"` field (`wazuh`, `splunk`, `sentinel`, `aminer`)
so you can filter, dedupe, or forward them downstream (e.g. into your own
SIEM, a database, or an alerting pipeline).

## Extending

Each connector class in `connectors/` exposes a `normalize_*()` method that
returns a list of dicts. To pull a different signal (e.g. Wazuh SCA results
instead of agent status, or a different KQL query for Sentinel), add a new
method following the same pattern and call it from `aggregate.py`.
