"""Entity extraction: a raw Wazuh alert -> a flat, normalized record (rule-based field mapping).

Wazuh alerts are already structured, so no NER is needed (PLAN.md section 4):

    agent.name / agent.ip          -> target Asset
    rule.mitre.id                  -> Technique  (else overrides/wazuh_rule_techniques.csv)
    data.vulnerability.cve         -> Vulnerability
    data.srcip / dstip / dstport   -> source (Asset or the Internet) and service
    rule.id / level / groups       -> alert properties

Pure functions: no Neo4j, no network. Graph matching happens in load.py.
"""
import csv
import json
import re
from pathlib import Path

CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


def load_rule_techniques(path: Path) -> dict[str, list[str]]:
    """rule_id -> [technique ids] from the hand-reviewed lookup table (missing file = empty)."""
    if not path.exists():
        return {}
    out: dict[str, list[str]] = {}
    with open(path, newline="", encoding="utf-8") as fh:
        lines = (ln for ln in fh if ln.strip() and not ln.lstrip().startswith("#"))
        for row in csv.DictReader(lines):
            tech = (row.get("technique") or "").strip()
            if TECHNIQUE.match(tech):
                out.setdefault(row["rule_id"].strip(), []).append(tech)
    return out


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _first(*values):
    for v in values:
        if isinstance(v, list):
            v = v[0] if v else None
        if v not in (None, ""):
            return str(v)
    return None


def normalize(hit: dict, rule_techniques: dict[str, list[str]] | None = None,
              revoked: dict[str, str] | None = None) -> dict:
    """One indexer hit ({_id, _source}) or a bare alert document -> normalized record.

    `revoked` maps ATT&CK ids that MITRE revoked to their replacement (cti_kg revoked_technique_map).
    The Wazuh ruleset lags behind ATT&CK releases, e.g. Wazuh 4.9 still tags T1562.001, which ATT&CK
    replaced with T1685. The ids as Wazuh sent them are kept in `techniques_original`.
    """
    src = hit.get("_source", hit)
    rule = src.get("rule") or {}
    agent = src.get("agent") or {}
    data = src.get("data") or {}
    mitre = rule.get("mitre") or {}

    techniques = [t for t in _as_list(mitre.get("id")) if TECHNIQUE.match(str(t))]
    technique_source = "wazuh-rule" if techniques else None
    if not techniques and rule_techniques:
        techniques = list(rule_techniques.get(str(rule.get("id")), []))
        technique_source = "lookup" if techniques else None
    original = sorted(set(techniques))
    techniques = [(revoked or {}).get(t, t) for t in techniques]

    vuln = data.get("vulnerability") or {}
    cves = {c.upper() for c in _as_list(vuln.get("cve")) + _as_list(vuln.get("id")) if CVE.fullmatch(str(c))}
    # Suricata EVE alerts (forwarded by the Wazuh agent as JSON): the rule's `metadata: cve CVE_2024_23897`
    # and CVE ids written in the signature, e.g. "ET EXPLOIT ... (CVE-2024-23897)".
    ids_alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
    meta_cves = _as_list((ids_alert.get("metadata") or {}).get("cve"))
    cves |= {str(c).upper().replace("_", "-") for c in meta_cves if CVE.fullmatch(str(c).upper().replace("_", "-"))}
    cves |= {m.upper() for m in CVE.findall(str(ids_alert.get("signature") or ""))}

    dstport = _first(data.get("dstport"), data.get("dest_port"))
    return {
        "alert_id": str(hit.get("_id") or src.get("id")),
        "timestamp": src.get("@timestamp") or src.get("timestamp"),
        "rule_id": str(rule.get("id")),
        "rule_level": int(rule.get("level", 0)),
        "description": rule.get("description"),
        "groups": _as_list(rule.get("groups")),
        "agent_id": agent.get("id"),
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "techniques": sorted(set(techniques)),
        "techniques_original": original,
        "technique_source": technique_source,
        "tactics": _as_list(mitre.get("tactic")),
        "cves": sorted(cves),
        "srcip": _first(data.get("srcip"), data.get("src_ip")),
        "dstip": _first(data.get("dstip"), data.get("dst_ip"), data.get("dest_ip")),
        "dstport": int(dstport) if dstport and dstport.isdigit() else None,
        "signature": ids_alert.get("signature"),
        "signature_id": _first(ids_alert.get("signature_id")),
        "full_log": (src.get("full_log") or "")[:2000],
    }


def read_jsonl(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(ln) for ln in fh if ln.strip()]
