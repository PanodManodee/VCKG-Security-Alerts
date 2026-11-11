"""Offline tests for alert entity extraction (no Neo4j, no Wazuh)."""
from pathlib import Path

from alert_kg.extract import load_rule_techniques, normalize, read_jsonl

FIX = Path(__file__).parent / "fixtures" / "wazuh_alerts.jsonl"
ALERTS = {h["_id"]: h for h in read_jsonl(FIX)}


def test_real_alert_fields():
    r = normalize(ALERTS["test-agent-stopped"])
    assert r["alert_id"] == "test-agent-stopped"
    assert r["rule_id"] == "506" and r["rule_level"] == 3
    assert r["agent_name"] == "postgresql" and r["agent_ip"] is None
    assert r["techniques"] == ["T1562.001"] and r["technique_source"] == "wazuh-rule"
    assert r["srcip"] is None and r["cves"] == []


def test_revoked_technique_is_remapped_and_original_kept():
    r = normalize(ALERTS["test-agent-stopped"], revoked={"T1562.001": "T1685"})
    assert r["techniques"] == ["T1685"]
    assert r["techniques_original"] == ["T1562.001"]


def test_source_ip_and_multiple_techniques():
    r = normalize(ALERTS["test-sshd-internal"])
    assert r["srcip"] == "10.10.40.42"
    assert r["techniques"] == ["T1021.004", "T1110.001"]
    assert r["tactics"] == ["Credential Access", "Lateral Movement"]


def test_cve_from_vulnerability_data():
    r = normalize(ALERTS["test-vuln-jenkins"])
    assert r["cves"] == ["CVE-2024-23897"]
    assert r["techniques"] == [] and r["technique_source"] is None


def test_rule_lookup_only_when_rule_has_no_mitre(tmp_path):
    table = tmp_path / "rules.csv"
    table.write_text("# comment\nrule_id,technique,note\n23506,T1190,test\n506,T1000,ignored\n", encoding="utf-8")
    lookup = load_rule_techniques(table)
    assert normalize(ALERTS["test-vuln-jenkins"], lookup)["techniques"] == ["T1190"]
    assert normalize(ALERTS["test-vuln-jenkins"], lookup)["technique_source"] == "lookup"
    assert normalize(ALERTS["test-agent-stopped"], lookup)["techniques"] == ["T1562.001"]   # rule.mitre wins


def test_bare_document_without_hit_wrapper():
    doc = ALERTS["test-web-external"]["_source"]
    r = normalize(doc)
    assert r["alert_id"] == doc["id"]
    assert r["srcip"] == "172.30.0.10"


def test_suricata_alert_gives_destination_and_cve_from_rule_metadata():
    r = normalize(ALERTS["test-suricata-jenkins"])
    assert r["agent_name"] == "ids"
    assert r["dstip"] == "10.10.20.22" and r["dstport"] == 8080 and r["srcip"] == "10.10.10.12"
    assert r["cves"] == ["CVE-2024-23897"]                    # CVE_2024_23897 in metadata, CVE-... in signature
    assert r["signature_id"] == "9000001"
