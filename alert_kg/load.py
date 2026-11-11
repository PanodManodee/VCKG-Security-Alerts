"""Write normalized alerts into the unified graph as Alert nodes.

    (Alert)-[:TARGETS]->(Asset)            agent.name (case-insensitive) or agent.ip; for agents that are not
                                           assets (the Suricata sensor `ids`), the asset with IP = data.dest_ip
    (Alert)-[:INDICATES]->(Technique)      rule.mitre.id or the rule lookup table
    (Alert)-[:MENTIONS]->(Vulnerability)   data.vulnerability.cve
    (Alert)-[:FROM]->(Asset)               data.srcip is a lab host
    (Alert)-[:FROM]->(Zone {Internet})     data.srcip is anything else (except loopback)

Only Alert nodes and their edges are created; Asset/Technique/Vulnerability/Zone are matched.
Everything written carries sources = ['alert_kg'].
"""
from asset_kg.db import driver

from . import config
from .extract import load_rule_techniques, normalize, read_jsonl

SRC = [config.SOURCE]
EXTERNAL_ZONE = "Internet"
LOCAL_IPS = {"127.0.0.1", "::1", "localhost"}

Q_SCHEMA = "CREATE CONSTRAINT alert_id IF NOT EXISTS FOR (n:Alert) REQUIRE n.alert_id IS UNIQUE"

Q_ALERTS = """
UNWIND $rows AS r
MERGE (al:Alert {alert_id: r.alert_id})
SET al += r{.timestamp, .rule_id, .rule_level, .description, .groups, .agent_name, .agent_ip,
            .techniques, .techniques_original, .technique_source, .tactics, .cves,
            .srcip, .dstip, .dstport, .signature, .signature_id, .full_log},
    al.sources = $src
WITH al, r
CALL (al, r) {
  // the agent's own host first; for network sensors that are not assets (Suricata on the `ids` agent),
  // the asset whose IP is the alert's destination (paper §III.A.2)
  OPTIONAL MATCH (a:Asset)
  WHERE toLower(a.hostname) = toLower(r.agent_name) OR (r.agent_ip IS NOT NULL AND a.ip = r.agent_ip)
     OR (r.dstip IS NOT NULL AND a.ip = r.dstip)
  WITH a ORDER BY CASE WHEN toLower(a.hostname) = toLower(r.agent_name) THEN 0
                       WHEN a.ip = r.agent_ip THEN 1 ELSE 2 END LIMIT 1
  FOREACH (_ IN CASE WHEN a IS NULL THEN [] ELSE [1] END |
    MERGE (al)-[e:TARGETS]->(a) SET e.sources = $src)
}
CALL (al, r) {
  UNWIND r.techniques AS tid
  MATCH (t:Technique {attack_id: tid})
  MERGE (al)-[e:INDICATES]->(t) SET e.sources = $src, e.via = r.technique_source
}
CALL (al, r) {
  UNWIND r.cves AS cve
  MATCH (v:Vulnerability {cve_id: cve})
  MERGE (al)-[e:MENTIONS]->(v) SET e.sources = $src
}
CALL (al, r) {
  WITH r WHERE r.srcip IS NOT NULL AND NOT r.srcip IN $local
  OPTIONAL MATCH (s:Asset {ip: r.srcip})
  OPTIONAL MATCH (z:Zone {name: $external})
  WITH coalesce(s, z) AS source WHERE source IS NOT NULL
  MERGE (al)-[e:FROM]->(source) SET e.sources = $src
}
RETURN count(al) AS n,
       sum(CASE WHEN EXISTS { (al)-[:TARGETS]->() } THEN 1 ELSE 0 END) AS targeted,
       sum(CASE WHEN EXISTS { (al)-[:INDICATES]->() } THEN 1 ELSE 0 END) AS with_technique,
       sum(CASE WHEN EXISTS { (al)-[:MENTIONS]->() } THEN 1 ELSE 0 END) AS with_cve,
       sum(CASE WHEN EXISTS { (al)-[:FROM]->() } THEN 1 ELSE 0 END) AS with_source
"""

Q_WIPE = "MATCH (al:Alert) WHERE 'alert_kg' IN coalesce(al.sources, []) DETACH DELETE al"

BATCH = 500


def revoked_techniques() -> dict[str, str]:
    """Revoked ATT&CK id -> replacement, from the same ATT&CK bundle the CTI graph was built from."""
    from cti_kg import config as cti_config
    from cti_kg.parse.attack import revoked_technique_map
    if not cti_config.ATTACK_JSON.exists():
        print(f"  {cti_config.ATTACK_JSON} not found: revoked ATT&CK ids are not remapped")
        return {}
    return revoked_technique_map(cti_config.ATTACK_JSON)


def load_records(session, records: list[dict]) -> dict:
    session.run(Q_SCHEMA).consume()
    totals = {"n": 0, "targeted": 0, "with_technique": 0, "with_cve": 0, "with_source": 0}
    for i in range(0, len(records), BATCH):
        res = session.execute_write(lambda tx, rows=records[i:i + BATCH]: tx.run(
            Q_ALERTS, rows=rows, src=SRC, local=list(LOCAL_IPS), external=EXTERNAL_ZONE).single().data())
        for k in totals:
            totals[k] += res[k]
    return totals


def load(path=config.RAW_ALERTS, do_wipe: bool = False, wait: int = 60) -> None:
    if not path.exists():
        raise SystemExit(f"{path} not found: run `python -m alert_kg fetch` first")
    rule_map = load_rule_techniques(config.RULE_TECHNIQUES)
    revoked = revoked_techniques()
    records = [normalize(h, rule_map, revoked) for h in read_jsonl(path)]
    remapped = sum(1 for r in records if r["techniques"] != r["techniques_original"])
    if remapped:
        print(f"  {remapped} alerts carried revoked ATT&CK ids, remapped to their replacements")
    with driver(wait) as drv, drv.session() as session:
        if do_wipe:
            session.run(Q_WIPE).consume()
            print("removed Alert nodes created by alert_kg")
        t = load_records(session, records)
    print(f"loaded {t['n']} alerts from {path}: {t['targeted']} mapped to an asset, "
          f"{t['with_technique']} with an ATT&CK technique, {t['with_cve']} with a CVE in the graph, "
          f"{t['with_source']} with a source")
    unmapped = sorted({r["agent_name"] for r in records} - {None})
    if t["targeted"] < t["n"]:
        print(f"  agents seen: {', '.join(unmapped)} (alerts from agents that are not Assets, e.g. "
              "wazuh.manager, stay unmapped)")
