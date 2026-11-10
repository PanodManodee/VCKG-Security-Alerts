"""Alert context: query the unified graph for one alert (PLAN.md section 4, step 3).

For an Alert node, the fixed query templates return:

  target          the asset the alert is about (zone, role, CR/IR/AR, Internet exposure, platforms)
  source          where it came from: a lab asset, the Internet, or unknown
  techniques      ATT&CK techniques with tactics, mitigations, and whether they apply to the target's platform
  vulnerabilities CVEs present on the target, flagged when the alert names them (MENTIONS) or when
                  the alert's technique leads to them (Technique <- AttackPattern <- Weakness -> CVE)
  attack_paths    shortest paths over CAN_REACH from the source (or from the Internet) to the target
  blast_radius    assets the target can reach in 1-3 hops, with their value and vulnerabilities

The result is a plain dict, written as JSON by `context` (data/alerts/context/<alert_id>.json).
Stage 4 (scoring) reads these files.
"""
import json

from asset_kg.db import driver

from . import config

Q_ALERT = """
MATCH (al:Alert {alert_id: $id})
OPTIONAL MATCH (al)-[:TARGETS]->(a:Asset)
OPTIONAL MATCH (a)-[:IN_ZONE]->(z:Zone)
OPTIONAL MATCH (al)-[:FROM]->(s)
RETURN al{.*, full_log: null, sources: null} AS alert,
       CASE WHEN a IS NULL THEN null ELSE a{.hostname, .ip, .role, .os, .cr, .ir, .ar,
            internet_exposed: coalesce(a.internet_exposed, false), zone: z.name,
            platforms: [(a)-[:RUNS_ON]->(p) | p.name],
            services: [(a)-[:RUNS]->(svc) | svc.id]} END AS target,
       CASE WHEN s IS NULL THEN null
            ELSE {kind: CASE WHEN s:Asset THEN 'asset' ELSE 'external' END,
                  name: coalesce(s.hostname, s.name), ip: al.srcip} END AS source
"""

Q_TECHNIQUES = """
MATCH (al:Alert {alert_id: $id})-[:INDICATES]->(t:Technique)
OPTIONAL MATCH (al)-[:TARGETS]->(a:Asset)
RETURN t.attack_id AS id, t.name AS name,
       [(t)-[:IMPLEMENTS]->(ta) | ta.name] + [(t)-[:SUBTECHNIQUE_OF]->()-[:IMPLEMENTS]->(ta) | ta.name] AS tactics,
       a IS NOT NULL AND EXISTS { (a)-[:RUNS_ON]->(:Platform)<-[:AFFECTS]-(t) } AS applies_to_target,
       [(t)-[:MITIGATED_BY]->(m) | {id: m.mit_id, name: m.name}] AS mitigations
ORDER BY id
"""

# Technique family: the technique, its parent, and its sub-techniques (CAPEC often maps to the parent).
# Only specific CWEs (Base / Variant / Compound) count as a link: Pillar and Class CWEs are so abstract that
# they join unrelated things, e.g. "Wazuh agent stopped" (T1685) -> CAPEC-578 Disable Security Software ->
# CWE-284 Improper Access Control (a Pillar) -> every access-control CVE on the host.
SPECIFIC_CWE = ["Base", "Variant", "Compound"]
Q_VULNS = """
MATCH (al:Alert {alert_id: $id})-[:TARGETS]->(a:Asset)-[:RUNS]->(svc:Service)
      -[:IMPLEMENTED_BY]->(sw:Software)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WITH al, v, collect(DISTINCT svc.id) AS services, collect(DISTINCT sw.id) AS software
RETURN v.cve_id AS cve, v.cvss3_score AS cvss3, v.cvss3_severity AS severity, v.cvss3_vector AS vector,
       v.kev_date_added IS NOT NULL AS kev, v.ssvc_exploitation AS exploitation, services, software,
       EXISTS { (al)-[:MENTIONS]->(v) } AS named_in_alert,
       [(al)-[:INDICATES]->(t:Technique)
        WHERE EXISTS { (v)<-[:EXPLOITED_BY]-(w:Weakness)-[:CAUSES_WEAKNESS]->(:AttackPattern)
                       -[:USES_TECHNIQUE]->(u:Technique)
                       WHERE w.abstraction IN $specific
                         AND (u = t OR (t)-[:SUBTECHNIQUE_OF]->(u) OR (u)-[:SUBTECHNIQUE_OF]->(t)) }
        | t.attack_id] AS via_techniques
"""

# Highest CVSS v3 score of the CVEs behind a service / asset (reduce: no aggregation inside lists).
MAX_CVSS_SERVICE = ("reduce(m = null, s IN COLLECT { MATCH (n)-[:IMPLEMENTED_BY]->()-[:HAS_VULNERABILITY]->(v) "
                    "RETURN v.cvss3_score AS s } | CASE WHEN m IS NULL OR s > m THEN s ELSE m END)")
MAX_CVSS_ASSET = ("reduce(m = null, s IN COLLECT { MATCH (b)-[:RUNS]->()-[:IMPLEMENTED_BY]->()-[:HAS_VULNERABILITY]->(v) "
                  "RETURN v.cvss3_score AS s } | CASE WHEN m IS NULL OR s > m THEN s ELSE m END)")

PATH_HOPS = 4
# Paths start at the alert's source; without a known source, at the outside zone(s) (the Internet).
Q_PATH_START_SOURCE = "MATCH (al:Alert {alert_id: $id})-[:TARGETS]->(a:Asset) MATCH (al)-[:FROM]->(start)"
Q_PATH_START_OUTSIDE = ("MATCH (al:Alert {alert_id: $id})-[:TARGETS]->(a:Asset) "
                        "MATCH (start:Zone) WHERE NOT (start)<-[:IN_ZONE]-(:Asset)")
Q_PATHS = """
MATCH p = SHORTEST 3 (start) ((x)-[:CAN_REACH]->(:Service)<-[:RUNS]-(y)){1,%d} (a)
RETURN [n IN nodes(p) | CASE WHEN n:Service THEN {service: n.id,
          cves: COUNT { (n)-[:IMPLEMENTED_BY]->()-[:HAS_VULNERABILITY]->() },
          max_cvss3: %s}
        ELSE {node: coalesce(n.hostname, n.name)} END] AS hops
""" % (PATH_HOPS, MAX_CVSS_SERVICE)

BLAST_HOPS = 3
Q_BLAST = """
MATCH (al:Alert {alert_id: $id})-[:TARGETS]->(a:Asset)
MATCH p = SHORTEST 1 (a) ((x)-[:CAN_REACH]->(:Service)<-[:RUNS]-(y)){1,%d} (b:Asset)
WHERE b <> a
RETURN b.hostname AS asset, length(p) / 2 AS hops, b.role AS role, b.cr AS cr, b.ir AS ir, b.ar AS ar,
       COUNT { MATCH (b)-[:RUNS]->()-[:IMPLEMENTED_BY]->()-[:HAS_VULNERABILITY]->(v) RETURN DISTINCT v } AS cves,
       %s AS max_cvss3
ORDER BY hops, asset
""" % (BLAST_HOPS, MAX_CVSS_ASSET)

Q_ALERT_IDS = """
MATCH (al:Alert) WHERE al.rule_level >= $min_level
  AND (EXISTS { (al)-[:INDICATES]->() } OR EXISTS { (al)-[:MENTIONS]->() } OR $all)
RETURN al.alert_id AS id ORDER BY al.timestamp
"""


def _sort_vulns(vulns: list[dict]) -> list[dict]:
    return sorted(vulns, key=lambda v: (not v["named_in_alert"], not v["via_techniques"],
                                        not v["kev"], -(v["cvss3"] or 0), v["cve"]))


def build_context(session, alert_id: str, other_vulns: int = 10) -> dict | None:
    head = session.run(Q_ALERT, id=alert_id).single()
    if head is None:
        return None
    techniques = session.run(Q_TECHNIQUES, id=alert_id).data()
    for t in techniques:
        t["tactics"] = sorted(set(t["tactics"]))
    start = Q_PATH_START_SOURCE if head["source"] else Q_PATH_START_OUTSIDE
    paths = [r["hops"] for r in session.run(start + "\n" + Q_PATHS, id=alert_id)]
    vulns = _sort_vulns(session.run(Q_VULNS, id=alert_id, specific=SPECIFIC_CWE).data())
    related = [v for v in vulns if v["named_in_alert"] or v["via_techniques"]]
    others = [v for v in vulns if not (v["named_in_alert"] or v["via_techniques"])]
    return {
        "alert": head["alert"],
        "target": head["target"],
        "source": head["source"] or {"kind": "unknown", "name": None, "ip": head["alert"].get("srcip")},
        "techniques": techniques,
        "vulnerabilities": {
            "on_target": len(vulns),
            "related_to_alert": related,
            "other_top": others[:other_vulns],
            "kev_on_target": sorted(v["cve"] for v in vulns if v["kev"]),
        },
        "attack_paths": paths,
        "blast_radius": session.run(Q_BLAST, id=alert_id).data(),
    }


def summary_line(ctx: dict) -> str:
    a, t = ctx["alert"], ctx["target"] or {}
    v = ctx["vulnerabilities"]
    path = ctx["attack_paths"][0] if ctx["attack_paths"] else []
    route = " > ".join(h.get("node") or h.get("service") for h in path)
    return (f"[{a['rule_level']:>2}] rule {a['rule_id']} {', '.join(a['techniques']) or '-'} "
            f"-> {t.get('hostname', '?')} ({t.get('zone', '?')}, exposed={t.get('internet_exposed')}) | "
            f"source {ctx['source']['kind']} | CVEs {v['on_target']} (related {len(v['related_to_alert'])}, "
            f"KEV {len(v['kev_on_target'])}) | blast {len(ctx['blast_radius'])} | path: {route or '-'}")


def context(alert_id: str | None = None, min_level: int = 3, include_all: bool = False,
            wait: int = 60, quiet: bool = False) -> list[dict]:
    """Write data/alerts/context/<id>.json for one alert, or for every alert with a technique or CVE."""
    config.CONTEXT_DIR.mkdir(parents=True, exist_ok=True)
    if not alert_id:      # a full run replaces the folder: no files left from alerts no longer in the graph
        for old in config.CONTEXT_DIR.glob("*.json"):
            old.unlink()
    out = []
    with driver(wait) as drv, drv.session() as session:
        ids = [alert_id] if alert_id else [r["id"] for r in session.run(
            Q_ALERT_IDS, min_level=min_level, all=include_all)]
        for aid in ids:
            ctx = build_context(session, aid)
            if ctx is None:
                print(f"no Alert {aid} in the graph (run `load`)")
                continue
            (config.CONTEXT_DIR / f"{aid}.json").write_text(json.dumps(ctx, indent=2, default=str),
                                                            encoding="utf-8")
            out.append(ctx)
            if not quiet:
                print(summary_line(ctx))
    print(f"{len(out)} alert contexts -> {config.CONTEXT_DIR}")
    return out
