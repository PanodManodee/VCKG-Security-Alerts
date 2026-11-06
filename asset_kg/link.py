"""Derived edges of the unified graph (asset graph + CTI graph). `link` rebuilds all of them:

1. link_software      Software -[IDENTIFIED_AS]-> CPE, Software -[HAS_VULNERABILITY]-> Vulnerability
2. link_platforms     Asset -[RUNS_ON]-> Platform          (OS family, lab/os_platforms.csv)
3. link_reachability  Asset/Zone -[CAN_REACH]-> Service    (zones and firewall rules)

Step 1, for every Software node with a cpe_vendor / cpe_product and a real version:
  1. fetch the CPE nodes of that vendor:product and their VULNERABLE_TO edges (indexed lookup),
  2. keep the edges whose CPE version / version range covers the installed version (versions.py),
  3. write IDENTIFIED_AS to the CPE nodes that matched and HAS_VULNERABILITY to their CVEs.

The range check is done here (not in Cypher) because Neo4j cannot order versions, and because
wildcard CPE nodes (version '*') keep their bounds on the VULNERABLE_TO edge.
Matching only vendor:product is exact by design: no fuzzy matching of names happens here.
"""
from . import config
from .db import driver
from .loader import read_csv
from .versions import cpe_applies

SRC = [config.SOURCE]

Q_SOFTWARE = """
MATCH (sw:Software)
RETURN sw.id AS id, sw.version AS version, sw.cpe_vendor AS vendor, sw.cpe_product AS product
ORDER BY id
"""

Q_CANDIDATES = """
MATCH (c:CPE {vendor: $vendor, product: $product})-[r:VULNERABLE_TO]->(v:Vulnerability)
RETURN c.cpe23 AS cpe, c.version AS cpe_version, properties(r) AS edge, v.cve_id AS cve
"""

Q_CLEAR = "MATCH (sw:Software {id: $id})-[r:IDENTIFIED_AS|HAS_VULNERABILITY]->() DELETE r"

Q_IDENTIFIED = """
UNWIND $cpes AS cpe
MATCH (sw:Software {id: $id}), (c:CPE {cpe23: cpe})
MERGE (sw)-[e:IDENTIFIED_AS]->(c)
SET e.sources = $src
"""

Q_VULN = """
UNWIND $cves AS cve
MATCH (sw:Software {id: $id}), (v:Vulnerability {cve_id: cve})
MERGE (sw)-[e:HAS_VULNERABILITY]->(v)
SET e.sources = $src
"""


# --- 2. platforms -------------------------------------------------------------------------------------
Q_ASSET_OS = "MATCH (a:Asset) RETURN a.hostname AS host, a.os AS os ORDER BY host"
Q_CLEAR_RUNS_ON = "MATCH (:Asset)-[r:RUNS_ON]->() DELETE r"
Q_RUNS_ON = """
UNWIND $rows AS r
MATCH (a:Asset {hostname: r.host}), (p:Platform {name: r.platform})
MERGE (a)-[e:RUNS_ON]->(p)
SET e.sources = $src
RETURN r.host AS host
"""

# --- 3. reachability ----------------------------------------------------------------------------------
# A host reaches the services of other hosts in its own zone (no firewall in between) and of hosts in
# zones its zone is ALLOWED_TO_REACH. Zone-level, all ports: the same as lab_env/firewall/rules.sh.
Q_CLEAR_REACH = "MATCH ()-[r:CAN_REACH]->(:Service) DELETE r"
Q_REACH_ASSETS = """
MATCH (a:Asset)-[:IN_ZONE]->(za:Zone), (b:Asset)-[:IN_ZONE]->(zb:Zone), (b)-[:RUNS]->(svc:Service)
WHERE a <> b AND (za = zb OR (za)-[:ALLOWED_TO_REACH]->(zb))
MERGE (a)-[e:CAN_REACH]->(svc)
SET e.sources = $src, e.via = CASE WHEN za = zb THEN 'same-zone' ELSE 'firewall' END
RETURN count(*) AS n
"""
# Zones without assets stand for the outside world (Internet): they reach services directly.
Q_REACH_ZONES = """
MATCH (z:Zone)-[:ALLOWED_TO_REACH]->(:Zone)<-[:IN_ZONE]-(:Asset)-[:RUNS]->(svc:Service)
WHERE NOT (z)<-[:IN_ZONE]-(:Asset)
MERGE (z)-[e:CAN_REACH]->(svc)
SET e.sources = $src, e.via = 'firewall'
RETURN count(*) AS n
"""
Q_EXPOSED = """
MATCH (a:Asset)
SET a.internet_exposed = EXISTS { (z:Zone)-[:CAN_REACH]->(:Service)<-[:RUNS]-(a) WHERE NOT (z)<-[:IN_ZONE]-(:Asset) }
WITH a WHERE a.internet_exposed
MATCH (z:Zone)-[:CAN_REACH]->(svc:Service)<-[:RUNS]-(a)
RETURN z.name AS zone, collect(svc.id) AS services
"""


def link_software(session) -> None:
    software = session.run(Q_SOFTWARE).data()
    print(f"software -> CPE / CVE ({len(software)} software nodes)")
    for sw in software:
        name = sw["id"]
        if not sw["vendor"] or not sw["product"]:
            print(f"  {name}: skipped, no cpe_vendor / cpe_product in lab/services.csv")
            continue
        if sw["version"].lower() == "unknown":
            print(f"  {name}: skipped, version is 'unknown' (fill it in lab/services.csv)")
            continue

        rows = session.run(Q_CANDIDATES, vendor=sw["vendor"], product=sw["product"]).data()
        if not rows:
            print(f"  {name}: no CPE {sw['vendor']}:{sw['product']} in the CTI graph "
                  "(check the pair with `python -m asset_kg.find_cpe`, or the CVE years loaded)")
            continue
        hits = [r for r in rows if cpe_applies(sw["version"], r["cpe_version"], r["edge"])]
        cpes = sorted({r["cpe"] for r in hits})
        cves = sorted({r["cve"] for r in hits})

        session.run(Q_CLEAR, id=name).consume()          # re-linking replaces old results
        if cpes:
            session.run(Q_IDENTIFIED, id=name, cpes=cpes, src=SRC).consume()
            session.run(Q_VULN, id=name, cves=cves, src=SRC).consume()
        print(f"  {name}: {len(rows)} candidate edges -> {len(cpes)} CPE, {len(cves)} CVE")


def platform_for(os_name: str | None, mapping: list[dict]) -> str | None:
    """First row of lab/os_platforms.csv whose os_prefix starts the OS name (case-insensitive)."""
    if not os_name:
        return None
    for row in mapping:
        if os_name.lower().startswith(row["os_prefix"].lower()):
            return row["platform"]
    return None


def link_platforms(session) -> None:
    mapping = read_csv("os_platforms.csv")
    rows, unmapped = [], []
    for a in session.run(Q_ASSET_OS):
        platform = platform_for(a["os"], mapping)
        if platform:
            rows.append({"host": a["host"], "platform": platform})
        else:
            unmapped.append(f"{a['host']} (os={a['os']!r})")

    session.run(Q_CLEAR_RUNS_ON).consume()
    linked = {r["host"] for r in session.run(Q_RUNS_ON, rows=rows, src=SRC)}
    missing = sorted({r["platform"] for r in rows if r["host"] not in linked})
    print(f"asset -> platform: {len(linked)} RUNS_ON edges")
    if unmapped:
        print(f"  no platform for: {', '.join(unmapped)} (fill `os` in assets.csv or add a row to os_platforms.csv)")
    if missing:
        print(f"  platform not in the CTI graph: {', '.join(missing)} (check the name in os_platforms.csv)")


def link_reachability(session) -> None:
    session.run(Q_CLEAR_REACH).consume()
    n_assets = session.run(Q_REACH_ASSETS, src=SRC).single()["n"]
    n_zones = session.run(Q_REACH_ZONES, src=SRC).single()["n"]
    print(f"reachability: {n_assets} asset -> service, {n_zones} outside zone -> service CAN_REACH edges")
    for r in session.run(Q_EXPOSED):
        print(f"  reachable from {r['zone']}: {', '.join(sorted(r['services']))}")


def link(wait: int = 60) -> None:
    with driver(wait) as drv, drv.session() as session:
        link_software(session)
        link_platforms(session)
        link_reachability(session)
