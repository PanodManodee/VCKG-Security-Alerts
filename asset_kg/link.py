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

Distro packages (services.csv rows with distro_package / package_version) still get IDENTIFIED_AS
from NVD, but their HAS_VULNERABILITY edges come from the distribution's security data (osv.py),
because NVD's upstream ranges ignore backported fixes. Every HAS_VULNERABILITY edge records where
it came from in `via`: 'nvd' or 'osv:<ecosystem>' (with `fixed_version`, empty when no fix exists).
"""
from . import config, osv
from .db import driver
from .loader import read_csv
from .versions import cpe_applies

SRC = [config.SOURCE]

Q_SOFTWARE = """
MATCH (sw:Software)
RETURN sw.id AS id, sw.version AS version, sw.cpe_vendor AS vendor, sw.cpe_product AS product,
       sw.distro_package AS distro_package, sw.package_version AS package_version,
       [(sw)<-[:IMPLEMENTED_BY]-(:Service)<-[:RUNS]-(a:Asset) | a.os] AS os_names
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
UNWIND $rows AS r
MATCH (sw:Software {id: $id}), (v:Vulnerability {cve_id: r.cve})
MERGE (sw)-[e:HAS_VULNERABILITY]->(v)
SET e.sources = $src, e.via = r.via, e.fixed_version = r.fixed
RETURN count(*) AS n
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


def nvd_matches(session, sw: dict) -> tuple[list[str], list[str], str | None]:
    """(CPEs, CVEs) whose NVD range covers the upstream version, or a reason why none were looked up."""
    if not sw["vendor"] or not sw["product"]:
        return [], [], "no cpe_vendor / cpe_product in lab/services.csv"
    if sw["version"].lower() == "unknown":
        return [], [], "version is 'unknown' (fill it in lab/services.csv)"
    rows = session.run(Q_CANDIDATES, vendor=sw["vendor"], product=sw["product"]).data()
    if not rows:
        return [], [], (f"no CPE {sw['vendor']}:{sw['product']} in the CTI graph (check the pair with "
                        "`python -m asset_kg.find_cpe`, or the CVE years loaded)")
    hits = [r for r in rows if cpe_applies(sw["version"], r["cpe_version"], r["edge"])]
    return sorted({r["cpe"] for r in hits}), sorted({r["cve"] for r in hits}), None


def link_software(session) -> None:
    software = session.run(Q_SOFTWARE).data()
    ecosystems = {r["os"]: r["osv_ecosystem"] for r in read_csv("os_ecosystems.csv")}
    indexes: dict[str, dict] = {}
    print(f"software -> CPE / CVE ({len(software)} software nodes)")
    for sw in software:
        name = sw["id"]
        cpes, nvd_cves, problem = nvd_matches(session, sw)
        session.run(Q_CLEAR, id=name).consume()          # re-linking replaces old results
        if cpes:
            session.run(Q_IDENTIFIED, id=name, cpes=cpes, src=SRC).consume()

        if not sw["distro_package"]:
            if problem:
                print(f"  {name}: skipped, {problem}")
                continue
            rows = [{"cve": c, "via": "nvd", "fixed": None} for c in nvd_cves]
            n = session.run(Q_VULN, id=name, rows=rows, src=SRC).single()["n"] if rows else 0
            print(f"  {name}: NVD -> {len(cpes)} CPE, {n} CVE")
            continue

        # distro package: CVEs from the distribution's security data, per OS the software runs on
        ecos = sorted({ecosystems[o] for o in sw["os_names"] if o in ecosystems})
        missing = sorted({o for o in sw["os_names"] if o not in ecosystems})
        if missing:
            print(f"  {name}: no OSV ecosystem for OS {missing} (add it to lab/os_ecosystems.csv)")
        rows: dict[str, dict] = {}
        for eco in ecos:
            if eco not in indexes:
                indexes[eco] = osv.load_index(eco)
            for cve, fixed in osv.affected_cves(indexes[eco], sw["distro_package"], sw["package_version"]).items():
                rows.setdefault(cve, {"cve": cve, "via": f"osv:{eco}", "fixed": fixed})
        n = session.run(Q_VULN, id=name, rows=list(rows.values()), src=SRC).single()["n"] if rows else 0
        print(f"  {name}: OSV {', '.join(ecos) or '-'} ({sw['distro_package']} {sw['package_version']}) -> "
              f"{len(rows)} CVE, {n} of them in the CTI graph  [NVD upstream ranges would give {len(nvd_cves)}]")


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
