"""Load the lab CSVs (lab/*.csv) into Neo4j with idempotent UNWIND ... MERGE.

Every node and edge written here carries sources = ['asset_kg'], the same provenance field the
CTI graph uses. `--wipe` removes only the nodes this package created, never CTI nodes.
"""
import csv
import sys
from pathlib import Path

from . import config
from .db import driver
from .schema import LEVELS, NODE_KEYS

SCHEMA_CYPHER = Path(__file__).with_name("schema.cypher")
SRC = [config.SOURCE]

Q_ZONES = """
UNWIND $rows AS r
MERGE (z:Zone {name: r.name})
SET z.sources = $src
"""

Q_ASSETS = """
UNWIND $rows AS r
MERGE (a:Asset {hostname: r.hostname})
SET a.role = r.role, a.os = r.os, a.ip = r.ip,
    a.cr = r.cr, a.ir = r.ir, a.ar = r.ar, a.justification = r.justification, a.sources = $src
WITH a, r
MATCH (z:Zone {name: r.zone})
MERGE (a)-[e:IN_ZONE]->(z)
SET e.sources = $src
RETURN count(*) AS n
"""

Q_SERVICES = """
UNWIND $rows AS r
MATCH (a:Asset {hostname: r.asset})
MERGE (svc:Service {id: r.asset + ':' + toString(r.port) + '/' + r.protocol})
SET svc.name = r.service, svc.port = r.port, svc.protocol = r.protocol, svc.sources = $src
MERGE (a)-[e1:RUNS]->(svc)
SET e1.sources = $src
MERGE (sw:Software {id: r.software + ' ' + coalesce(r.package_version, r.version)})
SET sw.name = r.software, sw.version = r.version,
    sw.cpe_vendor = r.cpe_vendor, sw.cpe_product = r.cpe_product,
    sw.distro_package = r.distro_package, sw.package_version = r.package_version, sw.sources = $src
MERGE (svc)-[e2:IMPLEMENTED_BY]->(sw)
SET e2.sources = $src
RETURN count(*) AS n
"""

Q_ASSET_EDGES = """
UNWIND $rows AS r
MATCH (a:Asset {hostname: r.src}), (b:Asset {hostname: r.dst})
MERGE (a)-[e:CONNECTS_TO]->(b)
SET e.sources = $src
RETURN count(*) AS n
"""

Q_ZONE_EDGES = """
UNWIND $rows AS r
MATCH (a:Zone {name: r.src}), (b:Zone {name: r.dst})
MERGE (a)-[e:ALLOWED_TO_REACH]->(b)
SET e.sources = $src
RETURN count(*) AS n
"""

Q_WIPE = """
MATCH (n)
WHERE any(l IN labels(n) WHERE l IN $labels) AND 'asset_kg' IN coalesce(n.sources, [])
DETACH DELETE n
"""


def read_csv(name: str) -> list[dict]:
    """Read lab/<name>. Blank lines and lines starting with # are skipped (as in overrides/*.csv)."""
    with open(config.LAB / name, newline="", encoding="utf-8") as fh:
        lines = (ln for ln in fh if ln.strip() and not ln.lstrip().startswith("#"))
        return [{k.strip(): (v or "").strip() for k, v in row.items() if k}
                for row in csv.DictReader(lines)]


def check(zones, assets, services, asset_edges, zone_edges) -> None:
    """Stop with a clear message when a CSV is inconsistent, before anything is written."""
    zone_names = {z["name"] for z in zones}
    hosts = {a["hostname"] for a in assets}
    for r in assets:
        for key in ("cr", "ir", "ar"):
            if r[key] not in LEVELS:
                sys.exit(f"assets.csv: {r['hostname']} has {key}={r[key]!r}, expected L, M or H")
        if r["zone"] not in zone_names:
            sys.exit(f"assets.csv: {r['hostname']} uses unknown zone {r['zone']!r}")
        r["ip"] = r["ip"] or None
        r["os"] = r["os"] or None
        r["justification"] = r.get("justification") or None
    for r in services:
        if r["asset"] not in hosts:
            sys.exit(f"services.csv: unknown asset {r['asset']!r}")
        r["port"] = int(r["port"])
        r["cpe_vendor"] = r.get("cpe_vendor") or None
        r["cpe_product"] = r.get("cpe_product") or None
        r["distro_package"] = r.get("distro_package") or None
        r["package_version"] = r.get("package_version") or None
        if bool(r["distro_package"]) != bool(r["package_version"]):
            sys.exit(f"services.csv: {r['asset']} {r['software']}: set both distro_package and "
                     "package_version, or neither")
    for r in asset_edges:
        for end in ("src", "dst"):
            if r[end] not in hosts:
                sys.exit(f"asset_edges.csv: unknown asset {r[end]!r}")
    for r in zone_edges:
        for end in ("src", "dst"):
            if r[end] not in zone_names:
                sys.exit(f"zone_edges.csv: unknown zone {r[end]!r}")


def apply_schema(session) -> None:
    """Apply schema.cypher (idempotent)."""
    for stmt in SCHEMA_CYPHER.read_text(encoding="utf-8").split(";"):
        lines = [ln for ln in stmt.splitlines() if not ln.strip().startswith("//")]
        if "".join(lines).strip():
            session.run("\n".join(lines))


def _write(session, label: str, query: str, rows: list[dict]) -> None:
    result = session.execute_write(lambda tx: tx.run(query, rows=rows, src=SRC).data())
    n = result[0]["n"] if result and "n" in result[0] else len(rows)
    note = "" if n == len(rows) else f"   <-- only {n} of {len(rows)} rows matched, check names in the CSV"
    print(f"  {label}: {len(rows)} rows{note}")


def load(do_wipe: bool = False, wait: int = 60) -> None:
    zones, assets = read_csv("zones.csv"), read_csv("assets.csv")
    services = read_csv("services.csv")
    asset_edges, zone_edges = read_csv("asset_edges.csv"), read_csv("zone_edges.csv")
    check(zones, assets, services, asset_edges, zone_edges)

    with driver(wait) as drv, drv.session() as session:
        if do_wipe:
            print("removing nodes created by asset_kg")
            session.run(Q_WIPE, labels=list(NODE_KEYS))
        apply_schema(session)
        print("loading lab/")
        _write(session, "Zone", Q_ZONES, zones)
        _write(session, "Asset + IN_ZONE", Q_ASSETS, assets)
        _write(session, "Service + Software", Q_SERVICES, services)
        _write(session, "CONNECTS_TO", Q_ASSET_EDGES, asset_edges)
        _write(session, "ALLOWED_TO_REACH", Q_ZONE_EDGES, zone_edges)
