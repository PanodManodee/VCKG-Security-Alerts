"""Sanity checks and counts for the asset graph (counterpart of cti_kg/validate and `stats`)."""
from .db import driver
from .schema import EDGE_TYPES, NODE_KEYS

ASSET_EDGE_TYPES = sorted({t for t, _, _ in EDGE_TYPES})


def db_counts(wait: int = 60) -> tuple[dict, dict]:
    with driver(wait) as drv, drv.session() as s:
        nodes = {lb: s.run(f"MATCH (n:`{lb}`) RETURN count(n) AS n").single()["n"] for lb in NODE_KEYS}
        edges = {r["t"]: r["n"] for r in s.run(
            "MATCH ()-[e]->() WHERE type(e) IN $types AND 'asset_kg' IN coalesce(e.sources, []) "
            "RETURN type(e) AS t, count(*) AS n ORDER BY n DESC", types=ASSET_EDGE_TYPES)}
    return nodes, edges


def stats_table(nodes: dict, edges: dict) -> str:
    lines = ["asset graph", "  nodes"] + [f"    {k:<18}{v}" for k, v in nodes.items()]
    lines += ["  edges"] + [f"    {k:<18}{v}" for k, v in edges.items()]
    return "\n".join(lines)


def run(wait: int = 60) -> bool:
    """Print the checks and return True when nothing is wrong."""
    ok = True
    with driver(wait) as drv, drv.session() as s:
        def rows(q, **p):
            return s.run(q, **p).data()

        print("validation")
        checks = [
            ("assets without exactly one zone",
             "MATCH (a:Asset) OPTIONAL MATCH (a)-[:IN_ZONE]->(z) "
             "WITH a, count(z) AS n WHERE n <> 1 RETURN a.hostname AS x"),
            ("services without software",
             "MATCH (s:Service) WHERE NOT (s)-[:IMPLEMENTED_BY]->() RETURN s.id AS x"),
            ("CONNECTS_TO edges that are not Asset to Asset",
             "MATCH (a)-[:CONNECTS_TO]->(b) WHERE NOT (a:Asset AND b:Asset) RETURN a.hostname AS x"),
            ("CPE nodes created by asset_kg (must be none)",
             "MATCH (c:CPE) WHERE 'asset_kg' IN coalesce(c.sources, []) RETURN c.cpe23 AS x"),
            ("Platform nodes created by asset_kg (must be none)",
             "MATCH (p:Platform) WHERE 'asset_kg' IN coalesce(p.sources, []) RETURN p.name AS x"),
            ("assets without a platform (RUNS_ON)",
             "MATCH (a:Asset) WHERE NOT (a)-[:RUNS_ON]->(:Platform) RETURN a.hostname AS x"),
            ("CAN_REACH edges to a service of the same asset",
             "MATCH (a:Asset)-[:CAN_REACH]->(:Service)<-[:RUNS]-(a) RETURN a.hostname AS x"),
        ]
        for title, q in checks:
            bad = [r["x"] for r in rows(q)]
            ok &= not bad
            print(f"  {'ok ' if not bad else 'BAD'} {title}: {bad or 'none'}")

        cov = s.run("MATCH (sw:Software) RETURN count(sw) AS total, "
                    "sum(CASE WHEN (sw)-[:IDENTIFIED_AS]->() THEN 1 ELSE 0 END) AS linked").single()
        print(f"  CPE linking coverage: {cov['linked']}/{cov['total']} software nodes")

        print("  CVEs per asset (via Software -> HAS_VULNERABILITY):")
        per_asset = rows(
            "MATCH (a:Asset)-[:RUNS]->(:Service)-[:IMPLEMENTED_BY]->(sw:Software)"
            "-[:HAS_VULNERABILITY]->(v:Vulnerability) "
            "RETURN a.hostname AS asset, count(DISTINCT v) AS cves, max(v.cvss3_score) AS max_cvss3 "
            "ORDER BY cves DESC")
        for r in per_asset:
            print(f"    {r['asset']}: {r['cves']} CVE, max CVSS v3 {r['max_cvss3']}")
        if not per_asset:
            print("    none yet (run `link`; check vendor/product/version in lab/services.csv)")

        print("  per asset: platform, ATT&CK techniques for it, services it can reach, who reaches it:")
        for r in rows(
                "MATCH (a:Asset) "
                "OPTIONAL MATCH (a)-[:RUNS_ON]->(p:Platform) "
                "WITH a, collect(DISTINCT p.name) AS platforms, "
                "     COUNT { MATCH (a)-[:RUNS_ON]->(:Platform)<-[:AFFECTS]-(t:Technique) RETURN DISTINCT t } AS techniques, "
                "     COUNT { (a)-[:CAN_REACH]->(:Service) } AS reaches, "
                "     COUNT { MATCH (x)-[:CAN_REACH]->(:Service)<-[:RUNS]-(a) RETURN DISTINCT x } AS reached_by "
                "RETURN a.hostname AS asset, platforms, techniques, reaches, reached_by, "
                "       coalesce(a.internet_exposed, false) AS exposed ORDER BY asset"):
            flag = "  INTERNET-EXPOSED" if r["exposed"] else ""
            print(f"    {r['asset']}: {', '.join(r['platforms']) or '-'}, {r['techniques']} techniques, "
                  f"reaches {r['reaches']} services, reached by {r['reached_by']}{flag}")
    return ok
