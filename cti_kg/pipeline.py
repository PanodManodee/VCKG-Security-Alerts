"""Build the CTI graph from data/raw into data/processed (JSONL shards), ready for loading.

Layout:
  data/processed/catalog/{nodes,edges}/*.jsonl     CWE / CAPEC / ATT&CK layer (small)
  data/processed/cve/<year>/{nodes,edges}/*.jsonl  Vulnerability / CPE layer, one shard per CVE year

Only the catalog layer is held in memory for the whole run; CVE years are built, saved and
released one at a time, so the full corpus fits in a few GB. Alignment re-points edges by
scanning them, so it runs on the catalog layer only.
"""
import csv
import json
import shutil
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import date, datetime, timezone
from pathlib import Path

from . import config
from .align.overrides import Overrides
from .align.resolve import align_platforms, dedup_mitigations
from .download.common import read_manifest
from .graph import Graph
from .parse.attack import parse_attack, revoked_technique_map
from .parse.capec import parse_capec
from .parse.cve import parse_cves
from .parse.cwe import find_cwe_xml, parse_cwe


def shard_dirs(processed: Path = config.PROCESSED) -> list[Path]:
    """Catalog first, then CVE years ascending (the order they must be loaded in)."""
    return [processed / "catalog"] + sorted((processed / "cve").glob("*"))


def build(since_year: int) -> dict:
    for d in ("catalog", "cve"):
        shutil.rmtree(config.PROCESSED / d, ignore_errors=True)

    g = Graph()
    print("parsing ATT&CK / CWE / CAPEC")
    versions = {"attack": parse_attack(config.ATTACK_JSON, g)}
    versions["cwe"] = parse_cwe(find_cwe_xml(config.RAW), g)
    versions["capec"] = parse_capec(config.CAPEC_XML, g, revoked_technique_map(config.ATTACK_JSON))

    print("aligning entities")
    overrides = Overrides()
    merges = align_platforms(g) + dedup_mitigations(g)
    merges += overrides.apply(g)

    # CWE Observed_Examples point at CVEs: move them into the matching year shard.
    observed = defaultdict(dict)
    for ek in [ek for ek in g.edges if ek[3] == "Vulnerability"]:
        observed[int(ek[4].split("-")[1])][ek] = g.edges.pop(ek)

    dangling = g.prune_dangling()
    g.save(config.PROCESSED / "catalog")
    catalog_keys = set(g.nodes)
    nodes, edges = g.node_counts(), g.edge_counts()

    cve_stats = Counter()
    for year in range(since_year, date.today().year + 1):
        gy = Graph()
        cve_stats.update(parse_cves(gy, year, year))
        for ek, props in observed.pop(year, {}).items():
            for s in props["sources"]:
                gy.add_edge(*ek, s)
        overrides.apply(gy, year)
        dangling.update(gy.prune_dangling(known=catalog_keys))
        if gy.nodes:
            gy.save(config.PROCESSED / "cve" / str(year))
        nodes.update(gy.node_counts())
        edges.update(gy.edge_counts())
        print(f"  {year}: {gy.node_counts().get('Vulnerability', 0)} CVEs")
    for ek_by_year in observed.values():  # observed examples older than since_year
        dangling[("EXPLOITED_BY", "Vulnerability")] += len(ek_by_year)

    # CPE nodes repeat across year shards; count distinct ones.
    nodes["CPE"] = len({json.loads(line)["key"] for d in shard_dirs()
                        for f in (d / "nodes").glob("CPE.jsonl") for line in open(f)})

    _write_merges(merges)
    report = {
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "since_year": since_year,
        "versions": versions,
        "raw_manifest": read_manifest(),
        "cve": dict(cve_stats),
        "alignment_merges": len(merges),
        "overrides": overrides.stats,
        "dangling_edges_dropped": {f"{t} (missing {label})": n for (t, label), n in dangling.most_common()},
        "nodes": dict(nodes.most_common()),
        "edges": dict(edges.most_common()),
    }
    (config.PROCESSED / "build_report.json").write_text(json.dumps(report, indent=2))
    return report


def _write_merges(merges) -> None:
    path = config.PROCESSED / "alignment_report.csv"
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["step", "label", "from_key", "to_key", "score", "method"])
        w.writeheader()
        for m in merges:
            w.writerow(asdict(m))
