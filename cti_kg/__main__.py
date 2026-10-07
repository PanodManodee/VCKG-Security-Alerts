"""CLI: python -m cti_kg {download,parse,load,validate,stats,all} [--since-year YYYY]"""
import argparse
import json

from . import config


def main() -> None:
    ap = argparse.ArgumentParser(prog="cti_kg", description="Build the CTI knowledge graph (CVE/CWE/CAPEC/ATT&CK).")
    ap.add_argument("command", choices=["download", "parse", "load", "validate", "stats", "all"])
    ap.add_argument("--since-year", type=int, default=config.SINCE_YEAR,
                    help=f"earliest CVE id year to ingest (default {config.SINCE_YEAR}; env CTI_SINCE_YEAR)")
    ap.add_argument("--force", action="store_true", help="re-download even if unchanged")
    ap.add_argument("--wipe", action="store_true", help="delete everything in Neo4j before loading")
    args = ap.parse_args()
    cmd = args.command

    if cmd in ("download", "all"):
        from .download import download_all
        download_all(args.since_year, args.force)

    if cmd in ("parse", "all"):
        from .pipeline import build
        report = build(args.since_year)
        print(json.dumps({k: report[k] for k in ("cve", "dangling_edges_dropped", "nodes", "edges")}, indent=2))

    if cmd in ("load", "all"):
        from .load.neo4j_loader import load
        load(do_wipe=args.wipe)

    if cmd in ("validate", "all"):
        from .validate.checks import run
        print(run(args.since_year))

    if cmd in ("stats", "all"):
        from .load.neo4j_loader import db_counts
        from .validate.checks import stats_table
        print(stats_table(*db_counts()))


if __name__ == "__main__":
    main()
