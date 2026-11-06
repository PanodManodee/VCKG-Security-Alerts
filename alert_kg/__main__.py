"""CLI: python -m alert_kg {fetch,load,context,all}

  fetch    Wazuh indexer -> data/alerts/raw.jsonl
  load     raw.jsonl (or --input FILE) -> Alert nodes linked to Asset / Technique / CVE / source
  context  graph queries per alert -> data/alerts/context/<alert_id>.json
  all      fetch -> load -> context
"""
import argparse
from pathlib import Path

from . import config


def main() -> None:
    ap = argparse.ArgumentParser(prog="alert_kg", description="Map Wazuh alerts onto the unified knowledge graph.")
    ap.add_argument("command", choices=["fetch", "load", "context", "all"])
    ap.add_argument("--since", default="24h", help="fetch: time window, OpenSearch date math (24h, 7d, ...)")
    ap.add_argument("--min-level", type=int, default=3, help="fetch/context: minimum rule.level")
    ap.add_argument("--input", type=Path, default=config.RAW_ALERTS, help="load: JSONL of indexer hits")
    ap.add_argument("--wipe", action="store_true", help="load: delete existing Alert nodes first")
    ap.add_argument("--alert", help="context: only this alert_id")
    ap.add_argument("--all-alerts", action="store_true",
                    help="context: also alerts without a technique or CVE (e.g. SCA results)")
    ap.add_argument("--wait", type=int, default=60, help="seconds to wait for Neo4j")
    args = ap.parse_args()

    if args.command in ("fetch", "all"):
        from .fetch import fetch
        fetch(args.since, args.min_level)
    if args.command in ("load", "all"):
        from .load import load
        load(args.input, do_wipe=args.wipe or args.command == "all", wait=args.wait)
    if args.command in ("context", "all"):
        from .context import context
        context(args.alert, args.min_level, args.all_alerts, args.wait)


if __name__ == "__main__":
    main()
