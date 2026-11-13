"""CLI: python -m asset_kg {load,link,validate,stats,all,wazuh-check,osv-download,wipe} [--wipe]"""
import argparse
import sys


def main() -> None:
    ap = argparse.ArgumentParser(prog="asset_kg",
                                 description="Build the computer-asset knowledge graph and link it to the CTI graph.")
    ap.add_argument("command", choices=["load", "link", "validate", "stats", "all", "wazuh-check", "osv-download", "wipe"],
                    help="wazuh-check: compare the CVE links with Wazuh's vulnerability detection (lab must run); osv-download: fetch Debian/Ubuntu security data used for distro packages; wipe: delete the nodes asset_kg created and exit, without loading (CTI nodes are never touched)")
    ap.add_argument("--wipe", action="store_true",
                    help="also delete the nodes asset_kg created before loading (load/all; CTI nodes are never touched)")
    ap.add_argument("--wait", type=int, default=60, help="seconds to wait for Neo4j to accept connections")
    args = ap.parse_args()
    cmd, ok = args.command, True

    if cmd == "wipe":
        from .loader import wipe_only
        wipe_only(wait=args.wait)

    if cmd in ("load", "all"):
        from .loader import load
        load(do_wipe=args.wipe, wait=args.wait)

    if cmd in ("link", "all"):
        from .link import link
        link(wait=args.wait)

    if cmd in ("validate", "all"):
        from .checks import run
        ok = run(args.wait)

    if cmd == "osv-download":
        from .osv import download
        download()

    if cmd == "wazuh-check":
        from .wazuh_check import run as wazuh_check
        wazuh_check(args.wait)

    if cmd in ("stats", "all"):
        from .checks import db_counts, stats_table
        print(stats_table(*db_counts(args.wait)))

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
