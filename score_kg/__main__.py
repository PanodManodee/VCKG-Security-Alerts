"""CLI: python -m score_kg {epss-download,vulns,alerts,report,sensitivity,all}

  vulns          EVS of every asset x CVE (no alert, E = X) -> data/scores/asset_cve_scores.csv
  alerts         EVS of every alerted vulnerability instance (a, c) -> data/scores/alert_scores.csv,
                 structured JSON per instance in data/reports/assessments/, Alert.evs* in Neo4j
  report         vulns + alerts + data/reports/threat_report.md
  sensitivity    EVS ranking under other beta / gamma -> data/reports/score_sensitivity.md
  all            report + sensitivity
  epss-download  fetch EPSS scores (a baseline shown next to the EVS, not part of it)
"""
import argparse

from . import config


def main() -> None:
    ap = argparse.ArgumentParser(prog="score_kg", description="Environmental Vulnerability Score (paper §III.A.2-4).")
    ap.add_argument("command", choices=["epss-download", "vulns", "alerts", "report", "sensitivity", "all"])
    ap.add_argument("--beta", type=float, default=config.BETA, help="uplift bound in EVS = Env(1 + beta P)")
    ap.add_argument("--gamma", type=float, default=config.GAMMA, help="distance discount in P(u), 0 < gamma < 1")
    ap.add_argument("--k", type=int, default=config.BLAST_K, help="blast-radius depth")
    ap.add_argument("--wait", type=int, default=60, help="seconds to wait for Neo4j")
    args = ap.parse_args()
    if not 0 < args.gamma < 1:
        ap.error("--gamma must be between 0 and 1")
    if args.beta < 0 or args.k < 0:
        ap.error("--beta and --k must be >= 0")

    from . import run
    if args.command == "epss-download":
        from .epss import download
        download()
    elif args.command == "vulns":
        run.run_vulns(args.beta, args.gamma, args.wait)
    elif args.command == "alerts":
        run.run_alerts(args.beta, args.gamma, args.k, args.wait)
    elif args.command in ("report", "all"):
        run.run_report(args.beta, args.gamma, args.k, args.wait)
    if args.command in ("sensitivity", "all"):
        run.run_sensitivity(args.wait)


if __name__ == "__main__":
    main()
