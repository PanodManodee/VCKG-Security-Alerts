"""CLI: python -m score_kg {epss-download,vulns,alerts,report,sensitivity,all}

  epss-download  fetch the daily EPSS scores -> data/raw/epss/
  vulns          score every asset x CVE -> data/scores/asset_cve_scores.csv
  alerts         score the alert contexts (python -m alert_kg context) -> data/scores/alert_scores.csv, Alert.risk_*
  report         vulns + alerts + data/reports/threat_report.md
  sensitivity    re-rank under other weights -> data/reports/score_sensitivity.md
  all            report + sensitivity
"""
import argparse

from . import config


def main() -> None:
    ap = argparse.ArgumentParser(prog="score_kg", description="Context-aware rescoring and the threat report (stage 4).")
    ap.add_argument("command", choices=["epss-download", "vulns", "alerts", "report", "sensitivity", "all"])
    ap.add_argument("--weights", default=None, help="alpha,beta,gamma (default SCORE_WEIGHTS or 1,1,1)")
    ap.add_argument("--wait", type=int, default=60, help="seconds to wait for Neo4j")
    args = ap.parse_args()
    weights = tuple(float(w) for w in args.weights.split(",")) if args.weights else config.WEIGHTS
    if len(weights) != 3 or not any(weights):
        ap.error("--weights needs three numbers, not all zero")

    from . import run
    if args.command == "epss-download":
        from .epss import download
        download()
    elif args.command == "vulns":
        run.run_vulns(weights, args.wait)
    elif args.command == "alerts":
        run.run_alerts(weights, args.wait)
    elif args.command in ("report", "all"):
        run.run_report(weights, args.wait)
    if args.command in ("sensitivity", "all"):
        run.run_sensitivity(args.wait)


if __name__ == "__main__":
    main()
