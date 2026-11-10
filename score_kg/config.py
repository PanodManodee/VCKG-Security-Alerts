"""Settings for stage 4 (rescoring). Neo4j settings come from asset_kg.config (same .env, same database)."""
import os

from asset_kg.config import ROOT

# α (EPSS threat), β (blast radius), γ (alert evidence) in R = S_env + (10 - S_env)(αT + βG + γA)/(α+β+γ).
# Equal by default; `python -m score_kg sensitivity` shows how much the ranking depends on them.
WEIGHTS = tuple(float(w) for w in os.getenv("SCORE_WEIGHTS", "1,1,1").split(","))

EPSS_URL = os.getenv("EPSS_URL", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz")
EPSS_CSV = ROOT / "data" / "raw" / "epss" / "epss_scores-current.csv.gz"

ALERT_CONTEXTS = ROOT / "data" / "alerts" / "context"     # written by `python -m alert_kg context`
SCORES = ROOT / "data" / "scores"
ASSET_CVE_CSV = SCORES / "asset_cve_scores.csv"
ALERT_CSV = SCORES / "alert_scores.csv"
REPORTS = ROOT / "data" / "reports"
THREAT_REPORT = REPORTS / "threat_report.md"
SENSITIVITY_REPORT = REPORTS / "score_sensitivity.md"

BLAST_HOPS = 3        # how far G looks from a compromised asset (same as alert_kg's blast radius)
