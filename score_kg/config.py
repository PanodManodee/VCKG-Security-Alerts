"""Settings for stage 4 (Environmental Vulnerability Score). Neo4j settings come from asset_kg.config.

Parameters of the paper (docs/scoring.md, Eqs. 9, 15, 16) that it leaves to the implementation:
    BETA     bounds the uplift from propagation:   EVS = min(10, Env * (1 + BETA * P(u)))
    GAMMA    discounts distant assets in P(u):     crit(v) * GAMMA ** d(u, v),  0 < GAMMA < 1
    BLAST_K  traversal depth of the blast radius:  BR_k(a, c), k = 1 in the paper
"""
import os

from asset_kg.config import ROOT

BETA = float(os.getenv("SCORE_BETA", "0.5"))
GAMMA = float(os.getenv("SCORE_GAMMA", "0.5"))
BLAST_K = int(os.getenv("SCORE_BLAST_K", "1"))
INTERNET_ZONE = os.getenv("SCORE_INTERNET_ZONE", "Internet")

# Baseline only (not part of the EVS): EPSS scores shown next to the EVS for comparison in stage 5.
EPSS_URL = os.getenv("EPSS_URL", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz")
EPSS_CSV = ROOT / "data" / "raw" / "epss" / "epss_scores-current.csv.gz"

ALERT_CONTEXTS = ROOT / "data" / "alerts" / "context"     # written by `python -m alert_kg context`
SCORES = ROOT / "data" / "scores"
ASSET_CVE_CSV = SCORES / "asset_cve_scores.csv"
ALERT_CSV = SCORES / "alert_scores.csv"
REPORTS = ROOT / "data" / "reports"
ASSESSMENTS = REPORTS / "assessments"                      # structured JSON per vulnerability instance (§III.A.4)
THREAT_REPORT = REPORTS / "threat_report.md"
SENSITIVITY_REPORT = REPORTS / "score_sensitivity.md"
