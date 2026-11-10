"""EPSS (FIRST / Empirical Security): probability of exploitation activity in the next 30 days.

The daily bulk CSV starts with a header line naming the model and score date, e.g.
    #model_version:v2026.06.15,score_date:2026-11-09T12:00:23Z
    cve,epss,percentile
It is kept in data/raw/epss/ and read into memory; it is not written into the CTI graph.
"""
import csv
import gzip

import requests

from . import config


def download() -> None:
    config.EPSS_CSV.parent.mkdir(parents=True, exist_ok=True)
    r = requests.get(config.EPSS_URL, timeout=120)      # follows the redirect to the dated file
    r.raise_for_status()
    config.EPSS_CSV.write_bytes(r.content)
    meta, scores = load()
    print(f"EPSS {meta.get('model_version')} scored {meta.get('score_date')}: {len(scores):,} CVEs -> {config.EPSS_CSV}")


def parse(lines) -> tuple[dict, dict]:
    """(metadata, {cve: (epss, percentile)}) from the CSV lines."""
    meta = {}
    lines = iter(lines)
    first = next(lines, "")
    if first.startswith("#"):
        meta = dict(part.split(":", 1) for part in first[1:].strip().split(",") if ":" in part)
    else:
        lines = iter([first, *lines])
    scores = {row["cve"]: (float(row["epss"]), float(row["percentile"])) for row in csv.DictReader(lines)}
    return meta, scores


def load() -> tuple[dict, dict]:
    if not config.EPSS_CSV.exists():
        raise SystemExit(f"{config.EPSS_CSV} not found: run `python -m score_kg epss-download`")
    with gzip.open(config.EPSS_CSV, "rt", encoding="utf-8") as fh:
        return parse(fh)
