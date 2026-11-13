"""CVE records: sparse git checkout of CVEProject/cvelistV5 + NVD 2.0 yearly JSON feeds."""

import subprocess
from datetime import date

from .. import config
from .common import fetch, update_manifest


def _git(*args, cwd=None) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def download_cvelist(since_year: int):
    """Shallow, blobless, sparse clone: only cves/<year> directories >= since_year are checked out."""
    repo = config.CVELIST_DIR
    years = [f"cves/{y}" for y in range(since_year, date.today().year + 1)]
    if not (repo / ".git").exists():
        print("  cvelistV5: cloning (sparse)")
        _git(
            "clone",
            "--depth",
            "1",
            "--filter=blob:none",
            "--sparse",
            config.CVELIST_REPO,
            str(repo),
        )
    else:
        # A shallow clone cannot fast-forward across fetched history; this is a read-only
        # mirror, so just move to the newest upstream commit.
        print("  cvelistV5: updating")
        _git("fetch", "--depth", "1", "origin", "main", cwd=repo)
        _git("reset", "--hard", "FETCH_HEAD", cwd=repo)
    _git("sparse-checkout", "set", *years, cwd=repo)
    update_manifest(
        "cvelistV5",
        url=config.CVELIST_REPO,
        commit=_git("rev-parse", "HEAD", cwd=repo),
        commit_date=_git("log", "-1", "--format=%cI", cwd=repo),
        years=f"{since_year}-",
    )


def download_nvd(since_year: int, force=False):
    """Download NVD 2.0 JSON feeds for each year >= since_year (clamped to NVD_FIRST_YEAR, the
    earliest year NVD actually publishes a feed for). These are used to populate the graph with
    CVE metadata and fill in the missing CVE records from cvelistV5."""
    for year in range(max(since_year, config.NVD_FIRST_YEAR), date.today().year + 1):
        fetch(
            config.NVD_FEED_URL.format(year=year),
            config.nvd_feed_path(year),
            f"nvd-{year}",
            force,
        )


def download_references(since_year: int, force=False):
    """Independent datasets used by `validate` (not loaded into the graph)."""
    fetch(
        config.CAPEC_STIX_URL,
        config.REF_DIR / "stix-capec.json",
        "ref-capec-stix",
        force,
    )
    for year in range(max(since_year, 1999), date.today().year + 1):
        fetch(
            config.CVE2CAPEC_URL.format(year=year),
            config.REF_DIR / f"CVE2CAPEC-{year}.jsonl.gz",
            f"ref-cve2capec-{year}",
            force,
        )
