"""Paths, source URLs and Neo4j settings. Values come from the environment / .env."""
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DATA = ROOT / "data"
RAW = DATA / "raw"
PROCESSED = DATA / "processed"
REPORTS = DATA / "reports"
OVERRIDES = ROOT / "overrides"
MANIFEST = RAW / "manifest.json"

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "change-me-please")

FIRST_CVE_YEAR = 1999  # cvelistV5 and CVE2CAPEC both cover CVE ids back to this year
NVD_FIRST_YEAR = 2002  # NVD's yearly JSON feeds publish nothing earlier; requesting them 404s
_since = os.getenv("CTI_SINCE_YEAR", "").strip()
SINCE_YEAR = int(_since) if _since else FIRST_CVE_YEAR

CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
ATTACK_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
              "master/enterprise-attack/enterprise-attack.json")
NVD_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
CVELIST_REPO = "https://github.com/CVEProject/cvelistV5.git"

# Reference datasets used only by `validate`
CAPEC_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
CVE2CAPEC_URL = "https://raw.githubusercontent.com/Galeax/CVE2CAPEC/main/database/CVE-{year}.jsonl.gz"

CVELIST_DIR = RAW / "cvelistV5"
CWE_ZIP = RAW / "cwec_latest.xml.zip"
CAPEC_XML = RAW / "capec_latest.xml"
ATTACK_JSON = RAW / "enterprise-attack.json"
REF_DIR = RAW / "ref"


def nvd_feed_path(year: int) -> Path:
    return RAW / f"nvdcve-2.0-{year}.json.gz"
