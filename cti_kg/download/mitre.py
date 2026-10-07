"""CWE, CAPEC and ATT&CK catalogs (single files published by MITRE)."""

import zipfile

from .. import config
from .common import fetch


def download_cwe(force=False):
    """Download CWE catalog (zip file containing XML). Unzip to RAW directory if needed."""
    if fetch(config.CWE_URL, config.CWE_ZIP, "cwe", force) or not list(
        config.RAW.glob("cwec_v*.xml")
    ):
        with zipfile.ZipFile(config.CWE_ZIP) as z:
            z.extractall(config.RAW)


def download_capec(force=False):
    """Download CAPEC catalog (XML)."""
    fetch(config.CAPEC_URL, config.CAPEC_XML, "capec", force)


def download_attack(force=False):
    """Download ATT&CK catalog (JSON)."""
    fetch(config.ATTACK_URL, config.ATTACK_JSON, "attack", force)
