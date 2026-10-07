from .cve import download_cvelist, download_nvd, download_references
from .mitre import download_attack, download_capec, download_cwe


def download_all(since_year: int, force: bool = False) -> None:
    download_cwe(force)
    download_capec(force)
    download_attack(force)
    download_nvd(since_year, force)
    download_cvelist(since_year)
    download_references(since_year, force)
