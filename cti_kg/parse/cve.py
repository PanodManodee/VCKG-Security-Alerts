"""CVE records -> Vulnerability and CPE nodes, EXPLOITED_BY and VULNERABLE_TO edges.

cvelistV5 is the record of truth (description, state, CNA/ADP data). The NVD 2.0 yearly
feed for the same year adds what the CNA usually omits: CWE, CPE configurations and
CVSS. Both are grouped by the year in the CVE id, so they are joined year by year.

CVSS priority: NVD Primary > NVD Secondary > CNA > CISA-ADP.
"""

import gzip
import json
import re
from datetime import date

from tqdm import tqdm

from .. import config
from ..graph import Graph

CWE_RE = re.compile(r"^CWE-\d+$")
CPE_SPLIT = re.compile(r"(?<!\\):")
CPE_FIELDS = [
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
]


def load_nvd_year(year: int) -> dict[str, dict]:
    path = config.nvd_feed_path(year)
    if not path.exists():
        return {}
    with gzip.open(path) as fh:
        return {v["cve"]["id"]: v["cve"] for v in json.load(fh)["vulnerabilities"]}


def iter_cvelist_year(year: int):
    year_dir = config.CVELIST_DIR / "cves" / str(year)
    if not year_dir.exists():
        return
    for f in year_dir.glob("*/CVE-*.json"):
        with open(f, encoding="utf-8") as fh:
            yield json.load(fh)


def parse_cpe(cpe23: str) -> dict:
    parts = CPE_SPLIT.split(cpe23)[2:]
    return {k: v for k, v in zip(CPE_FIELDS, parts) if v not in ("*", "-")}


# ---- field extraction ----


def _en(descs: list) -> str:
    for d in descs or []:
        if d.get("lang", "").startswith("en"):
            return d.get("value") or d.get("description") or ""
    return ""


def _cvelist_cvss(container: dict, key: str) -> dict | None:
    for m in container.get("metrics", []) or []:
        if key in m:
            return m[key]
    return None


def _nvd_cvss(nvd: dict, key: str) -> tuple[dict, str] | None:
    entries = (nvd or {}).get("metrics", {}).get(key, [])
    for want in ("Primary", "Secondary"):
        for e in entries:
            if e.get("type") == want:
                return e["cvssData"], f"nvd-{want.lower()}"
    return None


def _pick_cvss(nvd, cna, adps, nvd_key, cve_key):
    found = _nvd_cvss(nvd, nvd_key)
    if found:
        return found
    if cna and (d := _cvelist_cvss(cna, cve_key)):
        return d, "cna"
    for name, adp in adps:
        if d := _cvelist_cvss(adp, cve_key):
            return d, name
    return None


def _cvss_props(prefix: str, picked) -> dict:
    if not picked:
        return {}
    d, source = picked
    return {
        f"{prefix}_score": d.get("baseScore"),
        f"{prefix}_vector": d.get("vectorString"),
        f"{prefix}_severity": d.get("baseSeverity"),
        f"{prefix}_version": d.get("version"),
        f"{prefix}_source": source,
    }


def _ssvc(adps) -> dict:
    for _, adp in adps:
        for m in adp.get("metrics", []) or []:
            other = m.get("other", {})
            if other.get("type") == "ssvc":
                opts = {
                    k.lower().replace(" ", "_"): v
                    for o in other["content"].get("options", [])
                    for k, v in o.items()
                }
                return {f"ssvc_{k}": v for k, v in opts.items()}
    return {}


def _cwes(nvd, cna, adps) -> dict[str, set]:
    """cwe_id -> set of sources asserting it."""
    out: dict[str, set] = {}
    for w in (nvd or {}).get("weaknesses", []):
        for d in w.get("description", []):
            if CWE_RE.match(d.get("value", "")):
                out.setdefault(d["value"], set()).add("nvd")
    for name, cont in ([("cna", cna)] if cna else []) + adps:
        for pt in cont.get("problemTypes", []) or []:
            for d in pt.get("descriptions", []):
                cwe = d.get("cweId", "")
                if CWE_RE.match(cwe):
                    out.setdefault(cwe, set()).add(name)
    return out


def _cpe_matches(nvd, cna) -> list[tuple[str, dict, str]]:
    """(cpe23, edge props, source) for every vulnerable CPE."""
    out = []
    for conf in (nvd or {}).get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    out.append(
                        (
                            m["criteria"],
                            {
                                "version_start_including": m.get(
                                    "versionStartIncluding"
                                ),
                                "version_start_excluding": m.get(
                                    "versionStartExcluding"
                                ),
                                "version_end_including": m.get("versionEndIncluding"),
                                "version_end_excluding": m.get("versionEndExcluding"),
                            },
                            "nvd",
                        )
                    )
    if not out and cna:
        for a in cna.get("affected", []) or []:
            for cpe in a.get("cpes", []) or []:
                if cpe.startswith("cpe:2.3:"):
                    out.append((cpe, {}, "cna"))
    return out


# ---- main ----


def add_cve(g: Graph, cve_id: str, rec: dict | None, nvd: dict | None) -> None:
    """Add CVE node and edges to the graph, using cvelistV5 record and NVD 2.0 record if present."""
    meta = (rec or {}).get("cveMetadata", {})
    containers = (rec or {}).get("containers", {})
    cna = containers.get("cna")
    adps = [
        ((a.get("providerMetadata", {}).get("shortName") or "adp").lower(), a)
        for a in containers.get("adp", []) or []
    ]

    props = {
        "description": _en((cna or {}).get("descriptions"))
        or _en((nvd or {}).get("descriptions")),
        "state": meta.get("state"),
        "assigner": meta.get("assignerShortName"),
        "published": meta.get("datePublished") or (nvd or {}).get("published"),
        "last_modified": meta.get("dateUpdated") or (nvd or {}).get("lastModified"),
        "nvd_status": (nvd or {}).get("vulnStatus"),
        "kev_date_added": (nvd or {}).get("cisaExploitAdd"),
        "kev_required_action": (nvd or {}).get("cisaRequiredAction"),
        **_cvss_props(
            "cvss3",
            _pick_cvss(nvd, cna, adps, "cvssMetricV31", "cvssV3_1")
            or _pick_cvss(nvd, cna, adps, "cvssMetricV30", "cvssV3_0"),
        ),
        **_cvss_props("cvss4", _pick_cvss(nvd, cna, adps, "cvssMetricV40", "cvssV4_0")),
        **_cvss_props("cvss2", _pick_cvss(nvd, cna, adps, "cvssMetricV2", "cvssV2_0")),
        **_ssvc(adps),
    }
    srcs = [s for s, present in (("cvelistV5", rec), ("nvd", nvd)) if present]
    for s in srcs:
        g.add_node("Vulnerability", cve_id, s, **props)

    for cwe, cwe_srcs in _cwes(nvd, cna, adps).items():
        for s in cwe_srcs:
            g.add_edge("EXPLOITED_BY", "Weakness", cwe, "Vulnerability", cve_id, s)

    for cpe23, edge_props, s in _cpe_matches(nvd, cna):
        g.add_node("CPE", cpe23, s, **parse_cpe(cpe23))
        g.add_edge(
            "VULNERABLE_TO", "CPE", cpe23, "Vulnerability", cve_id, s, **edge_props
        )


def parse_cves(g: Graph, since_year: int, until_year: int | None = None) -> dict:
    """Ingest all CVEs with id year in [since_year, until_year]. Rejected CVEs are skipped."""
    until_year = until_year or date.today().year
    stats = {"cves": 0, "rejected": 0, "nvd_only": 0, "cvelist_only": 0}
    for year in range(since_year, until_year + 1):
        nvd = load_nvd_year(year)
        seen = set()
        for rec in tqdm(iter_cvelist_year(year), desc=f"CVE {year}", leave=False):
            cve_id = rec["cveMetadata"]["cveId"]
            seen.add(cve_id)
            if rec["cveMetadata"].get("state") == "REJECTED":
                stats["rejected"] += 1
                continue
            n = nvd.get(cve_id)
            stats["cvelist_only"] += n is None
            add_cve(g, cve_id, rec, n)
            stats["cves"] += 1
        for cve_id, n in nvd.items():
            if cve_id in seen:
                continue
            if n.get("vulnStatus") == "Rejected":
                stats["rejected"] += 1
                continue
            stats["nvd_only"] += 1
            add_cve(g, cve_id, None, n)
            stats["cves"] += 1
    return stats
