"""Reproduce Nagaty et al. Table 1 against independent reference datasets.

Runs on data/processed (exactly what gets loaded into Neo4j), so no DB is needed.

Deviations from the paper, by necessity:
  * CAUSES_WEAKNESS is checked against MITRE's CAPEC STIX bundle (mitre/cti) instead of
    BRON; BRON derives the same links from the same MITRE sources but needs its own
    ArangoDB pipeline to build.
  * AFFECTS (Weakness->OS platform) is checked for supporting evidence in NVD CPEs of the
    CVEs exploiting that weakness; the paper does not describe its exact procedure.
"""
import gzip
import json
from collections import defaultdict
from datetime import date

from .. import config
from ..graph import Graph
from ..parse.attack import revoked_technique_map
from ..parse.cve import load_nvd_year

# Counts reported by Nagaty et al. (ICCA 2025), section IV.B, for side-by-side stats.
PAPER_NODES = {"Weakness": 965, "AttackPattern": None, "Technique": 656, "Tactic": 14, "Group": 159,
               "Mitigation": 991, "DetectionMethod": 19, "Platform": 54, "Vulnerability": 284296,
               "CPE": 101644}
PAPER_EDGES = {"Weakness-EXPLOITED_BY->Vulnerability": 172278,
               "Weakness-CAUSES_WEAKNESS->AttackPattern": 1212,
               "AttackPattern-USES_TECHNIQUE->Technique": 2852,  # paper counts groups + patterns together
               "Weakness-MITIGATED_BY->Mitigation": 1525,
               "Weakness-DETECTED_BY->DetectionMethod": 718,
               "Weakness-AFFECTS->Platform": 1502,
               "Weakness-IS_PARENT->Weakness": 1683,
               "Technique-SUBTECHNIQUE_OF->Technique": 453}

# OS platforms and CPE patterns that evidence them (part:vendor:product prefix, or target_sw).
OS_EVIDENCE = {
    "Windows": (("o", "microsoft", "windows"), "windows"),
    "Linux": (("o", "linux", "linux_kernel"), "linux"),
    "macOS": (("o", "apple", "mac"), "macos"),
    "Android": (("o", "google", "android"), "android"),
    "iOS": (("o", "apple", "iphone_os"), "iphone_os"),
}


def _prf(ref: set, kg: set) -> dict:
    hits = len(ref & kg)
    rec = hits / len(ref) if ref else 0.0
    prec = hits / len(kg) if kg else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"ref": len(ref), "kg": len(kg), "hits": hits,
            "recall": 100 * rec, "precision": 100 * prec, "f1": 100 * f1}


def _edges(g: Graph, etype, sl, dl) -> set:
    return {(s, d) for (t, a, s, b, d) in g.edges if (t, a, b) == (etype, sl, dl)}


def _keys(g: Graph, label) -> set:
    return {k for (l, k) in g.nodes if l == label}


def _capec_stix():
    path = config.REF_DIR / "stix-capec.json"
    objs = json.loads(path.read_text())["objects"]
    return [o for o in objs if o["type"] == "attack-pattern"
            and not o.get("revoked") and o.get("x_capec_status") not in ("Deprecated", "Obsolete")]


def check_capec_attack(g: Graph) -> dict:
    revoked = revoked_technique_map(config.ATTACK_JSON)
    ref = set()
    for o in _capec_stix():
        capec = next(r["external_id"] for r in o["external_references"] if r["source_name"] == "capec")
        for r in o["external_references"]:
            if r["source_name"] == "ATTACK":
                ref.add((capec, revoked.get(r["external_id"], r["external_id"])))
    return _prf(ref, _edges(g, "USES_TECHNIQUE", "AttackPattern", "Technique"))


def check_causes_weakness(g: Graph) -> dict:
    ref = set()
    for o in _capec_stix():
        capec = next(r["external_id"] for r in o["external_references"] if r["source_name"] == "capec")
        for r in o["external_references"]:
            if r["source_name"] == "cwe":
                ref.add((r["external_id"], capec))
    return _prf(ref, _edges(g, "CAUSES_WEAKNESS", "Weakness", "AttackPattern"))


def _years(since: int) -> range:
    return range(since, date.today().year + 1)


def check_cwe_nodes(g: Graph, since: int) -> dict:
    """CWE ids referenced by NVD (the paper used 2020-2024 feeds) vs Weakness nodes."""
    ref = set()
    for y in _years(max(since, 2020)):
        for cve in load_nvd_year(y).values():
            for w in cve.get("weaknesses", []):
                for d in w.get("description", []):
                    if d["value"].startswith("CWE-"):
                        ref.add(d["value"])
    return _prf(ref, _keys(g, "Weakness"))


def cve_layer_index() -> tuple[set, dict]:
    """Stream the CVE year shards: (all EXPLOITED_BY pairs, cve -> OS platforms evidenced by CPEs)."""
    exploited, os_of_cve = set(), defaultdict(set)
    for shard in sorted((config.PROCESSED / "cve").glob("*")):
        gy = Graph.load(shard)
        exploited |= _edges(gy, "EXPLOITED_BY", "Weakness", "Vulnerability")
        for cpe, cve in _edges(gy, "VULNERABLE_TO", "CPE", "Vulnerability"):
            p = gy.nodes.get(("CPE", cpe), {})
            for plat, ((part, vendor, prod), tsw) in OS_EVIDENCE.items():
                if ((p.get("part"), p.get("vendor")) == (part, vendor) and p.get("product", "").startswith(prod)) \
                        or p.get("target_sw") == tsw:
                    os_of_cve[cve].add(plat)
    return exploited, os_of_cve


def _ancestors(g: Graph) -> dict[str, set]:
    parents = defaultdict(set)
    for p, c in _edges(g, "IS_PARENT", "Weakness", "Weakness"):
        parents[c].add(p)
    memo = {}

    def up(cwe, seen=()):
        if cwe not in memo:
            memo[cwe] = set()
            for p in parents[cwe] - set(seen):
                memo[cwe] |= {p} | up(p, (*seen, cwe))
        return memo[cwe]
    return {c: up(c) for c in list(parents)}


def check_exploited_by(g: Graph, kg: set, since: int, most_specific: bool = False) -> dict:
    """KG CWE->CVE edges vs Galeax/CVE2CAPEC, restricted to CVEs present in both.
    CVE2CAPEC lists each CVE's CWEs plus their ancestors; most_specific=True drops every
    reference CWE that is an ancestor of another CWE listed for the same CVE."""
    anc = _ancestors(g) if most_specific else {}
    ref = set()
    for y in _years(since):
        path = config.REF_DIR / f"CVE2CAPEC-{y}.jsonl.gz"
        if not path.exists():
            continue
        with gzip.open(path, "rt") as fh:
            for line in fh:
                for cve, info in json.loads(line).items():
                    cwes = {f"CWE-{c}" for c in info.get("CWE", [])}
                    if most_specific:
                        cwes -= set().union(*(anc.get(c, set()) for c in cwes))
                    ref.update((c, cve) for c in cwes)
    cves = {c for _, c in ref} & {c for _, c in kg}
    return _prf({e for e in ref if e[1] in cves}, {e for e in kg if e[1] in cves})


def check_affects(g: Graph, exploited: set, os_of_cve: dict) -> dict:
    """Weakness->OS platform edges with supporting CPE evidence among exploiting CVEs."""
    cves_of = defaultdict(set)
    for w, cve in exploited:
        cves_of[w].add(cve)
    kg = {(w, plat) for (w, plat) in _edges(g, "AFFECTS", "Weakness", "Platform") if plat in OS_EVIDENCE}
    tested = {(w, plat) for (w, plat) in kg if cves_of[w]}
    supported = {(w, plat) for (w, plat) in tested if any(plat in os_of_cve[c] for c in cves_of[w])}
    return {"ref": len(tested), "kg": len(kg), "hits": len(supported),
            "recall": None, "precision": 100 * len(supported) / len(tested) if tested else 0.0, "f1": None}


def run(since: int) -> str:
    g = Graph.load(config.PROCESSED / "catalog")
    exploited, os_of_cve = cve_layer_index()
    rows = [
        ("CAPEC->ATT&CK edges vs CAPEC STIX", check_capec_attack(g)),
        ("CAUSES_WEAKNESS edges vs CAPEC STIX", check_causes_weakness(g)),
        (f"CWE nodes vs NVD-referenced CWEs ({max(since, 2020)}+)", check_cwe_nodes(g, since)),
        ("EXPLOITED_BY edges vs CVE2CAPEC (shared CVEs)", check_exploited_by(g, exploited, since)),
        ("EXPLOITED_BY vs CVE2CAPEC, most-specific CWEs", check_exploited_by(g, exploited, since, True)),
        ("AFFECTS (OS) edges with NVD CPE evidence", check_affects(g, exploited, os_of_cve)),
    ]
    fmt = lambda v: "–" if v is None else f"{v:.2f}"
    out = ["# CTI KG validation (cf. Nagaty et al. Table 1)", "",
           f"Graph: data/processed, CVE years {since}+. Generated {date.today()}.", "",
           "| Task | Ref | KG | Hits | Rec % | Prec % | F1 % |", "|---|---:|---:|---:|---:|---:|---:|"]
    for name, r in rows:
        out.append(f"| {name} | {r['ref']} | {r['kg']} | {r['hits']} | {fmt(r['recall'])} | "
                   f"{fmt(r['precision'])} | {fmt(r['f1'])} |")
    out += ["", "Notes: see cti_kg/validate/checks.py docstrings for each reference and deviations "
            "from the paper. CVE2CAPEC expands each CVE's CWE to its ancestors, which lowers recall.", ""]
    report = "\n".join(out)
    config.REPORTS.mkdir(parents=True, exist_ok=True)
    (config.REPORTS / "validation.md").write_text(report)
    return report


def stats_table(nodes: dict, edges: dict) -> str:
    out = ["| Node | Ours | Paper |", "|---|---:|---:|"]
    out += [f"| {k} | {nodes.get(k, 0)} | {PAPER_NODES.get(k) or '–'} |" for k in PAPER_NODES]
    out += ["", "| Edge | Ours | Paper |", "|---|---:|---:|"]
    keys = list(PAPER_EDGES) + [k for k in edges if k not in PAPER_EDGES]
    out += [f"| {k} | {edges.get(k, 0)} | {PAPER_EDGES.get(k) or '–'} |" for k in keys]
    return "\n".join(out)
