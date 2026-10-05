"""Entity alignment & resolution (Nagaty et al. Phase 3).

Identifier-based sources (CVE/CWE/CAPEC/ATT&CK ids) already join exactly. Free-text
entities do not, so here we:
  1. canonicalize Platform names (alias table + fuzzy match between CWE and ATT&CK names),
  2. merge near-duplicate CWE mitigation texts (string similarity on descriptions).
Every automatic merge is recorded so it can be reviewed and, if wrong, undone through
overrides/ (see overrides.py).
"""
import csv
from dataclasses import dataclass

from rapidfuzz import fuzz, process

from .. import config
from ..graph import Graph
from ..parse.xmlutil import norm_key

PLATFORM_FUZZ_THRESHOLD = 90
MITIGATION_FUZZ_THRESHOLD = 92


@dataclass
class Merge:
    step: str
    label: str
    from_key: str
    to_key: str
    score: float
    method: str


def merge_node(g: Graph, label: str, from_key: str, to_key: str) -> None:
    """Fold node (label, from_key) into (label, to_key) and re-point all its edges."""
    if from_key == to_key or (label, from_key) not in g.nodes:
        return
    src = g.nodes.pop((label, from_key))
    dst = g.nodes.setdefault((label, to_key), {})
    for k, v in src.items():
        if k == "sources":
            dst["sources"] = set(dst.get("sources", ())) | set(v)
        elif k not in dst:
            dst[k] = v
    dst["merged_from"] = sorted(set(dst.get("merged_from", [])) | {from_key} | set(src.get("merged_from", [])))

    for ek in [ek for ek in g.edges if (ek[1], ek[2]) == (label, from_key) or (ek[3], ek[4]) == (label, from_key)]:
        etype, sl, s, dl, d = ek
        props = g.edges.pop(ek)
        new_key = (etype, sl, to_key if (sl, s) == (label, from_key) else s,
                   dl, to_key if (dl, d) == (label, from_key) else d)
        if new_key[2] == new_key[4] and sl == dl:
            continue  # would become a self-loop
        existing = g.edges.setdefault(new_key, {})
        for k, v in props.items():
            if k == "sources":
                existing["sources"] = set(existing.get("sources", ())) | set(v)
            else:
                existing.setdefault(k, v)


def load_aliases() -> dict[str, str]:
    path = config.OVERRIDES / "platform_aliases.csv"
    if not path.exists():
        return {}
    with open(path) as fh:
        return {r["alias"].strip(): r["canonical"].strip()
                for r in csv.DictReader(_skip_comments(fh)) if r.get("alias")}


def align_platforms(g: Graph) -> list[Merge]:
    merges = []
    for alias, canonical in load_aliases().items():
        if g.has_node("Platform", alias):
            merge_node(g, "Platform", alias, canonical)
            merges.append(Merge("platform", "Platform", alias, canonical, 100.0, "alias_table"))

    # Fuzzy: ATT&CK platform names onto CWE platform names (CWE vocabulary is canonical).
    attack = [k for (l, k), p in g.nodes.items() if l == "Platform" and p.get("kind") == "attack_platform"]
    cwe = [k for (l, k), p in g.nodes.items() if l == "Platform" and p.get("kind") != "attack_platform"]
    for name in attack:
        if name in cwe:
            continue
        hit = process.extractOne(name, cwe, scorer=fuzz.token_sort_ratio, processor=norm_key,
                                 score_cutoff=PLATFORM_FUZZ_THRESHOLD)
        if hit:
            merge_node(g, "Platform", name, hit[0])
            merges.append(Merge("platform", "Platform", name, hit[0], hit[1], "token_sort_ratio"))
    return merges


def dedup_mitigations(g: Graph) -> list[Merge]:
    """Merge CWE mitigations whose descriptions are near-identical (exact duplicates were
    already collapsed by the text-hash key at parse time)."""
    keys = sorted(k for (l, k), p in g.nodes.items() if l == "Mitigation" and p.get("origin") == "CWE")
    # Prefer official MIT-* ids as the surviving node, then the lexicographically smallest key.
    keys.sort(key=lambda k: (not k.startswith("MIT-"), k))
    texts = [norm_key(g.nodes[("Mitigation", k)].get("description", "")) for k in keys]
    merges, absorbed = [], set()
    for i, k in enumerate(keys):
        if k in absorbed:
            continue
        hits = process.extract(texts[i], texts[i + 1:], scorer=fuzz.ratio,
                               score_cutoff=MITIGATION_FUZZ_THRESHOLD, limit=None)
        for _, score, j in hits:
            other = keys[i + 1 + j]
            # Distinct official ids (MIT-21.1 / MIT-21.2) are deliberate variants: keep both.
            if other in absorbed or (k.startswith("MIT-") and other.startswith("MIT-")):
                continue
            merge_node(g, "Mitigation", other, k)
            absorbed.add(other)
            merges.append(Merge("mitigation", "Mitigation", other, k, score, "ratio"))
    return merges


def _skip_comments(fh):
    return (line for line in fh if line.strip() and not line.lstrip().startswith("#"))
