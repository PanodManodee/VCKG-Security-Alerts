"""Manual adjustments, applied after all automatic steps.

Files in overrides/ (lines starting with # are comments):
  entity_merges.csv   label,from_key,to_key,note       fold one node into another
                      (catalog labels only, not Vulnerability/CPE)
  removed_edges.csv   type,src_label,src_key,dst_label,dst_key,note
  extra_edges.csv     type,src_label,src_key,dst_label,dst_key,note   (marked manual=true)

The CVE layer is built one year at a time, so edge rows touching a Vulnerability are
routed to that CVE's year shard; all other rows apply to the catalog graph.
"""
import csv

from .. import config
from ..graph import Graph
from .resolve import Merge, _skip_comments, merge_node

CVE_LAYER = {"Vulnerability", "CPE"}


def _rows(name: str) -> list[dict]:
    path = config.OVERRIDES / name
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as fh:
        return [{k: (v or "").strip() for k, v in r.items()} for r in csv.DictReader(_skip_comments(fh))]


def edge_year(r: dict) -> int | None:
    """Year shard an edge row belongs to (None = catalog graph)."""
    for label, key in ((r["src_label"], r["src_key"]), (r["dst_label"], r["dst_key"])):
        if label == "Vulnerability":
            return int(key.split("-")[1])
    return None


class Overrides:
    def __init__(self):
        self.merges = _rows("entity_merges.csv")
        self.removed = _rows("removed_edges.csv")
        self.extra = _rows("extra_edges.csv")
        bad = [r for r in self.merges if r["label"] in CVE_LAYER]
        if bad:
            raise ValueError(f"entity_merges.csv: merging {sorted(CVE_LAYER)} nodes is not supported: {bad}")
        self.stats = {"edges_removed": 0, "edges_added": 0}

    def apply(self, g: Graph, year: int | None = None) -> list[Merge]:
        """Apply the rows that belong to this graph (year=None: the catalog graph)."""
        merges = []
        if year is None:
            for r in self.merges:
                merge_node(g, r["label"], r["from_key"], r["to_key"])
                merges.append(Merge("manual", r["label"], r["from_key"], r["to_key"], 100.0, "entity_merges.csv"))
        for r in self.removed:
            if edge_year(r) == year:
                self.stats["edges_removed"] += g.remove_edge(
                    r["type"], r["src_label"], r["src_key"], r["dst_label"], r["dst_key"])
        for r in self.extra:
            if edge_year(r) == year:
                g.add_edge(r["type"], r["src_label"], r["src_key"], r["dst_label"], r["dst_key"], "manual",
                           manual=True, note=r.get("note"))
                self.stats["edges_added"] += 1
        return merges
