"""In-memory graph collector shared by all parsers, plus JSONL (de)serialization.

Nodes are keyed by (label, key); edges by (type, src_label, src_key, dst_label, dst_key).
Adding the same node/edge twice merges properties, and the `sources` provenance
lists are unioned, so independent sources can assert the same fact.
"""
import json
from collections import Counter, defaultdict
from pathlib import Path

from .schema import EDGE_TYPES, NODE_KEYS


def _clean(props: dict) -> dict:
    """Neo4j properties must be primitives or homogeneous lists of primitives."""
    out = {}
    for k, v in props.items():
        if v is None or v == "" or v == []:
            continue
        if isinstance(v, (set, tuple)):
            v = sorted(v)
        out[k] = v
    return out


class Graph:
    def __init__(self):
        self.nodes: dict[tuple, dict] = {}
        self.edges: dict[tuple, dict] = {}

    # ---- building ----

    def add_node(self, label: str, key: str, source: str, **props) -> None:
        if label not in NODE_KEYS:
            raise ValueError(f"unknown node label {label}")
        node = self.nodes.setdefault((label, key), {})
        node["sources"] = set(node.get("sources", ())) | {source}
        for k, v in props.items():
            if v not in (None, "", []):
                node[k] = v

    def add_edge(self, etype: str, src_label: str, src: str, dst_label: str, dst: str,
                 source: str, **props) -> None:
        if (etype, src_label, dst_label) not in EDGE_TYPES:
            raise ValueError(f"edge {src_label}-[{etype}]->{dst_label} not in schema")
        edge = self.edges.setdefault((etype, src_label, src, dst_label, dst), {})
        edge["sources"] = set(edge.get("sources", ())) | {source}
        for k, v in props.items():
            if v not in (None, "", []):
                edge[k] = v

    def has_node(self, label: str, key: str) -> bool:
        return (label, key) in self.nodes

    def remove_edge(self, etype, src_label, src, dst_label, dst) -> bool:
        return self.edges.pop((etype, src_label, src, dst_label, dst), None) is not None

    def prune_dangling(self, known: set | None = None) -> Counter:
        """Drop edges whose endpoints are not nodes of this graph (or in `known`, the
        (label, key) set of another shard). Returns counts per (type, missing label)."""
        known = known or set()
        dropped = Counter()
        for ek in list(self.edges):
            etype, sl, s, dl, d = ek
            for label, key in ((sl, s), (dl, d)):
                if (label, key) not in self.nodes and (label, key) not in known:
                    dropped[(etype, label)] += 1
                    del self.edges[ek]
                    break
        return dropped

    # ---- stats ----

    def node_counts(self) -> Counter:
        return Counter(label for label, _ in self.nodes)

    def edge_counts(self) -> Counter:
        return Counter(f"{sl}-{t}->{dl}" for t, sl, _, dl, _ in self.edges)

    # ---- (de)serialization ----

    def save(self, out_dir: Path) -> None:
        nodes_dir, edges_dir = out_dir / "nodes", out_dir / "edges"
        for d in (nodes_dir, edges_dir):
            d.mkdir(parents=True, exist_ok=True)
            for f in d.glob("*.jsonl"):
                f.unlink()

        by_label = defaultdict(list)
        for (label, key), props in self.nodes.items():
            by_label[label].append({"key": key, "props": _clean(props)})
        for label, rows in by_label.items():
            _write_jsonl(nodes_dir / f"{label}.jsonl", sorted(rows, key=lambda r: r["key"]))

        by_type = defaultdict(list)
        for (etype, sl, s, dl, d), props in self.edges.items():
            by_type[(etype, sl, dl)].append({"src": s, "dst": d, "props": _clean(props)})
        for (etype, sl, dl), rows in by_type.items():
            rows.sort(key=lambda r: (r["src"], r["dst"]))
            _write_jsonl(edges_dir / f"{sl}__{etype}__{dl}.jsonl", rows)

    @classmethod
    def load(cls, in_dir: Path) -> "Graph":
        g = cls()
        for f in sorted((in_dir / "nodes").glob("*.jsonl")):
            for r in _read_jsonl(f):
                g.nodes[(f.stem, r["key"])] = r["props"]
        for f in sorted((in_dir / "edges").glob("*.jsonl")):
            sl, etype, dl = f.stem.split("__")
            for r in _read_jsonl(f):
                g.edges[(etype, sl, r["src"], dl, r["dst"])] = r["props"]
        return g


def _write_jsonl(path: Path, rows: list) -> None:
    with open(path, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def _read_jsonl(path: Path):
    with open(path) as fh:
        for line in fh:
            yield json.loads(line)
