"""Load data/processed JSONL into Neo4j with idempotent, batched UNWIND ... MERGE."""
import json
from pathlib import Path

from neo4j import GraphDatabase
from tqdm import tqdm

from .. import config
from ..schema import NODE_KEYS

BATCH = 5000
SCHEMA_CYPHER = Path(__file__).with_name("schema.cypher")


def _batches(path: Path):
    """Create a generator that yields batches of JSON objects from a JSONL file."""
    batch = []
    with open(path) as fh:
        for line in fh:
            batch.append(json.loads(line))
            if len(batch) >= BATCH:
                yield batch
                batch = []
    if batch:
        yield batch


def _count_lines(path: Path) -> int:
    with open(path) as fh:
        return sum(1 for _ in fh)


def driver():
    return GraphDatabase.driver(config.NEO4J_URI, auth=(config.NEO4J_USER, config.NEO4J_PASSWORD))


def apply_schema(session) -> None:
    """Read Cypher schema from schema.cypher and apply it to the database. This is idempotent."""
    for stmt in SCHEMA_CYPHER.read_text().split(";"):
        lines = [ln for ln in stmt.splitlines() if not ln.strip().startswith("//")]
        if "".join(lines).strip():
            session.run("\n".join(lines))


def wipe(session) -> None:
    session.run("MATCH (n) CALL (n) { DETACH DELETE n } IN TRANSACTIONS OF 10000 ROWS")


# `sources` is unioned rather than overwritten, since the same node/edge (e.g. a CPE) can
# appear in several shards or come from several runs.
_SET_PROPS = ("WITH x, r, coalesce(x.sources, []) AS old SET x += r.props "
              "SET x.sources = old + [s IN coalesce(r.props.sources, []) WHERE NOT s IN old]")


def _run_file(session, f: Path, query: str, desc: str) -> None:
    with tqdm(total=_count_lines(f), desc=desc, leave=False) as bar:
        for rows in _batches(f):
            session.execute_write(lambda tx: tx.run(query, rows=rows).consume())
            bar.update(len(rows))


def load(processed: Path = config.PROCESSED, do_wipe: bool = False) -> None:
    """Apply the schema and load all JSONL files in processed into Neo4j. If do_wipe is True, delete all existing nodes and edges first."""
    from ..pipeline import shard_dirs

    with driver() as drv, drv.session() as session:
        if do_wipe:
            print("wiping database")
            wipe(session)
        apply_schema(session)

        for shard in shard_dirs(processed):
            print(f"loading {shard.relative_to(processed)}")
            for f in sorted((shard / "nodes").glob("*.jsonl")):
                label = f.stem
                q = f"UNWIND $rows AS r MERGE (x:`{label}` {{{NODE_KEYS[label]}: r.key}}) " + _SET_PROPS
                _run_file(session, f, q, f"nodes {label}")
            for f in sorted((shard / "edges").glob("*.jsonl")):
                sl, etype, dl = f.stem.split("__")
                q = (f"UNWIND $rows AS r "
                     f"MATCH (a:`{sl}` {{{NODE_KEYS[sl]}: r.src}}) "
                     f"MATCH (b:`{dl}` {{{NODE_KEYS[dl]}: r.dst}}) "
                     f"MERGE (a)-[x:`{etype}`]->(b) " + _SET_PROPS)
                _run_file(session, f, q, f"edges {sl}-{etype}->{dl}")


def db_counts() -> tuple[dict, dict]:
    """Count number of nodes by label and edges by type in the Neo4j database."""
    with driver() as drv, drv.session() as session:
        nodes = {r["label"]: r["n"] for r in session.run(
            "MATCH (n) UNWIND labels(n) AS label RETURN label, count(*) AS n ORDER BY n DESC")}
        edges = {r["k"]: r["n"] for r in session.run(
            "MATCH (a)-[e]->(b) RETURN labels(a)[0] + '-' + type(e) + '->' + labels(b)[0] AS k, "
            "count(*) AS n ORDER BY n DESC")}
    return nodes, edges
