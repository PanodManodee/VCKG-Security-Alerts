# Context-aware vulnerability classification — CTI knowledge graph

Stage 2, step 1 of `ref_papers/outline_n_ideas.md`: the Cyber Threat Intelligence knowledge graph,
built the way Nagaty et al. (ICCA 2025) describe, from CVE (cvelistV5 + NVD), CWE, CAPEC and
MITRE ATT&CK. Schema and edge directions: [schema.md](schema.md).

## Run

```bash
cp .env.example .env            # set NEO4J_PASSWORD, optionally CTI_SINCE_YEAR
docker compose up -d            # Neo4j 5 + APOC, browser at http://localhost:7474
pip install -r requirements.txt

python -m cti_kg all --since-year 2024   # download -> parse -> load -> validate -> stats
```

Steps can be run on their own: `download`, `parse`, `load [--wipe]`, `validate`, `stats`.
Leaving out `--since-year` (and `CTI_SINCE_YEAR`) ingests the full CVE corpus (1999+).

| Step | Output |
|---|---|
| download | `data/raw/` + `data/raw/manifest.json` (source versions, ETags, git commit) |
| parse | `data/processed/{catalog,cve/<year>}/` JSONL, `build_report.json`, `alignment_report.csv` |
| load | Neo4j (idempotent MERGE; `--wipe` for a clean rebuild) |
| validate | `data/reports/validation.md` (reproduction of the paper's Table 1) |

## Manual adjustments

Edit `overrides/*.csv` (platform aliases, entity merges, added/removed edges) and re-run
`parse` + `load --wipe`. Review automatic merges in `data/processed/alignment_report.csv`.

## Tests

```bash
python -m pytest tests
```
