# Code Review Notes

## **main**.py

- main program for creating CTI knowledge graph
- arugments
  - command:
    - download: data from sources (CVE, CWE, CAPEC, ATT&CK)
    - parse: the downloaded data into a structured format
    - load: load the structured data into Neo4j
    - validate: check the integrity and correctness of the loaded data
    - stats: generate statistics about the knowledge graph
    - all: run all steps in sequence
  - since-year: optional argument to specify the starting year for CVE data ingestion
  - force: optional argument to force re-download of data
  - wipe: optional argument to wipe the existing Neo4j database before loading new data

## config.py

- file paths and configuration settings
- data download URLs for CVE, CWE, CAPEC, and ATT&CK
- reference datasets for validation and alignment URls

## align/override.py

- functions to handle manual adjustments and overrides for entity merges and edge modifications
- reads CSV files from the `overrides/` directory

## align/resolve.py

Entity alignment & resolution (Nagaty et al. Phase 3).

Identifier-based sources (CVE/CWE/CAPEC/ATT&CK ids) already join exactly. Free-text
entities do not, so here we: 1. canonicalize Platform names (alias table + fuzzy match between CWE and ATT&CK names), 2. merge near-duplicate CWE mitigation texts (string similarity on descriptions).
Every automatic merge is recorded so it can be reviewed and, if wrong, undone through
overrides/ (see overrides.py).

- Fold node and re-link edges to the canonical node
- Load alias table from CSV
- Algin CWE and ATT&CK platform names using alias table and fuzzy matching
- Merge near-duplicate CWE mitigation texts using string similarity
- Skip comment lines and blank lines in CSV files

## download/common.py

HTTP fetch with conditional requests, and the raw-data manifest (provenance)

## download/cve.py

CVE records: sparse git checkout of CVEProject/cvelistV5 + NVD 2.0 yearly JSON feeds

- download CVE data from NVD JSON feeds and CVEProject GitHub repository
- Independent datasts used by `validate` (not loaded into the grpah)

## download/mitre.py

- download MITRE datasets (CWE, CAPEC, ATT&CK) from MITRE's GitHub repositories

## load/neo4j.py

Load data/processed JSONL into Neo4j with idempotent, batched UNWIND ... MERGE

- read Cypher schema from `load/schema.cypher` and apply it to the Neo4j database
- count the number of nodes and relationships loaded into Neo4j
