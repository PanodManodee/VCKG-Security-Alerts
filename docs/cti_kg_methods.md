# CTI knowledge graph: methods

*Methods write-up for the threat side of the project. Covers what was implemented in `cti_kg/` and how. Status as of 2026-10-17.*

## 1. Objective and scope

We reproduced the threat-centric part of Nagaty et al.'s framework (*Construction of a Unified Knowledge Graph for Cyber Threat Intelligence*, ICCA 2025):

- **Phase 1:** data collection.
- **Phase 2:** construction of the cyber-threat graph.
- **Phase 3:** entity alignment and resolution.
- **Validation:** the paper's Table 1.

We also built the CPE layer that the paper puts in its Computer Asset Graph, because CPE is how the asset graph will connect to the threat graph later.

We did **not** build the paper's Phase 4 (link prediction with graph neural networks) or Phase 5 (analytics). The current build covers CVEs published from 2024 on. The full corpus is supported but hasn't been run.

## 2. Data sources (Phase 1)

We used only structured, authoritative CTI sources.

| Source | Version used | What it contributes |
|---|---|---|
| MITRE CWE (XML) | 4.20 | Weakness types, hierarchy, mitigations, detection methods, platforms |
| MITRE CAPEC (XML) | 3.9 | Attack patterns, links to CWE, links to ATT&CK |
| MITRE ATT&CK Enterprise (STIX 2.1) | release recorded in the bundle (19.2) | Techniques, tactics, groups, mitigations, platforms |
| CVE Program cvelistV5 (Git) | pinned commit | Official CVE record: description, state, CNA and CISA-ADP data |
| NVD CVE API 2.0 yearly feeds | October 2026 snapshot | CWE assignments, CPE applicability rules, CVSS scores |

Every download is recorded in `data/raw/manifest.json` (URL, ETag/Last-Modified, Git commit, time). This makes each build traceable to exact source versions, so it can be reproduced.

## 3. Schema

The graph is a typed property graph G = (V, E, λ, ρ):

- λ assigns each node one of 10 labels.
- ρ assigns each edge a relation type.
- Each edge must match one of 14 allowed (type, source label, target label) triples, listed in `cti_kg/schema.py`. The code rejects any edge outside this list.

We kept Nagaty's relation names and fixed the edge directions, which the paper leaves unspecified (see `schema.md`). The Weakness node is the hub:

- **Weakness →**
  - Vulnerability (`EXPLOITED_BY`)
  - AttackPattern (`CAUSES_WEAKNESS`)
  - Mitigation (`MITIGATED_BY`)
  - DetectionMethod (`DETECTED_BY`)
  - Platform (`AFFECTS`)
  - Weakness (`IS_PARENT`)
- **AttackPattern →** Technique (`USES_TECHNIQUE`).
- **Technique →** Tactic (`IMPLEMENTS`).
- **Sub-technique →** parent technique (`SUBTECHNIQUE_OF`).
- **Group →** Technique (`USES_TECHNIQUE`).
- **CPE →** Vulnerability (`VULNERABLE_TO`). The version range is stored as properties on the edge, so this plays the role of the paper's `AFFECTS_VERSION`.

Additions beyond the paper, each chosen for a later stage:

- **Technique → Mitigation and Technique → Platform:** ATT&CK's own mitigations, and the platforms a technique applies to.
- **Context on Vulnerability nodes:**
  - CVSS v2, v3.x and v4.0 scores, vectors and severities.
  - CISA's SSVC decision points: exploitation, automatable, technical impact.
  - The date the CVE was added to CISA's Known Exploited Vulnerabilities (KEV) catalog.
- **CWE consequence scopes and impacts on Weakness nodes.** These are inputs for re-scoring in stage 4.
- **Provenance:** every node and edge carries `sources`, the set of sources that assert it (e.g. `{nvd, cisa-adp}`). Nagaty's future-work section calls for exactly this.

## 4. Construction method (Phase 2)

Text-mining approaches such as Høst et al.'s NVD knowledge graph use named-entity recognition with SecBERT plus rule-based relation extraction. Here, by contrast, every entity and relation comes from **explicit structured fields** in the sources. That gives near-perfect precision on extraction, but the graph can only contain what the sources state explicitly.

**CWE.**
- Each CWE's `ChildOf` relations become parent→child `IS_PARENT` edges.
- `Applicable_Platforms` become `AFFECTS` edges. The source's "prevalence" is kept on the edge.
- `Detection_Methods` become `DETECTED_BY` edges, using MITRE's fixed list of 19 method names.
- `Potential_Mitigations` become Mitigation nodes:
  - A mitigation is identified by MITRE's mitigation ID where one exists.
  - Otherwise it gets a content address: a SHA-1 hash of the normalized text. Identical text used under different CWEs therefore becomes one node.
- `Related_Attack_Patterns` become `CAUSES_WEAKNESS` edges.
- `Observed_Examples` that cite CVEs become extra `EXPLOITED_BY` edges.
- Deprecated weaknesses are kept, with their status recorded.
- CWE Categories become Weakness nodes marked `abstraction = "Category"`, because NVD still assigns categories (e.g. CWE-264) to CVEs. Their member lists are not turned into `IS_PARENT` edges, because those groupings (OWASP, CERT, 7PK) would mix into the weakness hierarchy.

**CAPEC.**
- `Related_Weaknesses` become `CAUSES_WEAKNESS` edges. These are combined with CWE's links, so a link stated by both catalogs carries both sources.
- `ChildOf` becomes `IS_PARENT`.
- The ATT&CK mappings become `USES_TECHNIQUE` edges.
- Where a mapping points to an ATT&CK technique that has since been replaced, we follow ATT&CK's chain of `revoked-by` replacements to the current technique. The original ID is kept on the edge (`mapped_from`).

**ATT&CK.** Parsed with MITRE's `mitreattack-python` library, excluding revoked and deprecated objects.
- A technique is linked to a tactic when it lists that tactic among its kill-chain phases.
- Group and mitigation links come from the STIX `uses` and `mitigates` relationships.

**CVE (combining two sources).** cvelistV5 is treated as the record of truth, and NVD fills in what it lacks. The two are joined on CVE ID, one year at a time.
- **CWE assignments:** the union of three sources, with each edge recording which of them made it:
  - NVD
  - the CNA (the organization that assigned the CVE)
  - CISA-ADP (CISA's enrichment)
- **CVSS:** one score is chosen per CVSS version, in this order of precedence: NVD primary, then NVD secondary, then CNA, then CISA-ADP. The source of the chosen score is stored.
- **CPEs:** taken from NVD's applicability rules, keeping only matches marked as vulnerable.
  - The version bounds (`versionStart/End`, inclusive or exclusive) are stored on the `VULNERABLE_TO` edge.
  - If NVD has no rules for a CVE, we fall back to the CPEs listed by the CNA.
- **Rejected CVEs** are excluded.

## 5. Integration: entity alignment and resolution (Phase 3)

Nagaty describes aligning entities across sources using string matching and text similarity. We do this in two layers.

1. **Matching on identifiers.** CWE, CAPEC, ATT&CK and CVE all use stable, shared identifiers ("CWE-79" means the same thing in every source). For these entities, alignment is an exact join on the ID.
2. **Similarity matching for free-text entities:**
   - **Platforms:**
     - A curated alias table (`overrides/platform_aliases.csv`) is applied first.
     - Then ATT&CK platform names are matched to CWE's platform names by token-sort similarity (≥ 90).
   - **Mitigations:**
     - After the hash-based merging, remaining mitigations are compared by normalized edit-distance similarity (≥ 92).
     - Two official MITRE mitigation IDs are never merged into each other, because MITRE numbers such variants separately on purpose (e.g. MIT-21.1 / MIT-21.2).
   - **How a merge works:**
     - Properties are combined, with existing values kept.
     - All edges of the absorbed node move to the surviving node, and their sources are combined.
     - The absorbed node's ID is recorded in `merged_from`.

Every automatic merge is written to `data/processed/alignment_report.csv` for review. Corrections are made through override files in `overrides/`:
- entity merges
- extra edges (marked `manual = true`)
- removed edges

This provides the "room for manual adjustment" the project outline asks for.

Finally, a **referential-integrity pass** removes any edge whose endpoint doesn't exist, and reports how many were removed and why. Examples are CVEs outside the year window, and CWE IDs that are Views.

## 6. Implementation

- **Memory:**
  - The CWE/CAPEC/ATT&CK layer is held in memory as one graph.
  - The CVE/CPE layer is built **one year at a time**, and each year is written to disk as its own set of JSONL files (`data/processed/cve/<year>/`).
  - Peak memory therefore depends on the largest single year (about 1.9 GB) instead of the whole corpus.
- **Loading into Neo4j:**
  - Uniqueness constraints are created on every node key.
  - Data is loaded in batches of 5,000 rows with `UNWIND … MERGE`.
  - Loading is **idempotent**: running it twice gives identical counts, which we tested. Provenance from repeated loads is combined, not overwritten.
- **Tests:** unit tests on trimmed real records reproduce the paper's Figure 5 chain (CWE-732 → CAPEC-1 → T1574.010) and check the CVE combining logic.

## 7. Results (CVEs from 2024 on)

| | Ours | Nagaty et al. |
|---|---:|---:|
| Weakness (969 weaknesses + 422 categories) | 1,391 | 965 |
| Technique / Tactic / Group | 697 / 15 / 176 | 656 / 14 / 159 |
| DetectionMethod | 19 | 19 |
| Vulnerability / CPE | 148,591 / 50,141 | 284,296 / 101,644 (all years) |
| `CAUSES_WEAKNESS` | 1,211 | 1,212 |
| `IS_PARENT` (CWE + CAPEC) | 1,692 | 1,683 |
| `EXPLOITED_BY` | 163,163 | 172,278 |
| `VULNERABLE_TO` | 470,903 | – |

The differences in ATT&CK counts reflect newer ATT&CK releases, e.g. the new "Stealth" tactic.

**Validation (reproducing the paper's Table 1):**

| Check | Reference | Recall | Precision |
|---|---|---:|---:|
| CAPEC → ATT&CK edges | CAPEC STIX bundle (MITRE) | 99.6 % | 100 % |
| `CAUSES_WEAKNESS` edges | CAPEC STIX bundle | 100 % | 100 % |
| CWE nodes | CWE IDs referenced by NVD (2024+) | 99.7 % | 52.6 % |
| `EXPLOITED_BY` (most specific CWE per CVE) | Galeax CVE2CAPEC | 100 % | 87.2 % |

How to read these numbers:

- **The 100 % results test extraction fidelity, not semantic correctness.** The CAPEC STIX bundle and the CAPEC XML we parsed both come from MITRE. So 100 % shows we extracted the source correctly, not that the links are true. The same caveat applies to the paper's own use of BRON, which draws on the same MITRE data.
- **CWE precision is low by design.** It counts CWEs that recent NVD records never mention as false positives. The paper's equivalent figure was 37.3 %.
- **The `EXPLOITED_BY` reference was adjusted.** CVE2CAPEC lists every ancestor of each CVE's CWE. We removed the ancestors so we compare like with like. Against the raw dataset, recall is only 29 %.
- **The 12.8 % of `EXPLOITED_BY` edges that CVE2CAPEC lacks** come from CNA, CISA-ADP and CWE example assertions. CVE2CAPEC uses NVD only, so it doesn't contain them.

**Where we differ from the paper:** for `CAUSES_WEAKNESS` we validated against MITRE's CAPEC STIX bundle instead of BRON, because BRON needs its own database pipeline to build.

## 8. Limitations

1. **Explicit links only.** The graph contains no inferred links. Coverage is limited by what the sources state, and NVD has a backlog of CVEs it hasn't analysed yet. Link prediction (Nagaty Phase 4, or the TACT paper) is the natural next step.
2. **Simplified applicability rules.** NVD rules of the form "application X running on platform Y" keep only the vulnerable CPE, so the platform condition is lost.
3. **Distro backports.** NVD version ranges don't reflect Linux distro backports, which matters when assets are matched to CVEs.
4. **Mitigation merging may over-merge.** Similarity-based merging can combine templated variants that differ in meaning by one word (e.g. "leading" vs "trailing" special elements).
5. **Weak platform check.** The Weakness → Platform check has only 20 testable edges, so it isn't statistically meaningful.
6. **Year window.** Only CVEs from 2024 on are loaded so far. CWE example CVEs from before 2024 are dropped as out of scope.
