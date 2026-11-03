# Mapping Wazuh Alerts onto a Linked Asset + CTI Knowledge Graph and Querying for Attack Paths / Affected Assets

Scope note: the project's CTI KG follows the Nagaty et al. (ICCA 2025) schema: Weakness(CWE)-[:EXPLOITED_BY]->Vulnerability(CVE); Weakness-[:CAUSES_WEAKNESS]->AttackPattern(CAPEC)-[:USES_TECHNIQUE]->Technique(ATT&CK)-[:IMPLEMENTS]->Tactic; Group-[:USES_TECHNIQUE]->Technique; CPE-[:VULNERABLE_TO]->Vulnerability; plus MITIGATED_BY. An asset KG is planned. Asset ontologies, CPE matching and scoring formulas are deliberately out of scope here.

## Q1. Wazuh alert JSON structure, MITRE coverage of the default ruleset, and how to retrieve alerts

### Takeaway
A Wazuh 4.x alert carries enough structured fields to map it to the KG without any NLP:
- `rule.mitre.id`, `rule.mitre.tactic` and `rule.mitre.technique` link to Technique and Tactic.
- `agent.id`, `agent.name` and `agent.ip` link to the Host.
- `data.srcip` and `data.dstuser` give the attacker IP and the targeted account.
- The `vulnerability.*` fields link to CVE.

Only about 22.5% of default rules (v4.14.1) carry a MITRE ID, so many alerts will have no technique. For host→CVE facts, the `wazuh-states-vulnerabilities-*` index is a better source than alerts. Read alerts from the indexer (`wazuh-alerts-4.x-*`), from `alerts.json`, or push them through an integratord `custom-*` script.

### Cited Findings
**MITRE fields in alerts**
- Rules map to ATT&CK through a `<mitre><id>T…</id></mitre>` block in the rule XML. When the rule fires, the alert carries `rule.mitre.id` (e.g. `["T1543.003"]`), `rule.mitre.technique` (e.g. `["Windows Service"]`) and `rule.mitre.tactic` (e.g. `["Persistence","Privilege Escalation"]`). These are arrays, because one rule can map to several techniques and tactics. The documented example alert also has `rule.id` (110011), `rule.level` (10) and `rule.description`. — [Wazuh docs: MITRE ATT&CK framework](https://documentation.wazuh.com/current/user-manual/ruleset/mitre.html)
- Wazuh "ships detection rules mapped against relevant MITRE IDs" and lets custom rules add IDs. The docs give no count of mapped rules and no ATT&CK version. — [Wazuh docs: MITRE](https://documentation.wazuh.com/current/user-manual/ruleset/mitre.html)

**MITRE coverage of the v4.14.1 ruleset (my own count)**
- Method: a sparse clone of `wazuh/wazuh` at tag v4.14.1, `ruleset/rules/*.xml` (168 files), then a regex over `<rule>…</rule>` blocks that contain `<id>T####(.###)?</id>`. — [wazuh/wazuh ruleset @ v4.14.1](https://github.com/wazuh/wazuh/tree/v4.14.1/ruleset/rules)
- Results:
  - 4,515 rules in total, of which 1,015 (22.5%) carry at least one MITRE technique ID.
  - 166 distinct technique IDs are used.
  - The most frequent are T1484 (107 rules), T1110 brute force (92), T1078 valid accounts (90), T1499 (48), T1055 (38), T1114 (36), T1047 (27), T1531 (25), T1489 (25), T1133 (23), T1105 (20), T1070.004 (20), T1112 (19) and T1059.001 (19).
- Caveat: the regex does not exclude XML-commented rules, so the figures may be slightly high. This is a count of rules mapped to ATT&CK, not of attacks detected.
- Older Wazuh docs (4.4) describe the default ruleset as "more than 3,000 rules". That figure is outdated next to the 4,515 counted for v4.14.1. — [Wazuh 4.4 log analysis](https://documentation.wazuh.com/4.4/getting-started/use-cases/log-analysis.html)

**FIM (syscheck) rules carry MITRE IDs**
- Rule 550 ("Integrity checksum changed", level 7) → T1565.001.
- Rule 553 ("File deleted", level 7) → T1070.004 and T1485.
- Rule 554 ("File added", level 5) has no MITRE ID.
- Source: `0015-ossec_rules.xml` in the [ruleset @ v4.14.1](https://github.com/wazuh/wazuh/blob/v4.14.1/ruleset/rules/0015-ossec_rules.xml)

**Vulnerability-detector rules (`0520-vulnerability-detector_rules.xml`)**
- Rule 23501 (level 0) matches JSON events that have a `vulnerability.cve` field.
- Its children select on `vulnerability.status` and `vulnerability.severity`:
  - 23502: Solved (level 3).
  - 23503: Active/Low (level 5).
  - 23504: Active/Medium or Untriaged (level 7).
  - 23505: Active/High (level 10).
  - 23506: Active/Critical (level 13).
  - 23507: Clear.
- The rule descriptions are `$(vulnerability.cve) affects $(vulnerability.package.name)`. — [ruleset @ v4.14.1](https://github.com/wazuh/wazuh/blob/v4.14.1/ruleset/rules/0520-vulnerability-detector_rules.xml)

**Vulnerability detection: the states index versus alerts (Wazuh ≥4.8)**
- The detector correlates the Syscollector software inventory with the Wazuh CTI feed, or with an offline copy of it. — [Wazuh docs: Vulnerability detection](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html)
- The "how it works" page shows a document whose `_index` is `wazuh-states-vulnerabilities-server`. This is a state document, not an alert. Its fields:
  - `agent.{id,name,type,version}`, `host.os.{full,name,platform,type,version}`
  - `package.{name,version,architecture,type}`
  - `vulnerability.{id,severity,score.base,score.version,description,category,classification,enumeration,detected_at,published_at,reference,scanner.condition,scanner.source,scanner.vendor,under_evaluation}`
  - Example: `vulnerability.id = "CVE-2025-4050"`, package Google Chrome 134.0.6998.118, `scanner.condition = "Package less than 136.0.7103.59"`. — [Wazuh docs: Vulnerability detection – how it works](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html)
- When alerts are generated (same page):
  - They fire only when a vulnerability is newly detected or resolved.
  - OS alerts do not fire on the initial inventory scan.
  - Package changes made while the agent was stopped do not alert.
  - Feed-content updates re-evaluate agents without alerting.
  - Source: [same page](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html)
- Field paths conflict between the docs and the ruleset. The docs page shows top-level `vulnerability.*` (states index), while the rules match decoded fields `vulnerability.cve`, `vulnerability.package.name` and so on. Neither source shows the exact path these take inside a `wazuh-alerts-*` document (see Inferences).

**Retrieving alerts**
- The indexer stores alerts generated by the server in the `wazuh-alerts-4.x-*` indices.
- It exposes a REST API (OpenSearch, port 9200) for searches.
- The documented example query is `GET /wazuh-alerts-4.x-*/_search` with a `bool`/`must` filter on `rule.mitre.tactic` and `rule.mitre.technique`, sorted by `timestamp` descending.
- Source: [Wazuh docs: Wazuh indexer](https://documentation.wazuh.com/4.12/getting-started/components/wazuh-indexer.html)
- Integratord pushes alerts to a script:
  - Configure `<integration><name>custom-…</name><hook_url/><level/><rule_id/><group/><alert_format>json</alert_format></integration>`.
  - Each matching alert is written to `/tmp/<name>-<ts>-<rand>.alert`, and the script receives that path as `sys.argv[1]`.
  - `level` filters by minimum rule level. Setting both `rule_id` and `group` requires a match on both.
  - The raw alert log is `/var/ossec/logs/alerts/alerts.json`.
  - Source: [Wazuh docs: Integration with external APIs](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
- In Wazuh 5.0 (beta/rc), rules move to a Sigma-format syntax with Wazuh extensions for MITRE mapping. Code that parses the 4.x XML ruleset may need adapting. — [Wazuh 5.0-rc docs: rules](https://documentation.wazuh.com/5.0-rc/user-manual/data-analysis/rules.html)

### Inferences
**Pull versus push**
- Pull from the indexer, not the manager API. The existing `old_design/wazuh_connector.py` calls the manager API (port 55000), which serves agents, FIM, SCA and vulnerability endpoints, not alert history.
- Add an OpenSearch client: `requests` with basic auth, or `opensearch-py`.
- Query `wazuh-alerts-4.x-*` with a `range` on `timestamp`, `rule.level >= N` and `exists: rule.mitre.id`. Use `search_after` for paging.
- Query `wazuh-states-vulnerabilities-*` for host→CVE.
- For near-real-time processing, a `custom-kg` integratord script is simpler than polling.

**Host→CVE edges come from the states index**
- Vulnerability alerts are change events only. Use the states index to build `(:Host)-[:HAS_VULNERABILITY]->(:Vulnerability)` edges in the asset KG.
- This gives a direct host→CVE link (with `package.*` as the software node), with no CPE matching needed. CPE then serves only to link to the CTI side.

**Alert field paths**
- Wazuh places JSON-decoded dynamic fields under `data.` in `wazuh-alerts-*`. Vulnerability alerts should therefore appear as `data.vulnerability.cve`, `data.vulnerability.package.name`, `data.vulnerability.severity`, `data.vulnerability.status`, and similar.
- I infer this from the decoder and rule fields. It is not confirmed in a fetched doc, so check one live alert in `alerts.json`.

**Field → KG node mapping**

| Field | KG node or role |
|---|---|
| `rule.mitre.id[]` | Technique |
| `rule.mitre.tactic[]` | Tactic |
| `agent.id` / `agent.name` / `agent.ip` | Host (victim) |
| `data.srcip` | external IP / attacker host |
| `data.dstuser` / `data.srcuser` | Account |
| `data.win.eventdata.{image,parentImage,commandLine,targetFilename,user}` | Process / File / Account, for Sysmon-derived Windows alerts |
| `syscheck.path` | File on Host |
| `data.vulnerability.cve` | Vulnerability |
| `data.vulnerability.package.name` | Software on Host |
| `rule.groups[]` | coarse category (`authentication_failed`, `syscheck`, `web`, `sysmon`, …) |

**Sub-techniques and unmapped rules**
- `rule.mitre.id` mixes sub-techniques (T1070.004) with parent techniques. The KG must hold both, with `SUBTECHNIQUE_OF`, or normalise to the parent for matching.
- With about 77% of rules unmapped, a fallback mapping is needed for alerts that have no `rule.mitre.id` (see Q2).

### Gaps
- No official Wazuh figure exists for the number of MITRE-mapped rules or the ATT&CK version the 4.x ruleset uses. The 22.5% above is my own regex count.
- I did not fetch a live `wazuh-alerts-*` vulnerability alert, so the exact `data.vulnerability.*` subfields (for example `cvss.cvss3.base_score` versus `score.base`) are unconfirmed for 4.8+.
- `old_design/wazuh_connector.py::get_agent_vulnerabilities` calls the manager API. I could not confirm whether the 4.8+ manager API still serves per-agent vulnerabilities. If it does not, query `wazuh-states-vulnerabilities-*` in the indexer instead.
- An unverified Google Groups post claims only 3 of 24 replayed techniques alerted on a default install ([thread](https://groups.google.com/g/wazuh/c/xCNva7qg-R4)). It measures detection, not mapping, and is anecdotal.

## Q2. Entity and relation extraction from alerts and logs: field mapping vs NER vs LLM, and alert→ATT&CK mapping

### Takeaway
For Wazuh, deterministic field mapping (structured JSON → typed KG nodes) should be the primary method. NER models (CyNER, SecureBERT and descendants) are trained on CTI prose and fit free-text parts such as `full_log` and `rule.description` poorly. Recent LLM work (RAM 2025, and others) maps SIEM rules or log segments to ATT&CK. It is useful offline, to back-fill technique IDs for the roughly 77% of Wazuh rules with no `<mitre>` tag, rather than per-alert at runtime.

### Cited Findings
- **RAM (Rule-ATT&CK Mapper):** Wudali et al., 2025, arXiv 2502.02337. A multi-stage, prompt-chaining LLM pipeline that maps structured SIEM rules (Splunk/Sigma style) to ATT&CK techniques without pre-training or fine-tuning. The authors note that earlier ML work targeted free-text CTI reports rather than structured rules. — [arXiv 2502.02337](https://arxiv.org/html/2502.02337v1)
- **Security Logs to ATT&CK Insights:** arXiv 2510.20930. Uses an LLM to segment IDS log activity into behavioural phases and map each phase to probable ATT&CK techniques. — [alphaXiv 2510.20930](https://www.alphaxiv.org/abs/2510.20930)
- **Fine-tuned lightweight LLM for alerts:** fine-tuned on alerts and attack descriptions labelled with ATT&CK techniques, evaluated over 367 techniques. The authors claim it outperforms RAM. I saw only slides, so this is unverified. — [iai.sbu.ac.ir slides](https://iai.sbu.ac.ir/Areas/Panel/Hamayesh/3/Files/iai-1182.pdf)
- **Theses:**
  - TU Wien compares ChatGPT and Gemini on classifying IDS alerts as true or false positive and assigning ATT&CK techniques, including the effect of extra log context and few-shot examples. — [TU Wien repositum](https://repositum.tuwien.at/handle/20.500.12708/226916?mode=full)
  - Politecnico di Torino (2025) studies LLM mapping of Windows telemetry to ATT&CK. — [PoliTo thesis](https://webthesis.biblio.polito.it/37688/)
- **CyNER:** Alam et al., 2022. A Python library that combines transformer NER, regex/heuristic IOC extraction and generic NER (spaCy/Flair). Its best model, XLM-RoBERTa-large, reached 76.66% span micro-F1 on its CTI corpus. — [arXiv 2204.05754](https://arxiv.org/abs/2204.05754v1)
- **SecureBERT:**
  - The original is a RoBERTa-based cybersecurity LM with a custom tokenizer, evaluated on MLM, sentiment and NER. — [ar5iv 2204.02685](https://ar5iv.labs.arxiv.org/html/2204.02685)
  - SecureBERT 2.0 (2025) reports NER on expert-annotated threat-intel reports. — [arXiv 2510.00240](https://arxiv.org/pdf/2510.00240)
  - SecureModernBERT-NER (Hugging Face) recognises 22 CTI entity types. — [HF model card](https://huggingface.co/attack-vector/SecureModernBERT-NER/blob/main/README.md)
- **Merged CyNER + APTNER:** combined into a seven-label scheme, with gains reported from the merged resource. — [CEUR-WS Vol-3928 paper 170](https://ceur-ws.org/Vol-3928/paper_170.pdf)
- **CVE→ATT&CK classification:** a CVE→TTP knowledge graph built with transformer classification (CySecBERT) reports macro-F1 of 87.71% for techniques and 96.16% for tactics. The year was not given in the result. — [CatalyzeX listing](https://www.catalyzex.com/author/Swati%20Yadav)
- **Project reference paper (Dong & Geng, IEEE DSC 2024):**
  - Pipeline: BiLSTM-CRF NER over vulnerability text, Jiagu relation extraction (422 triples), py2neo write into Neo4j (59,783 nodes, 59,679 edges, 56 relation types).
  - Queries: a BERT classifier plus extracted entities query the KG for similar vulnerabilities by category, hazard level and entity.
  - Scope: this is NER over vulnerability descriptions, not over alerts.
  - Source: [doi 10.1109/DSC63484.2024.00030](https://doi.org/10.1109/DSC63484.2024.00030)
- **Wazuh 5.0 rules:** Sigma-format with Wazuh extensions for MITRE mapping. — [Wazuh 5.0-rc rules](https://documentation.wazuh.com/5.0-rc/user-manual/data-analysis/rules.html)

### Inferences
**Recommended tiered extraction pipeline (implementable in Python)**
1. Deterministic JSON-path mapping. This covers almost all entity types, as in the Q1 table.
2. Regex/IOC extraction on `full_log` and `data.win.eventdata.commandLine` for IPs, hashes, URLs, file paths and CVE IDs. CyNER's heuristic module, or plain regex, is enough here.
3. For alerts with no MITRE tag:
   - A static rule.id→technique lookup built offline. Use an LLM in the RAM style over the rule XML (description, groups, decoded fields), plus manual review.
   - Alternatively, inherit the technique from a parent rule (`if_sid`).
4. Optional: a transformer or LLM classifier on `rule.description` + `full_log` as a last resort, evaluated against Atomic Red Team ground truth (Q5).

**Relations**
- Relations come mostly from the alert's structure, not from text:
  - `(Alert)-[:ON_HOST]->(Host)`
  - `(Alert)-[:INDICATES]->(Technique)`
  - `(Alert)-[:FROM_IP]->(IP)`
  - `(Alert)-[:TARGETS_ACCOUNT]->(Account)`
  - `(Alert)-[:REFERS_TO]->(Vulnerability)`
- Cross-alert relations (same host, same srcip, temporal order) are created by correlation (Q3).

**Sigma tags**
- If Wazuh 5.x keeps Sigma-style ATT&CK tags (in Sigma these are `tags: attack.tXXXX`, from my recall rather than the Wazuh docs), the rule's technique tags can be read directly for alert→technique mapping. Verify this against the 5.0 rule schema.

**NER**
- NER is mainly useful if the thesis also ingests unstructured sources such as Suricata signature text or CTI reports. For Wazuh JSON it adds little and introduces errors.

### Gaps
- I found no peer-reviewed paper evaluating NER (CyNER/SecureBERT) on Wazuh or SIEM alert text specifically.
- I found no published Wazuh-rule→ATT&CK completion dataset.
- RAM's precision and recall numbers were not extracted, since only the abstract was read.

## Q3. Papers (2019–2026) on alert correlation and triage with knowledge, provenance or attack graphs: how they find attack paths and affected assets

### Takeaway
There are three families:
- **Provenance-graph systems** (HOLMES 2019, NoDoze 2019, RapSheet 2020) correlate alerts through causal system-event graphs and TTP ordering.
- **Attack-graph-based triage** (Sadlek et al. 2025, MulVAL plus ATT&CK rules) matches alert sequences to a precomputed attack graph and scores severity by kill-chain progress and asset criticality. This is the closest analogue to this thesis.
- **Alert-graph grouping and contextualisation** (Eckhoff et al. 2025 on AIT-ADS) links alerts into graphs and matches them to past incidents with graph neural matching.

I found no single paper that combines Wazuh alerts, ATT&CK, CVE/CWE/CAPEC and an asset KG for attack paths. That combination is the gap the thesis can fill.

### Cited Findings
**Sadlek, Yamin, Čeleda, Katt, "Severity-Based Triage of Cybersecurity Incidents Using Kill Chain Attack Graphs", JISA 2025**
- Three steps:
  1. Build a kill-chain attack graph from host and network data, using MulVAL with generation rules based on ATT&CK techniques.
  2. Form sequences of detected alerts and match them to the attack graph.
  3. Assign severity from the most advanced kill-chain phase reached and the criticality of affected assets.
- Results: AUC 0.95 for classifying sequences by match score, and a threshold that catches 80% of malicious sequences with few benign misclassified.
- Source: [MUNI publication page](https://ics.muni.cz/en/research/publications/2468764), doi 10.1016/j.jisa.2024.103956

**HOLMES (Milajerdi et al., IEEE S&P 2019)**
- Correlates suspicious information flows in a provenance graph and maps low-level events to ATT&CK/APT-kill-chain TTPs.
- Builds a high-level scenario graph that summarises attacker actions in real time.
- Evaluated on nine real-world APT scenarios, with high precision and a low false-alarm rate.
- Source: [arXiv 1810.01594](https://arxiv.org/pdf/1810.01594)

**NoDoze (Hassan et al., NDSS 2019)**
- Builds a causal dependency graph for each alert.
- Scores each event by how rare it was historically in the enterprise, then propagates the scores through the graph (network diffusion) to rank alerts.
- Result: 86% fewer false alarms on 364 alerts, with true-alert graphs about two orders of magnitude smaller.
- Source: [NDSS](https://dev.ndss-symposium.org/ndss-paper/nodoze-combatting-threat-alert-fatigue-with-automated-provenance-triage)

**RapSheet, "Tactical Provenance Analysis for EDR Systems" (Hassan, Bates, Marino, IEEE S&P 2020)**
- Builds Tactical Provenance Graphs whose nodes are EDR alerts (TTP-tagged) and whose edges are causal dependencies.
- Scores threat severity from the temporal order of alerts, consistent with kill-chain progression.
- Evaluated with Symantec EDR in an enterprise, where malicious TPGs ranked above false alarms.
- Sources: [paper PDF](https://www.cs.virginia.edu/~hur7wv/papers/hassan-oakland20.pdf), [UIUC page](https://sts.cs.illinois.edu/papers/paper/TacticalProvenanceAn20200518.html)

**Eckhoff et al., "A Graph-Based Approach to Alert Contextualisation in SOCs" (arXiv 2509.12923, 2025)**
- Groups alerts into graphs: alerts are nodes, and edges join related alerts within time windows.
- Uses Graph Matching Networks to correlate incoming alert groups with historical incidents.
- Per a search snippet, it uses AIT-ADS (about 2.66M alerts, mostly false positives labelled "-", heavily imbalanced).
- Source: [arXiv 2509.12923](https://arxiv.org/abs/2509.12923)

**Risk-based alerting on AIT-ADS**
- Treats AIT-ADS Wazuh and AIT-ADS Suricata as separate datasets, because host-based and network-based alerts need different parameters.
- Source: [arXiv 2609.02465](https://arxiv.org/pdf/2609.02465)

**Noel et al. (2015, IEEE HST) / CyGraph**
- TVA/Cauldron derives attack graphs from vulnerability scans and firewall rules.
- CyGraph stores the network topology, firewall policies, vulnerabilities and intrusion alerts as a property graph in Neo4j, and analyses it with Cypher queries.
- The flexible schema is described as "much more flexible" than relational storage for this domain.
- Sources: [Noel 2015 HST PDF](https://csis.gmu.edu/noel/pubs/2015_IEEE_HST.pdf), [Neo4j MITRE case study](https://neo4j.com/blog/graphs-in-government-mitre)

**Threat KG across ATT&CK, CAPEC, CWE, CVE and CPE (Sands, 2024)**
- About 66k entities, including 31,187 CVEs.
- Link prediction improves Hits@10 by 6.5%.
- It is a CTI-KG foundation, not a triage method.
- Source: [Sands doi 10.1051/sands/2024019](https://sands.edpsciences.org/10.1051/sands/2024019)

### Inferences
**How these systems find attack paths**
- Provenance systems: backward and forward causal traversal from an alert node.
- Attack-graph systems: precompute reachable privilege states (MulVAL Datalog), then embed alerts as observed steps on graph paths.
- Alert-graph systems: temporal and entity co-occurrence edges.

**How they find affected assets**
- Hosts and processes on the causal or attack-graph path from the alerted node.
- Severity is weighted by asset criticality (Sadlek) or by rarity (NoDoze).

**Fit for this thesis**
- The closest blueprint is Sadlek et al. Replace the MulVAL attack graph with Cypher traversal over the linked CTI + asset KG:
  - Alerts become Technique matches.
  - Kill-chain progress comes from `Technique-[:IMPLEMENTS]->Tactic` ordering across alerts on the same host or entity.
  - Affected assets are hosts reachable from the alerted host that hold CVEs exploitable by techniques in the observed or likely next tactic.
- Group-[:USES_TECHNIQUE] gives a HOLMES/RapSheet-style "which APT matches the observed TTP set" ranking.
- The thesis does not need OS-level provenance (no Sysmon-graph construction), which keeps it implementable with Wazuh plus Neo4j.

### Gaps
- Not read in full: Sadlek et al.'s matching algorithm and asset-criticality scheme, and Eckhoff et al.'s exact alert-linking features.
- I did not find a 2022–2026 peer-reviewed paper that explicitly links Wazuh alerts into a CVE/CWE/CAPEC/ATT&CK KG with assets. This absence comes from my searches, not a systematic review.

## Q4. Attack-path computation in Neo4j: MulVAL, CyGraph, BloodHound-style queries, Cypher shortest paths, APOC and GDS, plus example Cypher

### Takeaway
Use native Cypher for path discovery:
- `SHORTEST k`, `ALL SHORTEST` or legacy `shortestPath`, with bounded variable-length patterns.
- APOC `apoc.path.subgraphNodes` / `expandConfig` with label and relationship filters for blast-radius (reachable-asset) sets.
- GDS (PageRank, personalised PageRank seeded on alerted nodes, betweenness) for ranking affected assets.

MulVAL is a separate Datalog attack-graph generator whose output could be imported. BloodHound is the canonical example of "shortest path from compromised node to crown jewel" in Neo4j.

### Cited Findings
**Cypher shortest-path syntax (Neo4j 5 / 2025.x)**
- `MATCH p = SHORTEST k (a)-[:R]-+(b)` returns the k shortest by hop count. `k` may be a parameter from 2025.06.
- `ALL SHORTEST` returns every path tied for shortest. `ANY` / `ANY SHORTEST` equals `SHORTEST 1`. `SHORTEST k GROUPS` returns all paths at each of the k shortest lengths.
- `SHORTEST` "functionally replaces and extends" `shortestPath()` / `allShortestPaths()`. The legacy functions still work but are not GQL-conformant.
- Source: [Neo4j Cypher manual: shortest paths](https://neo4j.com/docs/cypher-manual/current/patterns/shortest-paths/)

**Performance caveats (same page)**
- `shortestPath` falls back to exhaustive search when a predicate must inspect the whole path. This can be very slow when no path exists, and `dbms.cypher.forbid_exhaustive_shortestpath` disables the fallback.
- Indexing or constraining the lookup properties helps the planner use the fast per-pair `ShortestPath` operator.
- Source: [Neo4j shortest paths](https://neo4j.com/docs/cypher-manual/current/patterns/shortest-paths/)

**APOC path expansion**
- Signature: `apoc.path.subgraphNodes(startNode|list, config)`.
- `relationshipFilter`, e.g. `"CONNECTS_TO>|RUNS<"`: `>` outgoing, `<` incoming, comma for sequences.
- `labelFilter` operators:
  - `+` allow
  - `-` deny
  - `/` terminate at the node
  - `>` end node, keep expanding
- Precedence is fixed: deny, then terminate, then end node, then allow.
- Other options: `minLevel`, `maxLevel`, `bfs` (default true), `limit`, `endNodes`, `terminatorNodes`, `allowlistNodes`, `denylistNodes`.
- Source: [APOC docs: subgraphNodes](https://neo4j.com/docs/apoc/current/overview/apoc.path/apoc.path.subgraphNodes/)

**GDS**
- Betweenness:
  - `gds.betweenness.stream/write(graph, {samplingSize, samplingSeed})`.
  - Projection: `gds.graph.project(name, source, target, {relationshipProperties})`, with `undirectedRelationshipTypes:['*']` for an undirected graph, which costs about twice as much to compute.
  - Source: [GDS betweenness](https://neo4j.com/docs/graph-data-science/current/algorithms/betweenness-centrality/)
- PageRank:
  - `gds.pageRank.stream(graph, {dampingFactor:0.85, maxIterations, relationshipWeightProperty, sourceNodes})`.
  - `sourceNodes` turns it into Personalized PageRank and accepts `[[node, bias], …]` pairs.
  - Source: [GDS PageRank](https://neo4j.com/docs/graph-data-science/current/algorithms/page-rank/)

**BloodHound**
- Neo4j-backed. Edges always point in the direction of compromise or privilege gain.
- The canonical query is `shortestPath` from users (or `{owned:true}` nodes) to `Group {name:'DOMAIN ADMINS@…'}` with an unbounded `[*1..]`. Analysts mark compromised nodes with `SET n.owned=true`.
- Sources: [SpecterOps: Intro to Cypher](https://specterops.io/blog/2017/09/18/bloodhound-intro-to-cypher/), [BloodHound CE docs: Cypher search](https://bloodhound.specterops.io/analyze-data/explore/cypher-search), [Compass Security blog](https://blog.compass-security.com/2019/12/finding-active-directory-attack-paths-using-bloodhound/)

**MulVAL**
- An open-source Datalog-based generator of logical attack graphs, with fact nodes, derivation (rule) nodes and privilege nodes.
- A survey catalogues its extensions and their attack-scenario coverage.
- Source: [MulVAL extensions survey, arXiv 2208.05750](https://arxiv.org/pdf/2208.05750)

**CyGraph / Noel**
- The attack graph is computed outside Neo4j (TVA/Cauldron), then stored and queried in Neo4j with Cypher, together with topology and alerts.
- Source: [Noel 2015](https://csis.gmu.edu/noel/pubs/2015_IEEE_HST.pdf)

### Inferences
These Cypher patterns are my own, written against the project schema. Asset-side labels and relationships (`Host`, `Software`, `Alert`, `HAS_VULNERABILITY`, `RUNS`, `HAS_CPE`, `CONNECTS_TO`, `asset_value`) are placeholders until the asset KG is built. Where a hop bound is needed, the patterns use variable-length syntax (`*1..5`) or the `+` quantifier. The page I fetched showed only `+` and `{2,}`, not a bounded `{1,5}` quantified path pattern.

All Cypher below is unexecuted. It was written against the schema, and the asset labels are placeholders. Known traps:
- **Query 5:** `gds.graph.project('net', …)` errors on a rerun unless `CALL gds.graph.drop('net', false)` runs first. Alerted hosts with no `CONNECTS_TO` edge are not in the projection, so passing them as `sourceNodes` may fail. Filter the seeds to projected nodes first.
- **Query 3:** a whole-path `WHERE` over `nodes(p)` combined with a `SHORTEST` selector may be applied after path selection, which would return fewer than 3 paths or none. Prefer an inline predicate on each hop, or run `EXPLAIN` to check.

**Design points**
- The Technique→CAPEC→CWE→CVE expansion fans out to thousands of CVEs.
- Always intersect it with the alerted host's own CVEs from the states index. Do not enumerate the CTI side unbounded.
- Filter on `Technique.x_mitre_platforms` against the host OS.
- Normalise sub-techniques: match `t.id = x OR t.id = split(x,'.')[0]`.

```cypher
// 0. Ingest one alert (from Python, params from the Wazuh JSON)
MERGE (h:Host {agent_id:$agent_id}) ON CREATE SET h.name=$agent_name, h.ip=$agent_ip
CREATE (a:Alert {id:$alert_id, rule_id:$rule_id, level:$level, ts:datetime($ts), desc:$desc})
MERGE (a)-[:ON_HOST]->(h)
WITH a
UNWIND $mitre_ids AS tid
MATCH (t:Technique) WHERE t.id = tid OR t.id = split(tid,'.')[0]
MERGE (a)-[:INDICATES]->(t);

// 1. Alert -> Technique -> CAPEC -> CWE -> CVE, restricted to CVEs actually present on the alerted host
MATCH (a:Alert {id:$alert_id})-[:ON_HOST]->(h:Host),
      (a)-[:INDICATES]->(t:Technique)
WHERE any(p IN t.x_mitre_platforms WHERE toLower(p) = toLower(h.os_platform))
MATCH (t)<-[:USES_TECHNIQUE]-(ap:AttackPattern)<-[:CAUSES_WEAKNESS]-(w:Weakness)
      -[:EXPLOITED_BY]->(v:Vulnerability)<-[:HAS_VULNERABILITY]-(h)
RETURN t.id, ap.id, w.id, v.id, v.cvss ORDER BY v.cvss DESC;

// 1b. Same, joining through CPE when the host→CVE edge is not materialised
MATCH (a:Alert {id:$alert_id})-[:ON_HOST]->(h:Host)-[:RUNS]->(:Software)-[:HAS_CPE]->(c:CPE)
      -[:VULNERABLE_TO]->(v:Vulnerability)<-[:EXPLOITED_BY]-(w:Weakness)
      -[:CAUSES_WEAKNESS]->(:AttackPattern)-[:USES_TECHNIQUE]->(t:Technique)<-[:INDICATES]-(a)
RETURN DISTINCT v.id, w.id, t.id;

// 2. Blast radius: assets reachable from the alerted host over network edges (APOC)
MATCH (a:Alert {id:$alert_id})-[:ON_HOST]->(h:Host)
CALL apoc.path.subgraphNodes(h, {relationshipFilter:'CONNECTS_TO>', labelFilter:'+Host', maxLevel:4})
YIELD node AS reach
OPTIONAL MATCH (reach)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN reach.name, reach.asset_value, count(v) AS vulns ORDER BY reach.asset_value DESC;

// 3. Attack path from alerted host to a crown-jewel asset (BloodHound-style), every hop on a vulnerable host
MATCH (a:Alert {id:$alert_id})-[:ON_HOST]->(src:Host), (dst:Host {crown_jewel:true})
MATCH p = SHORTEST 3 (src)-[:CONNECTS_TO]->+(dst)
WHERE all(n IN nodes(p)[1..] WHERE EXISTS { (n)-[:HAS_VULNERABILITY]->(:Vulnerability) })
RETURN [n IN nodes(p) | n.name] AS path, length(p) AS hops;

// 4. Likely next techniques: same Groups using the observed technique set (HOLMES/RapSheet flavour)
MATCH (h:Host {agent_id:$agent_id})<-[:ON_HOST]-(a:Alert)-[:INDICATES]->(t:Technique)
WITH collect(DISTINCT t) AS seen
MATCH (g:Group)-[:USES_TECHNIQUE]->(t) WHERE t IN seen
WITH g, count(t) AS overlap, seen ORDER BY overlap DESC LIMIT 5
MATCH (g)-[:USES_TECHNIQUE]->(nxt:Technique)-[:IMPLEMENTS]->(ta:Tactic) WHERE NOT nxt IN seen
RETURN g.name, overlap, ta.name, collect(DISTINCT nxt.id)[..10];

// 5. Rank affected assets with Personalized PageRank seeded on alerted hosts (GDS)
MATCH (s:Host)-[r:CONNECTS_TO]->(t:Host)
WITH gds.graph.project('net', s, t) AS g
MATCH (h:Host)<-[:ON_HOST]-(:Alert) WITH collect(DISTINCT h) AS seeds
CALL gds.pageRank.stream('net', {sourceNodes: seeds, dampingFactor:0.85})
YIELD nodeId, score
RETURN gds.util.asNode(nodeId).name AS host, score ORDER BY score DESC LIMIT 20;
```

- Betweenness on the same `net` projection identifies choke-point hosts, useful for mitigation prioritisation. Personalized PageRank captures closeness to the current alerts.
- Kill-chain progression per host: order the alerts by `ts` and map each to `Tactic` via `IMPLEMENTS`, then take the maximum tactic order reached (as in Sadlek et al. and RapSheet).
  - Do not order tactics by their TA IDs. They are not in kill-chain order: Reconnaissance is TA0043 and Resource Development is TA0042, yet both come first, and Exfiltration TA0010 comes after Command and Control TA0011.
  - Instead, store `Tactic.order` at ingest from the enterprise `x-mitre-matrix` object's `tactic_refs` array. This array is in matrix order, per my unverified recall.
- MulVAL is optional. Its value is a formal privilege-escalation semantics. For a thesis built on Neo4j, plain Cypher reachability over `CONNECTS_TO`, `HAS_VULNERABILITY` and technique preconditions is simpler and good enough. If MulVAL is used, my unverified recall is that it emits its graph as CSV files (VERTICES/ARCS), which could be loaded with `LOAD CSV`. Check this against the MulVAL output before relying on it.

### Gaps
- I found no documented MulVAL→Neo4j import tool. The CSV approach above is my suggestion.
- I did not verify GDS memory or runtime figures at the expected KG size (use the CTI-side node count from your own KG). Project only the asset/network subgraph for GDS.
- CyGraph's exact schema and queries are not public in detail.

## Q5. Ground truth: labelled Wazuh alerts from Atomic Red Team and Kali in the lab, and public datasets for evaluation

### Takeaway
Run Atomic Red Team via Invoke-AtomicTest with execution logging on. Each execution record gives technique ID, test GUID, hostname, IP, user and UTC time. Join it to `wazuh-alerts-*` on `agent.name`/`agent.ip` plus a time window. This labels every alert with the true technique (or as benign) and lets you score both Wazuh's `rule.mitre.id` and the KG's path and affected-asset outputs. Kali multi-step attacks (scan → exploit → priv-esc → lateral movement) give path-level ground truth. For external evaluation:
- AIT-ADS (Wazuh + Suricata + AMiner alerts, 8 multi-step scenarios, CC BY 4.0) is the best fit.
- ATLAS/ATLASv2 and DARPA OpTC are provenance-level datasets with weaker or reconstructed labels.

### Cited Findings
**Invoke-AtomicTest execution logging**
- The default CSV log is written to `$env:TEMP` or `/tmp`, at `Invoke-AtomicTest-ExecutionLog.csv`, or at `-ExecutionLogPath`. It records execution time, technique, test number and name, user, hostname, IP, GUID, ProcessId and ExitCode.
- Only actual executions are logged (not `-ShowDetails`, `-CheckPrereqs`, `-GetPrereqs` or `-Cleanup`).
- Other loggers:
  - `Attire-ExecutionLogger`: JSON that includes full command input and output, importable into VECTR.
  - `Syslog-ExecutionLogger`: JSON to a syslog server, with time (UTC and local), technique, test number and name, hostname, IP, username, GUID and tags.
  - `WinEvent-ExecutionLogger`: writes to an "Atomic Red Team" Windows event log.
- Source: [invoke-atomicredteam wiki: Execution Logging](https://github.com/redcanaryco/invoke-atomicredteam/wiki/Execution-Logging)

**Wazuh's own guide**
- Runs Atomic Red Team on Windows (e.g. T1053.005 Scheduled Task, T1218.010 Regsvr32), configures Wazuh to collect the events (Sysmon), writes rules and checks the alerts.
- Source: [Wazuh blog: Emulation of ATT&CK techniques and detection with Wazuh](https://wazuh.com/blog/emulation-of-attck-techniques-and-detection-with-wazuh/)

**Practitioner reports**
- Atomic tests for T1053.005 and T1105 executed successfully, but only some produced Wazuh alerts with default rules. Windows Defender Operational log collection was added to help.
- Use a disposable Windows VM with Sysmon and the Wazuh agent.
- Sources: [DEV: Deploying and validating a Wazuh SIEM with Atomic Red Team](https://dev.to/jfash007/deploying-and-validating-a-wazuh-siem-with-atomic-red-team-26i4), [SOCFortress](https://socfortress.medium.com/validate-your-security-detection-rules-23e90a256ae8)

**AIT-ADS (Landauer, Skopik, Wurzenberger; CSET 2024)**
- Eight scenarios: fox, harrison, russellmitchell, santos, shaw, wardbeck, wheeler, wilson.
- 2,655,821 alerts: Wazuh 2,293,628, Suricata 306,635, AMiner 55,558.
- Attack steps: nmap, WPScan and dirb scans; webshell upload via CVE-2020-24186; John the Ripper cracking; privilege escalation; remote command execution; DNSteal exfiltration; service stop.
- Includes false positives from normal user activity (logins, updates).
- `labels.csv` holds the start and end times of each scenario's attack phases.
- Size 96.2 MB zip, CC BY 4.0.
- Derived from AIT-LDSv2 (Landauer et al., IEEE TDSC 2023).
- Sources: [Zenodo 8263181](https://zenodo.org/records/8263181), [AIT publication page](https://publications.ait.ac.at/en/publications/introducing-a-new-alert-data-set-for-multi-step-attack-analysis/)
- AIT-ADS has a real CVE (CVE-2020-24186, wpDiscuz webshell) in its chain, which allows a CVE→CWE→CAPEC→ATT&CK path test on public data. — [Zenodo 8263181](https://zenodo.org/records/8263181)

**ATLAS / ATLASv2**
- Original ATLAS labels only 2–3 malicious entities per attack chain.
- ATLASv2 replicates the 10 ATLAS scenarios with Sysmon and Carbon Black telemetry. Per-attack labels are lists of malicious Windows Security `EventRecordID`s, and process labels come via the REAPr ground-truth set.
- Source: [ATLASv2, arXiv 2401.01341](https://ar5iv.labs.arxiv.org/html/2401.01341)

**DARPA OpTC**
- Released as-is, "practically guaranteed to be imperfect". A partially corrected version fixes identifier and property errors.
- Labels must be rebuilt from Red Team descriptions, agent PIDs and C2 infrastructure (per a 2026 benchmark paper).
- Sources: [corrected OpTC (b2find)](https://b2find.eudat.eu/dataset/91c22ce3-fb2c-5e30-8b66-f990dda960b2), [IEEE DataPort OpTC](https://ieee-dataport.org/node/3910), [arXiv 2608.01454](https://arxiv.org/pdf/2608.01454)

### Inferences
**Lab labelling protocol (Python)**
1. Sync NTP on all VMs.
2. Run `Invoke-AtomicTest Txxxx -TestNumbers n -LoggingModule Syslog-ExecutionLogger`, or the CSV logger, on the Windows and Linux agents. Run Kali steps from a script that logs `(utc_start, utc_end, step, technique_id, src_ip, dst_host, cve_if_any)`.
3. Pull `wazuh-alerts-*` for the window.
4. Label each alert. It is positive for technique T if `agent.name` (or `data.srcip`/`agent.ip`) matches the execution host or attacker IP and the alert's `timestamp` falls in [start − δ, end + Δ]. Otherwise it is benign background.
5. Run Atomic cleanup between tests to avoid label bleed. Leave a quiet gap between tests and generate benign background activity.

**Metrics from these labels**
- Technique-mapping accuracy: `rule.mitre.id` or the fallback mapping versus the executed technique.
- Tactic and kill-chain progression accuracy.
- Attack-path correctness: does the KG path contain the actual Kali pivot hosts and CVE?
- Affected-asset precision@k and recall against hosts actually touched.
- Alert-rescoring ranking metrics (AUC, as in Sadlek et al.).

**Further notes**
- Do not rely on Wazuh's default rules to fire for every Atomic test. Record "executed but no alert" as a coverage gap, and add Sysmon config (e.g. SwiftOnSecurity/Olaf) plus custom rules with `<mitre>` tags.
- For AIT-ADS, per-alert labels must likewise be derived by joining `labels.csv` phase windows with alert host and IP. The phase names map naturally to ATT&CK, though that mapping has to be done manually: scans→T1595/T1046, webshell→T1505.003 + T1190, cracking→T1110.002, exfil→T1048.

### Gaps
- I did not confirm the official AIT-ADS per-alert label schema. The Zenodo page mentions only phase time ranges in `labels.csv`, so check the AIT GitHub repository.
- I found no official OpTC ground-truth document; the label details come from secondary papers.
- I did not verify that the STIX `x-mitre-matrix.tactic_refs` array gives kill-chain order. Check it in the STIX bundle already loaded.
- I did not find a public dataset of Atomic Red Team runs with matching Wazuh alerts. The lab will have to generate its own.
