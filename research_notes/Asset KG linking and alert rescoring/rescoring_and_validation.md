# Context-aware Re-scoring of Vulnerabilities/Alerts and How to Validate It

Scope: scoring frameworks and ML/KG methods that adjust CVSS-style priority with threat and asset context, plus evaluation methodology for comparing a new score with the original CVSS score. Grounded in the thesis "Context-aware Vulnerability Classification using Knowledge Graph and Threat Intelligence" (outline: `/home/panodmanodee/projects/cyber_crime_projects/outline_n_ideas.md`. Note: the file is at the project root, not in `ref_papers/`). The Neo4j KG already stores CVSS v2/v3/v4 base score, vector and severity, plus vulnrichment SSVC fields (`ssvc_exploitation`, `ssvc_automatable`, `ssvc_technical_impact`) and the KEV date on Vulnerability nodes.

Research date: 2026-10-17. Primary sources were fetched where possible: the CISA SSVC guide PDF, the EPSS v3 paper PDF, the CVSS-BERT PDF, the FIRST CVSS specs, the live EPSS API, the EPSS bulk CSV header and the live KEV feed. Items marked "(abstract/snippet only)" were not verified against full text.

---

## 1. Standard context frameworks: CVSS v3.1 environmental, CVSS v4.0 threat/environmental, EPSS, SSVC, KEV (formulas, decision tables, data access)

### Takeaway
All four standard frameworks can be computed from data the project already holds or can fetch for free.
- **CVSS v3.1 Environmental:** a closed-form formula with CR/IR/AR weights.
- **CVSS v4.0:** a lookup/interpolation over MacroVectors (use a library such as the FIRST reference calculator port, not a hand formula).
- **EPSS:** a free daily API and CSV. The current model as of Oct 2026 is the 2026-06-15 model ("EPSS v5"), so v4 is already superseded.
- **SSVC trees:** both the CISA tree and the CERT/CC deployer tree can be computed from the stored `ssvc_*` fields plus asset-KG attributes. Standard CVSS threat metrics can only *lower* a score (E=X is treated as the worst case), so an increase in priority has to come from the environmental metrics or from outside CVSS.

### Cited Findings

**CVSS v3.1 Environmental and Temporal (exact equations)** — [FIRST CVSS v3.1 spec](https://www.first.org/cvss/v3.1/specification-document)
- `MISS = min(1 − (1 − CR×MC)(1 − IR×MI)(1 − AR×MA), 0.915)`.
- ModifiedImpact:
  - Scope Unchanged: `6.42 × MISS`.
  - Scope Changed: `7.52 × (MISS − 0.029) − 3.25 × (MISS × 0.9731 − 0.02)^13`.
- `ModifiedExploitability = 8.22 × MAV × MAC × MPR × MUI`.
- EnvironmentalScore:
  - If ModifiedImpact ≤ 0, the score is 0.
  - Scope Unchanged: `Roundup(Roundup(min(MI + ME, 10)) × E × RL × RC)`.
  - Scope Changed: `Roundup(Roundup(min(1.08 × (MI + ME), 10)) × E × RL × RC)`.
- `TemporalScore = Roundup(BaseScore × E × RL × RC)`.
- Weights:
  - CR/IR/AR: H = 1.5, M = 1.0, L = 0.5, X = 1.0.
  - E: X/H = 1.0, F = 0.97, P = 0.94, U = 0.91.
  - RL: X/U = 1.0, W = 0.97, T = 0.96, O = 0.95.
  - RC: X/C = 1.0, R = 0.96, U = 0.92.
  - MAV: N = 0.85, A = 0.62, L = 0.55, P = 0.2.
  - MAC: L = 0.77, H = 0.44.
  - MPR: N = 0.85; L = 0.62 (0.68 if Scope Changed); H = 0.27 (0.5 if Scope Changed).
  - MUI: N = 0.85, R = 0.62.
  - MC/MI/MA: H = 0.56, L = 0.22, N = 0.
- Roundup is the smallest one-decimal value ≥ the input. The spec's Appendix A gives an integer-based implementation (`int_input = round(input × 100000)`; if `int_input % 10000 == 0`, return `int_input / 100000`; otherwise return `(floor(int_input / 10000) + 1) / 10`) to avoid floating-point errors. — [FIRST CVSS v3.1 spec](https://www.first.org/cvss/v3.1/specification-document)

**CVSS v4.0** — [FIRST CVSS v4.0 spec](https://www.first.org/cvss/v4.0/specification-document)
- Nomenclature:
  - CVSS-B: Base only.
  - CVSS-BT: Base + Threat.
  - CVSS-BE: Base + Environmental.
  - CVSS-BTE: Base + Threat + Environmental.
  - NVD and other providers typically publish only CVSS-B.
- Threat metric Exploit Maturity (E) values:
  - A (Attacked): attacks reported, or exploit toolkits available.
  - P (POC): public PoC, no known attempts.
  - U (Unreported).
  - X (Not Defined): scored as A, the worst case.
- Environmental metrics:
  - Security Requirements CR/IR/AR take H/M/L. X defaults to High (worst case), so lower values lower the score.
  - The Modified Base metrics replace the Base values when defined and can raise or lower the score.
  - A Safety (S) value is available for MSI/MSA (subsequent-system integrity and availability).
- Computation is **not closed-form**:
  - Vectors map to MacroVectors via six equivalence sets, EQ1–EQ6, with EQ3 and EQ6 evaluated jointly.
  - The highest-severity vector in each MacroVector takes its score from a lookup table (`cvss_lookup.js` in the reference calculator).
  - Other vectors are interpolated by the mean proportional distance to lower MacroVectors.
- Qualitative bands: None 0.0, Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0.
- The spec recommends threat intelligence that covers all vulnerabilities, drawn from multiple sources and updated frequently and automatically. It does **not** prescribe an EPSS→E mapping.

**EPSS**
- EPSS v3 (Jacobs et al., WEIS 2023) — [arXiv 2302.14172](https://arxiv.org/abs/2302.14172):
  - Model and features: XGBoost classifier on 1,477 features.
  - Exploitation ground truth comes from Fortinet/Fortiguard, AlienVault OTX, Shadowserver and GreyNoise.
  - Target: exploitation activity in the next 30 days, chosen "to align with most enterprise patch cycles".
  - Evaluation uses precision-recall AUC, because exploited CVEs are severely imbalanced and ROC/accuracy "may be misleading".
- EPSS v3 results on the 1–30 Dec 2022 test window — [arXiv 2302.14172](https://arxiv.org/abs/2302.14172):

  | Model | PR-AUC | F1 | Threshold at F1 | Efficiency | Coverage | Effort (% of CVEs) |
  |---|---|---|---|---|---|---|
  | EPSS v3 | 0.7795 | 0.728 | ≥ 0.36 | 78.5% | 67.8% | 3.5% |
  | EPSS v2 | 0.4288 | 0.451 | ≥ 0.16 | 45.5% | 44.8% | 4% |
  | EPSS v1 | 0.2998 | 0.361 | ≥ 0.2 | 43% | 31.1% | 2.9% |
  | CVSS v3.x base | 0.051 | 0.108 | ≥ 9.7 | 6.5% | 32.3% | 13.7% |

  - Other simple strategies in the paper's figure:
    - "CVSS PR:N": 70.4% effort, 88.1% coverage, 5.1% efficiency.
    - "Exploit in ExploitDB": 10.9% effort, 34.7% coverage, 13.0% efficiency.
- Definitions (useful vocabulary for the thesis) — [arXiv 2302.14172](https://arxiv.org/abs/2302.14172):
  - **Efficiency = precision**: "out of all the vulnerabilities remediated, how many were actually exploited?"
  - **Coverage = recall**: "out of all the vulnerabilities that are being exploited, how many were actually remediated?"
  - **Effort** = the share of CVEs flagged.
- EPSS v4 — [Empirical Security, "Introducing EPSS v4"](https://research.empiricalsecurity.com/research/introducing-epss-version-4):
  - Release date: the post gives "March 16" with no year. Secondary sources say 17 Mar 2025 ([Xygeni](https://xygeni.io/?p=46755)). The one-day conflict is unresolved.
  - New exploitation evidence: malware/endpoint detections, web/RSS mentions, Shodan, HackerOne Hacktivity. Exploitation activity covers about 12K vulnerabilities per month.
  - New features and handling:
    - CWEs grouped into the top 22 categories plus category 1400.
    - CNA/ADP data from cve.org used when NVD lacks CVSS/CPE.
    - REJECTED CVEs are no longer scored.
  - The post gives no numeric v4-vs-v3 metric.
  - Comparison against CVSS ≥ 7 on about 239K CVEs:
    - CVSS 7+ needs about 50.7% effort for 74.6% coverage at about 6% efficiency.
    - At the same coverage, EPSS needs about 6% effort at about 47% efficiency, i.e. "more than 8×" less effort.
- **EPSS v5 is current (Oct 2026):**
  - The bulk CSV downloaded on 2026-10-17 has the header `#model_version:v2026.06.15,score_date:2026-10-17T12:00:28Z` with columns `cve,epss,percentile`. — [EPSS bulk CSV](https://epss.empiricalsecurity.com/epss_scores-current.csv.gz)
  - The "EPSS V5 Is Here" post is dated "Jun 15" — [Empirical Security](https://research.empiricalsecurity.com/research/epss-v5-is-here). It reports:
    - v5 scores all 318K+ CVEs.
    - Calibration is refined so scores match observed exploitation rates.
    - On an *unnamed* ranking metric (random ≈ 0.025, perfect = 1.0), v4 scored 0.514 and v5 scored 0.633, about +23% (vendor-reported, 4 May 2026 data). Do not call this PR-AUC; the post does not name the metric.
  - The post does not state whether FIRST formally designates v5 as the official model.
- **EPSS API (verified live):**
  - `GET https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2014-0160` returns `{cve, epss, percentile, date}` per CVE.
  - `&scope=time-series` adds a daily history array (about 30 days).
  - A `date=` parameter retrieves historical scores. This was verified live: `?cve=CVE-2021-44228&date=2023-01-01` returned epss 0.97095, percentile 0.99998. It is key for temporal validation. Historical scores come from whichever model was in production on that date, which is the correct behaviour for a forward test.
  - Bulk daily CSVs are now hosted at `epss.empiricalsecurity.com`.
  - The `api.first.org/data/v1/epss` call was verified on 2026-10-17. The FIRST API docs pages `first.org/epss/api(.html)` returned 404 at fetch time.

**SSVC — CISA tree (exact; from the CISA SSVC Guide PDF)** — [CISA SSVC Guide](https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf); [CISA SSVC page](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc)
- Decision points:
  - Exploitation: none / poc / active.
  - Automatable: no / yes.
  - Technical Impact: partial / total.
  - Mission Prevalence: Minimal / Support / Essential. "Support" means the component only supports MEFs; "Essential" means it directly provides MEFs.
  - Public Well-Being Impact: Minimal / Material / Irreversible.
- Outcomes:
  - Track: remediate within standard timelines.
  - Track*: monitor closely; standard timelines.
  - Attend: supervisory attention; remediate sooner than standard timelines.
  - Act: leadership action; remediate "as soon as possible".
- Table 8, Mission & Well-Being (rows = Mission Prevalence, columns = Well-Being Minimal / Material / Irreversible):
  - Minimal → Low / Medium / High.
  - Support → Medium / Medium / High.
  - Essential → High / High / High.
- Table 9 (36 rows). Format: Exploitation, Automatable, Technical Impact → outcomes for M&WB = low / medium / high.
  - none, no, partial → Track / Track / Track
  - none, no, total → Track / Track / Track*
  - none, yes, partial → Track / Track / Attend
  - none, yes, total → Track / Track / Attend
  - poc, no, partial → Track / Track / Track*
  - poc, no, total → Track / Track* / Attend
  - poc, yes, partial → Track / Track / Attend
  - poc, yes, total → Track / Track* / Attend
  - active, no, partial → Track / Track / Attend
  - active, no, total → Track / Attend / Act
  - active, yes, partial → Attend / Attend / Act
  - active, yes, total → Attend / Act / Act

**SSVC — CERT/CC Deployer tree (condensed by a summarizer; verify against the CERT/CC SSVC repo before quoting as exact)** — [CERT/CC SSVC deployer tree](https://certcc.github.io/SSVC/howto/deployer_tree/)
- Decision points:
  - Exploitation: None / Public PoC / Active.
  - System Exposure: Small / Controlled / Open.
  - Automatable: No / Yes.
  - Human Impact: Low / Medium / High / Very High. It combines Safety Impact (Negligible / Marginal / Critical / Catastrophic) and Mission Impact (Degraded / Crippled / MEF Failure / Mission Failure).
- Outcomes: Defer / Scheduled / Out-of-Cycle / Immediate.
- Human Impact rules:
  - L = Negligible safety AND (Degraded or Crippled) mission.
  - M = (Negligible AND MEF Failure) OR (Marginal AND Degraded/Crippled).
  - H = (Critical AND Degraded/Crippled) OR (Marginal AND MEF Failure).
  - VH = Catastrophic safety OR Mission Failure.
- Condensed outcome table (columns HI = L / M / H / VH):
  - None:
    - Small: No → D D S S; Yes → D S S S.
    - Controlled: No → D S S S; Yes → S S S S.
    - Open: No → D S S S; Yes → S S S O.
  - PoC:
    - Small: No → D S S S; Yes → S S S S.
    - Controlled: No → D S S S; Yes → S S S O.
    - Open: No → S S S O; Yes → S S O O.
  - Active:
    - Small: No → S S O O; Yes → S O O O.
    - Controlled: No → S S O O; Yes → O O O O.
    - Open: No → S O O I; Yes → O O I I.
- The CERT/CC site also hosts the coordinator triage tree (Decline / Track / Coordinate) and a "CISA BOD 26-04 Response Model" page, not examined here. — [CERT/CC coordinator triage](https://certcc.github.io/SSVC/howto/coordination_triage_decision/)

**CISA KEV (verified live feed)**
- Feed: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
- On 2026-10-16 it held catalogVersion 2026.10.16 with 1,748 entries.
- Per-entry fields: `cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, forensicTriage, notes, cwes`.
- Source: [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)

### Inferences
- **Both SSVC trees can be computed for the KG.**
  - The vulnrichment fields map directly onto CISA's Exploitation, Automatable and Technical Impact.
  - The asset KG has to supply Mission Prevalence (from asset value / role, e.g. "Essential" if the asset directly provides a crown-jewel service) and Public Well-Being (usually "Minimal" in a lab; "Material/Irreversible" for OT/health assets).
  - For the **deployer** tree, Automatable and Exploitation come from vulnrichment (map poc → Public PoC). System Exposure comes from the asset KG's topology: Open = internet-reachable; Controlled = reachable only via filtered paths; Small = isolated or local-only. Human Impact comes from the asset's mission/safety attributes.
  - The thesis lab is a *deployer* (it patches and defends assets), so the deployer tree is conceptually the closer fit. The CISA tree is better documented and citable verbatim, so computing both and reporting both as baselines is cheap.
- **CVSS threat metrics only lower scores.**
  - v3.1: E/RL/RC default to 1.0; any defined value multiplies by ≤ 1.
  - v4.0: E=X equals Attacked.
  - So "threat context" inside CVSS can only *demote* non-exploited CVEs. Any *promotion* must come from the environmental metrics (CR/IR/AR = H, MAV = N) or from a score defined outside CVSS.
- **EPSS→E mapping is a design choice, not a standard.** FIRST gives none. A defensible rule:
  - KEV-listed or `ssvc_exploitation = active` → A.
  - `poc` or an ExploitDB entry → P.
  - Otherwise → U.
  - EPSS stays a separate continuous signal rather than being forced into E.
- **Use a library, not a hand implementation, for CVSS v4.** For Python + Neo4j, a maintained library avoids re-implementing the MacroVector lookup. The `cvss` PyPI package (v3.6, "CVSS2/3/4 library with interactive calculator", RedHatProductSecurity) fits — [PyPI cvss](https://pypi.org/project/cvss/); [GitHub](https://github.com/RedHatProductSecurity/cvss).
- **The stored SSVC fields are raw vulnrichment option strings.** `cti_kg/parse/cve.py::_ssvc` lower-cases the option *keys* (`ssvc_exploitation`, `ssvc_automatable`, `ssvc_technical_impact`) but stores the *values* verbatim. Normalise the values (e.g. `.lower()`) before looking them up in Table 9.

### Gaps
- The full CVSS v4.0 MacroVector lookup table was not reproduced; it lives in the FIRST reference calculator (`cvss_lookup.js`).
- The exact FIRST EPSS API docs page (the parameter list for `epss-gt`, `percentile-gt`, `order`, `date`) 404'd. `date=` and `scope=time-series` should be re-checked against current docs before use.
- Whether FIRST officially labels the 2026-06-15 model "EPSS v5" was not confirmed on first.org.
- The CERT/CC deployer outcome table above passed through a summarizer; verify row by row against the CERT/CC SSVC GitHub repo (`data/` decision tables) before quoting.

---

## 2. Graph/KG-based vulnerability and alert prioritization research (2019–2026)

### Takeaway
Graph-based prioritization falls into three families:
1. **Attack-graph analytics:** MulVAL, Bayesian attack graphs, PageRank-style AssetRank.
2. **Heterogeneous-graph / GNN exploitability prediction:** CVE–CWE–CPE–vendor graphs labelled with exploit evidence.
3. **KG-plus-weighted-criteria alert scoring:** TI-KG plus asset-vulnerability graph, scored with AHP.

Few works combine asset context with learned exploit likelihood and evaluate the result against an external ground truth. Most report self-defined metrics, so this is the gap the thesis can occupy.

### Cited Findings
- **Nagaty et al.**, "Construction of a Unified Knowledge Graph for Cyber Threat Intelligence" (ICCA 2025, DOI 10.1109/ICCA66035.2025.11430746) — local PDF `ref_papers/Construction_of_a_Unified_Knowledge_Graph_for_Cyber_Threat_Intelligence.pdf` ([DOI](https://doi.org/10.1109/ICCA66035.2025.11430746)):
  - Phase 4 "adopts GNN algorithms for enhancing the integrated Knowledge graph by predicting links, thereby detecting possible vulnerabilities and attack trajectories"; Phase 5 uses Neo4j for insight generation.
  - Validation is of the *graph*, not of a score: 100% ATT&CK–CAPEC crosswalk coverage, 100% CAUSES_WEAKNESS validation, 99.8% AFFECTS-edge accuracy, 98.83% CWE capture, and node-level retrieval F1 of 54.14%.
  - Future work names precision/recall of inferred EXPLOITED_BY links and GNN "hallucinated" relations as open problems.
  - It cites the SAPPAN framework (Spyropoulos et al.), which applies graph-based clustering and **alert ranking** over a CTI KG.
- **AssetRank (Sawilla & Ou, ESORICS 2008)** generalizes PageRank to dependency (MulVAL) attack graphs, using public vulnerability data to weight vertices. Its values "only indicate relative ranks and cannot be used to indicate absolute security risks". — [Sawilla & Ou, ESORICS 2008](https://cse.usf.edu/~xou/publications/esorics08.pdf)
- **StepRank (Almohri thesis)** extends AssetRank over a reversed (forward) MulVAL graph. — [Almohri, K-State thesis](https://krex.k-state.edu/server/api/core/bitstreams/543965c1-5ee1-44db-af32-8cc463bee9cd/content)
- A KTH degree project adds time-to-compromise parameters to PageRank on attack graphs. — [DiVA thesis](https://www.diva-portal.org/smash/get/diva2:1811242/FULLTEXT01.pdf)
- TriAssetRank ranks vulnerabilities, exploits and privileges for countermeasure prioritization (abstract/snippet only). — [TriAssetRank](https://www.researchgate.net/publication/385402428_TriAssetRank_Ranking_Vulnerabilities_Exploits_and_Privileges_for_Countermeasures_Prioritization)
- **Bayesian attack graphs over MulVAL** relax MulVAL's assumptions that exploit success is 100% and that vulnerabilities are independent. They use CVSS-derived exploit probabilities and conditional probabilities along attack paths. — [Improved MulVAL Bayesian Attack Graphs](https://www.researchgate.net/publication/290174563_Network_Security_Risk_Analysis_using_Improved_MulVAL_Bayesian_Attack_Graphs); [MulVAL extensions survey, arXiv 2208.05750](https://arxiv.org/pdf/2208.05750)
- NIST work aggregates vulnerability metrics across an enterprise network via attack graphs. — [NIST, "Aggregating Vulnerability Metrics in Enterprise Networks using Attack Graphs"](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=926022)
- **Heterogeneous-graph GNN exploitability prediction:**
  - Yin et al. 2023 ("Empowering Vulnerability Prioritization: A Heterogeneous Graph-Driven Framework for Exploitability Prediction", Springer) combines topological features with heterogeneous GNN embeddings and reports gains over per-vulnerability features (abstract/snippet only; paywalled). — [Springer chapter](https://link.springer.com/chapter/10.1007/978-981-99-7254-8_23)
  - ExPreHet (Knowledge-Based Systems 2025) builds a heterogeneous graph with four node categories and BiLSTM-based aggregation for exploitability prediction (snippet only). — [ScienceDirect](https://www.sciencedirect.com/science/article/abs/pii/S0950705125015564)
- **HARP (arXiv 2608.19430, Aug 2026)** ranks CVEs for a natural-language query. It retrieves evidence from a vulnerability KG and fuses "global, enterprise, and user views" with weights fit to preference examples, and reports beating "multiple baselines". Metrics and numbers were not visible in the abstract. — [arXiv 2608.19430](https://arxiv.org/abs/2608.19430)
- **KG + asset-vulnerability graph alert prioritization** ("Intelligent priority awareness method for alert data in SOC threat response", Springer 2026):
  - Fuses a TI-KG with an asset-vulnerability association graph to replace static device severity.
  - Scores six dimensions with AHP weights, including target criticality, attack-phase severity and attack continuity.
  - Reports a 45.2% reduction in mean response time (snippet only; paywalled, self-reported). — [Springer 2026](https://link.springer.com/article/10.1007/s44443-026-01172-w)
- **Alert-driven attack graphs** (arXiv 2408.09888) forecast next attacker actions from IDS alerts. An interview study with 6 SOC analysts found the forecasts helpful for prioritizing critical incidents, but the user study is small. — [arXiv 2408.09888](https://arxiv.org/pdf/2408.09888)
- **ACM CSUR survey "Alert Prioritisation in Security Operations Centres: A Systematic Survey on Criteria and Methods"** notes that graph representations of alerts can surface critical threats that look minor when each alert is viewed alone (snippet only; the full text returned 403). — [ACM 10.1145/3695462](https://dl.acm.org/doi/10.1145/3695462)
- A patent family ("Leveraging attack graphs of agile security platform"; assignee not verified) raises an alert's priority when the asset lies on a critical path of an attack graph. — [USPTO 11283825](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11283825)
- **Survey of 82 studies** (Jiang et al., arXiv 2502.11070, Feb 2025) groups prioritization metrics into severity, exploitability, contextual factors, predictive indicators and aggregation methods. It calls for "dynamic, context-aware metrics". A search snippet says predictive metrics appear mostly in ML methods (13 studies) and rarely in graph models (3 studies). — [arXiv 2502.11070](https://arxiv.org/abs/2502.11070)
- A journal paper claims a KG + GNN exploitation forecaster with 89.2% accuracy at 30 days (abstract only; **unverified**). — [JCSANDM](https://journals.riverpublishers.com/index.php/JCSANDM/article/view/29505)

### Inferences
- The thesis can follow the attack-graph tradition on its own Neo4j KG without MulVAL:
  - Compute **reachability paths** (Attacker/Internet → host → vulnerable software → CVE → Technique) with Cypher shortest paths, or with Neo4j GDS / NetworkX for PageRank and Personalized PageRank seeded at alerting hosts.
  - Propagate asset value backwards (AssetRank-style).
  - These are explainable and implementable in Python.
- GNN link prediction (the Nagaty Phase 4 / TACT direction) is best positioned as a **feature generator**, for example the predicted CVE→Technique or Asset→CVE link probability. It should not be the scorer. Its outputs are hard to validate and Nagaty himself flags hallucinated links.
- The AHP / weighted-criteria approach of the 2026 alert paper is the closest published analogue to the thesis's alert re-scoring. Its weights are expert-elicited, which needs a sensitivity analysis.

### Gaps
- Full texts of Yin et al. 2023, ExPreHet, the 2026 Springer alert paper, the ACM alert survey and HARP were paywalled or abstract-only. Their exact inputs, models, datasets and metric values are not verified.
- There was no head-to-head comparison of PageRank-style vs Bayesian attack-graph risk on a common topology.
- No KG-embedding (TransE/RotatE)-based *risk score* paper with external-ground-truth validation was found in this session.

---

## 3. Text-based approaches: SecBERT / SecureBERT / CVSS-BERT / LLMs predicting CVSS from descriptions

### Takeaway
Text models reconstruct **CVSS base** metrics from CVE descriptions reasonably well:
- BERT per-metric accuracy is about 84–96%, with base-score MAE about 0.73 (CVSS-BERT).
- 2024–2026 LLM studies show similar or modestly better per-metric results, with correlated errors.

They predict what NVD analysts would assign, not organisational context. They are therefore suited to **gap-filling** (CVEs lacking a CVSS vector, or CVSS v4 back-filling) and to mapping alert text to CVE/CWE/ATT&CK. They are not suited to being the re-scoring engine itself. This bears directly on the outline's stage-4 idea ("secBERT, ML for text classification").

### Cited Findings
- **CVSS-BERT (Shahid & Debar, IEEE ICMLA 2021)** — [arXiv 2111.08510](https://arxiv.org/abs/2111.08510):
  - One BERT classifier per CVSS v3 base metric, trained on 3 years of NVD CVEs; the test set has 22,963 CVEs.
  - Accuracy ranges from 83.79% (Privileges Required, the hardest) to 96.07% (Attack Complexity, inflated by 93% class imbalance), with Scope at 95.45%.
  - The base score computed from predicted vectors has MAE 0.73 and MSE 1.79; 55.3% match exactly and 75% are within 1 point.
  - Explainability comes from gradient-based input saliency.
- **CTIBench (NeurIPS 2024 Datasets & Benchmarks)** includes CTI-VSP: predict CVSS v3 vectors for 1,000 CVE descriptions from 2024, scored by MAE. — [CTIBench paper](https://proceedings.neurips.cc/paper_files/paper/2024/file/5acd3c628aa1819fbf07c39ef73e7285-Paper-Datasets_and_Benchmarks_Track.pdf)
  - The Cisco Foundation-sec-8B technical reports report results on CTIBench-VSP. — [arXiv 2508.01059](https://arxiv.org/pdf/2508.01059)
- **"From Description to Score: Can LLMs Quantify Vulnerabilities?"** (Jafarikhah et al., arXiv 2512.06781, Dec 2025 / Jan 2026) — [arXiv 2512.06781](https://arxiv.org/abs/2512.06781):
  - More than 31,000 recent CVEs; tests GPT-5, Llama, Grok, DeepSeek and Gemini.
  - Big gains over the baseline on some metrics (e.g. Availability Impact), modest gains on Attack Complexity.
  - LLMs "often misclassify the same CVEs" (correlated errors), so ensembles help only marginally.
  - Many errors trace to descriptions lacking context.
  - A search snippet cites GPT-5 at 84.66% vs a baseline of 83.85% on Attack Complexity (snippet only).
- **AutoCVSS (EMNLP 2025 Industry)** evaluates LLM prompting from bare metric names up to the full FIRST definitions for CVSS v3.1 base prediction. It criticises prior work (McClanahan et al. 2024) for scoring CVE IDs from memorised knowledge, which cannot work for CVEs after the knowledge cutoff (snippet only). — [AutoCVSS](https://aclanthology.org/2025.emnlp-industry.38.pdf)
- "Can LLMs Classify CVEs?" (arXiv 2504.10713) compares LLM prompting with supervised embedding-based models for CVSS vector generation (snippet only). — [arXiv 2504.10713](https://arxiv.org/pdf/2504.10713)
- A RoBERTa model for severity matched the eventual official severity about 85% of the time on recent CVEs (snippet only). — [arXiv 2507.03607](https://arxiv.org/pdf/2507.03607)
- Product context changes severity: an ACM study analyses product-specific CVSS scores that diverge from the generic NVD score. This supports the premise that a context-free CVSS is insufficient (title/snippet only). — [ACM 10.1145/3697090.3697109](https://dl.acm.org/doi/full/10.1145/3697090.3697109)

### Inferences
- Since the KG already holds CVSS v2/v3/v4 vectors for most CVEs, a text model adds value only for:
  - CVEs with missing vectors (NVD backlog; CNA-only records);
  - predicting v4 vectors where only v3 exists;
  - classifying Wazuh alert text into ATT&CK technique or CWE to link alerts into the KG. That last use overlaps with other researchers' alert-parsing scope.
- A text-only predictor of a "contextual score" has no supervised labels, because no public dataset of org-specific re-scored CVEs exists. A learned re-scorer would need labels from (a) exploitation (EPSS/KEV) or (b) the thesis's own testbed and analyst labels.
- If a text model is used, use temporal splits (train on CVEs before T, test on CVEs after T) to avoid memorisation, the issue AutoCVSS raises for LLMs.

### Gaps
- No verified accuracy figures were retrieved for SecBERT (jackaduma) or SecureBERT (Aghaei et al., 2022) on CVSS prediction specifically.
- The per-metric tables for the 2025–2026 LLM papers were not read in full.
- No paper was found that feeds asset context into a text model to produce a context-adjusted CVSS.

---

## 4. Validation methodology: comparing a new score with CVSS (metrics, baselines, datasets)

### Takeaway
Published practice uses three kinds of evidence:
1. **Rank/agreement statistics between scoring systems:** Spearman, Kendall, Pearson, Cohen's κ, Krippendorff's α, top-N overlap.
2. **Retrieval metrics against exploitation ground truth:** PR-AUC, F1, efficiency/coverage/effort, measured against KEV or exploitation activity in a forward window.
3. **Qualitative or user evidence:** analyst interviews, testbed scenarios.

Two pitfalls matter for this thesis:
- **Circularity.** KEV and SSVC exploitation are already features in the KG.
- **Unit of analysis.** KEV/EPSS labels are per CVE, while the thesis score is per asset×CVE or per alert.

### Cited Findings
- **Koscinski et al., "Conflicting Scores, Confusing Signals"** (arXiv 2508.13644, Aug 2025) — [arXiv 2508.13644](https://arxiv.org/html/2508.13644):
  - Data: 600 Microsoft Patch Tuesday CVEs (Apr–Jul 2024); 458 had EPSS scores.
  - Systems: CVSS, SSVC (computed under Low / Medium / High Mission & Well-Being settings), EPSS and Microsoft's Exploitability Index.
  - Statistics:
    - Kendall τ, Spearman ρ and Pearson r (with p-values).
    - Cohen's κ and Krippendorff's α on binned scores (SSVC in 4 bins, others in 10 equal bins).
    - Top-N overlap, triage effort (CVEs in the top-1..3 bins), t-SNE plots.
  - Results:
    - κ was about 0 for every pair (−0.01 to 0.03); α was mostly negative (e.g. CVSS–EPSS −0.45).
    - Only 5 CVEs appeared in all four systems' top-N lists.
    - CVSS had **198 ties in its top 20**.
    - Of 13 KEV CVEs, CVSS scored 12 above 0.7 (normalised), while EPSS scored 9 below 0.1 and left 3 unscored.
  - Across the full KEV (1,226 CVEs):
    - Only 19.9% had a peak EPSS ≥ 0.5 *before* their KEV addition date.
    - 8.3% reached ≥ 0.9.
    - 22.4% had no EPSS score before exploitation.
  - This "score as of before KEV dateAdded" analysis is a citable precedent for temporal validation.
- **Hellsten et al. (Aalto / Lockheed Martin), "When Cyber Scoring Systems Diverge"** (arXiv 2609.37217, Sep 2026) — [arXiv 2609.37217](https://arxiv.org/html/2609.37217v1):
  - Data: 659 vulnerability records (592 CVEs) on a reconstructed 2015 Ukraine power-grid OT topology; 113 have both CVSS v2 and v3.
  - Method: Spearman ρ with Benjamini–Hochberg correction.
  - Results:
    - CVSS v2 vs v3: impact r = 0.82, exploitability r = 0.86.
    - EPSS-365 vs IronMiner: r = 0.77; both only moderately correlated with CVSS.
    - SSVC was weakly correlated with all the others.
    - EPSS median was 0.03 at 30 days and 0.35 at 365 days.
  - KEV was an *input* (to SSVC and IronMiner), not ground truth.
  - Proposes heuristic hybrid formulas (a weighted composite and a CVSS-anchored priority) explicitly marked "not formally validated".
  - Conclusion: the scores are "not interchangeable" and divergence is structured, so multi-signal assessment is recommended.
- **EPSS v3 paper** — [arXiv 2302.14172](https://arxiv.org/abs/2302.14172):
  - **Temporal protocol:** features as of a test date, labels = exploitation in the following 30 days, a one-month gap between training cutoff and test date, and 5-fold CV stratified and grouped by CVE.
  - **Metrics:** PR-AUC (chosen for class imbalance), F1-optimal threshold, efficiency/coverage/effort.
  - **Baselines:** CVSS v3 base, EPSS v1/v2, simple rules (PR:N, ExploitDB).
- **Vulnerability Management Chaining** (Shimizu & Hashimoto, arXiv 2506.01220; listed as IEEE Access vol. 14, 2026) — [arXiv 2506.01220](https://arxiv.org/abs/2506.01220):
  - Two-stage rule: (KEV OR EPSS ≥ 0.088) → then CVSS ≥ 7.0.
  - On 28,377 vulnerabilities with vendor-reported exploitation: 85.6% coverage, 18× efficiency, about 95% fewer urgent items, and 48 exploited CVEs missed by both KEV and EPSS alone.
  - Snippet-level baseline numbers looked internally inconsistent and are omitted.
- **CVSS-BERT** evaluates against NVD labels with per-metric accuracy and weighted P/R/F1, plus MAE/MSE and exact-match rate on the reconstructed base score. This is the standard protocol for text→CVSS. — [arXiv 2111.08510](https://arxiv.org/abs/2111.08510)
- **Analyst/user evaluation:** a 6-analyst interview study of alert-driven attack graphs — [arXiv 2408.09888](https://arxiv.org/pdf/2408.09888); a mean-time-to-respond reduction as a SOC outcome metric (self-reported) — [Springer 2026](https://link.springer.com/article/10.1007/s44443-026-01172-w).
- **Public ground-truth sources**, verified accessible on 2026-10-17:
  - KEV, with `dateAdded` and `knownRansomwareCampaignUse` — [KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).
  - EPSS daily scores with history via `date=` and time-series — [EPSS API](https://api.first.org/data/v1/epss?cve=CVE-2021-44228&scope=time-series).
  - EPSS bulk daily CSVs — [EPSS CSV](https://epss.empiricalsecurity.com/epss_scores-current.csv.gz).
  - ExploitDB presence used as a weaker label in the EPSS paper — [arXiv 2302.14172](https://arxiv.org/abs/2302.14172).

### Inferences — a defensible three-tier validation protocol for the thesis
1. **Tier A: threat layer vs global ground truth (per CVE).**
   - Freeze all inputs as of date T: EPSS via `date=T`; SSVC from the vulnrichment git history at T; exclude the KEV flag, or use KEV status at T only.
   - Labels: KEV additions with `dateAdded` in (T, T+30/90 days], optionally plus EPSS-source exploitation.
   - Exclude CVEs already in KEV at T from the evaluation set.
   - KEV adds relatively few CVEs per month, so one 30-day window gives few positives. Use several rolling T dates and/or 90/180-day windows, and optionally add EPSS-source or ExploitDB evidence as a secondary label.
   - Report PR-AUC, F1-optimal efficiency/coverage/effort, and precision@k / recall@k.
   - Baselines: CVSS-B (v3.1 and v4), CVSS-BT, EPSS alone, KEV-only, the SSVC CISA tree, and VMC's (KEV ∨ EPSS ≥ 0.088) ∧ CVSS ≥ 7.
   - This avoids the circularity seen in Hellsten et al., where KEV fed the scores it was compared with.
2. **Tier B: context layer in the testbed (per asset×CVE / per alert).**
   - Global labels cannot validate asset context. Use the outline's attacker node (Kali / Atomic Red Team) to inject known attack chains against designated high-value assets, mixed with benign or noise activity and attacks on low-value hosts.
   - Ground truth: alerts and CVEs belonging to the injected chain that reach crown-jewel assets, labelled with graded relevance (e.g. 3 = chain step on a crown jewel, 2 = chain step elsewhere, 1 = related, 0 = noise).
   - Metrics: **NDCG@k**, precision@k, MRR (rank of the first true-chain alert), and the analyst workload needed to reach full coverage.
   - Baselines: Wazuh `rule.level`, the CVSS base of the linked CVE, CVSS-BT, EPSS, and ablations of the thesis score (−asset value, −reachability, −alert evidence, −threat).
   - State a **tie-break rule**, since CVSS has massive ties (198 in a top 20 per Koscinski).
3. **Tier C: agreement with experts and shift vs CVSS.**
   - Have 2–3 analysts (professor, SOC staff) independently rank or bin a sample of asset×CVE pairs using SSVC-style categories.
   - Report weighted Cohen's κ (or Krippendorff's α for more than 2 raters) between the thesis score and the experts, compared with CVSS-vs-experts.
   - Report Kendall τ / Spearman ρ between the new score and CVSS. Do not maximise this: a moderate ρ shows the score is related to CVSS but re-orders it. Show a confusion matrix of severity-band changes, e.g. "x% of CVSS-High demoted to Track for non-exposed low-value assets".
- **Statistics:** use bootstrap confidence intervals over CVEs or scenarios, and a paired test (e.g. a permutation test on NDCG@k) for new-score vs CVSS. Use Benjamini–Hochberg when many correlations are reported, as Hellsten does.

### Gaps
- No public dataset of *organisation-context* ground truth (asset×CVE priorities labelled by analysts) was found. Tier B/C labels must be self-generated, which should be acknowledged as a threat to validity.
- None of the papers examined in full reported NDCG@k for vulnerability prioritisation. NDCG is recommended by inference from IR practice, not cited precedent here.
- The vulnrichment repo's commit history as a source of as-of-T SSVC values is assumed from its git hosting (github.com/cisagov/vulnrichment) and was not verified in this session.

---

## 5. Practical recommendation: a defensible scoring design (CVSS base + threat + environmental + alert evidence)

### Takeaway
Build the score in transparent, standards-anchored layers, each ablatable:
1. **CVSS-BTE / Environmental** computed with standard formulas, with CR/IR/AR and MAV derived from the asset KG.
2. **Threat modifier** from KEV/SSVC/EPSS.
3. **Graph blast radius:** downstream asset value via Personalized PageRank in Neo4j. Direct exposure goes into MAV.
4. **Alert-evidence boost** from Wazuh alerts matched to the CVE or ATT&CK technique.

Report both a continuous score (for ranking metrics) and an SSVC-style categorical outcome (for agreement metrics). Use GNN/text models only as auxiliary feature generators. This whole section is an inference assembled from the cited components above.

### Cited Findings (components)
- The CVSS v3.1 Environmental formula and weights (CR/IR/AR H = 1.5, M = 1.0, L = 0.5; MAV N = 0.85 … P = 0.2) can encode asset value and network exposure in a standard, citable way. — [FIRST CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document)
- CVSS v4 BTE is the standards body's own "context-aware" score; providers publish only CVSS-B, so BT/BTE must be computed by the consumer. — [FIRST CVSS v4.0](https://www.first.org/cvss/v4.0/specification-document)
- Combining KEV, EPSS and CVSS in a chained rule retained 85.6% coverage with about 95% workload reduction. — [arXiv 2506.01220](https://arxiv.org/abs/2506.01220)
- Single scores disagree structurally, and multi-signal assessment is recommended. — [arXiv 2609.37217](https://arxiv.org/html/2609.37217v1); [arXiv 2508.13644](https://arxiv.org/html/2508.13644)
- EPSS misses many exploited CVEs before KEV listing (only 19.9% reached ≥ 0.5 beforehand), so EPSS should not be the sole threat signal. — [arXiv 2508.13644](https://arxiv.org/html/2508.13644)
- The CISA SSVC tree gives a citable categorical mapping from (Exploitation, Automatable, Technical Impact, Mission & Well-Being) to an action. — [CISA SSVC Guide](https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf)
- PageRank-style attack-graph ranks are relative and not absolute risk. Use them as rank or normalised features, not probabilities. — [Sawilla & Ou](https://cse.usf.edu/~xou/publications/esorics08.pdf)

### Inferences — proposed design (Python + Neo4j)
For each pair (asset a, vulnerability v), optionally triggered by an alert x:

1. **Base:** `B = CVSS v3.1 base` (or v4 CVSS-B), read from the Vulnerability node. Use v3.1 for the closed-form environmental computation; use the `cvss` library for v4.
2. **Environmental (standard):** `S_env = CVSS v3.1 EnvironmentalScore`, computed with:
   - CR/IR/AR from asset value. Example: crown-jewel data store → CR = H, IR = H; availability-critical service → AR = H; lab workstation → L.
   - **MAV** from KG reachability. Internet- or attacker-zone-reachable → N; same subnet only → A; local only → L.
   - Optionally **MPR** from whether the attacker's foothold already holds credentials on the path.
   - E/RL/RC from the threat mapping in step 3. This yields a fully standard CVSS-BTE-equivalent number, which is the strongest defence in a viva.
3. **Threat mapping:**
   - E = H (v3.1) / A (v4) if the CVE is in KEV (dateAdded ≤ now) or `ssvc_exploitation = active`.
   - E = P/F if `poc`.
   - E = U otherwise.
   - Keep EPSS percentile as a separate continuous feature `T = EPSS percentile`, because CVSS threat can only demote.
4. **Graph blast radius:** `G ∈ [0,1]`.
   - To avoid double-counting, *direct* reachability of asset a is already encoded in MAV (step 2). G should instead measure **downstream impact**: how much asset value becomes reachable *from* a once it is compromised (lateral movement / pivot potential).
   - Compute it from either:
     - an AssetRank-style propagation: normalised Personalized PageRank on the Asset+CTI KG, seeded at a, over CAN_REACH/TRUSTS edges, weighted by target asset value (Neo4j GDS or NetworkX); or
     - a simple sum: the asset value of nodes within k hops of a, normalised.
   - Ablating MAV and G separately then tests distinct hypotheses: exposure of a vs consequences beyond a.
5. **Alert evidence:** `A ∈ {0, 0.5, 1}`:
   - 1: a Wazuh alert maps to this CVE, or to an ATT&CK technique linked to the CVE's CWE/CAPEC, on asset a within the last N hours.
   - 0.5: the alert is on a neighbouring asset in the attack path.
   - 0: no alert evidence.
6. **Final continuous score**, with S_env as the floor and context able to raise it:
   - `R = min(10, S_env + (10 − S_env) × (α·T + β·G + γ·A) / (α + β + γ))`.
     - With no threat, blast-radius or alert evidence, R = S_env, the standard CVSS-BTE-equivalent.
     - With all three maximal, R = 10.
     - Each signal closes part of the gap to 10, so a confirmed alert on a crown-jewel asset can lift a medium CVSS above High.
     - Demotion is handled by the standard part: CR/IR/AR = L, MAV = L/P, E = U lower S_env.
   - or
   - a learned version: logistic regression or gradient boosting on [B, S_env, T, KEV, G, A, CWE scope features], trained on Tier-A temporal labels for the threat part only.
   - α, β, γ are set by expert judgement (AHP, as in the 2026 alert paper) and then subjected to a sensitivity analysis.
7. **Categorical outcome:**
   - CISA SSVC Table 9, with Mission Prevalence from asset value and Well-Being from asset safety attributes; or
   - the deployer tree, with System Exposure taken from MAV (N → Open, A → Controlled, L/P → Small).
8. **Report:**
   - For each asset×CVE: the CVSS base, the new score, the delta, and the SSVC outcome.
   - For each alert: a priority equal to the max R over the CVEs/techniques it links to.
   - Explanations: the Cypher path(s) and per-layer contributions.

**Ablation table** (maps directly onto the Tier A/B/C validation in Section 4):

| Variant | Purpose |
|---|---|
| CVSS-B | baseline |
| + E (CVSS-BT) | threat via CVSS only |
| + CR/IR/AR/MAV (CVSS-BTE) | standard environmental context |
| + EPSS | continuous threat |
| + G | graph blast radius |
| + A | alert evidence |
| SSVC (CISA) | categorical baseline |
| SSVC (deployer) | categorical baseline |

**Where ML/GNN fit:**
- TACT/GNN link prediction can add predicted Asset→CVE or CVE→Technique edges, flagged with confidence. Report results with and without predicted edges.
- A SecBERT/LLM classifier can fill missing CVSS vectors and map alert text to techniques.
- Neither should define the final score without the Tier-A/B labels.

### Gaps
- No published paper validates exactly this layered design. The weights α/β/γ and the asset-value→CR/IR/AR mapping are design choices to justify with expert input and sensitivity analysis.
- The interaction between CVSS v4 environmental metrics and asset value (e.g. using MSI/MSA Safety) was not explored. v3.1 is simpler for closed-form computation, but NVD increasingly publishes v4. Consider computing both.
