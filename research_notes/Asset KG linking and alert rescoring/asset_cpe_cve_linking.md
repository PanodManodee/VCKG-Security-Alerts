# Linking host software/OS inventory to CPE and CVE (Asset KG ↔ CTI KG)

Scope: methods, tools, accuracy and pitfalls for mapping installed software and OSes (Wazuh syscollector, dpkg/rpm, the Windows registry, nmap -sV) to CPE names and then to CVEs, including version-range evaluation. Grounded in the project's existing Neo4j CTI KG: `(CPE {cpe23})-[:VULNERABLE_TO {version_start_including, version_start_excluding, version_end_including, version_end_excluding}]->(Vulnerability)`, built from cvelistV5 and NVD 2.0 (see `/home/panodmanodee/projects/cyber_crime_projects/schema.md`).

Local sources used:
- Nagaty et al., "Construction of a Unified Knowledge Graph for CTI", ICCA 2025: `/home/panodmanodee/projects/cyber_crime_projects/ref_papers/Construction_of_a_Unified_Knowledge_Graph_for_Cyber_Threat_Intelligence.pdf`
- Høst, Lison & Moonen, "Constructing a KG from Textual Descriptions of Software Vulnerabilities in the NVD": `/home/panodmanodee/projects/cyber_crime_projects/ref_papers/Constructing a Knowledge Graph from Textual Descriptions of Software Vulnerabilities in the National Vulnerability Database.pdf`

---

## Q1. How do you generate or match CPEs from inventory data, which tools exist, and how accurate are they?

### Takeaway
No tool reliably turns a raw inventory string (a dpkg/rpm package name, a Windows "DisplayName/Publisher", or a banner) into the right NVD vendor:product. Every practical pipeline normalises the name, generates candidates from the NVD CPE dictionary, ranks them by fuzzy or keyword similarity, and accepts only above a threshold or after a human check. The modern scanners (Grype, Trivy) avoid CPE matching for distro and language packages entirely because it causes so many false positives. They match OS packages against distro advisories and use purl/ecosystem IDs for libraries.

### Cited Findings

**NVD reference data you can match against**
- The NVD CPE API 2.0 (`https://services.nvd.nist.gov/rest/json/cpes/2.0`) accepts a `cpeMatchString` and returns CPE names that exist in the Official CPE Dictionary, at up to 10,000 per page — [NVD developers: Products](https://nvd.nist.gov/developers/products); [nvdlib docs](https://nvdlib.readthedocs.io/en/latest/v2/CPEv2.html)
- The Match Criteria API `/cpematch/2.0` (GET) takes `cveId`, `matchCriteriaId` (a UUID), `lastModStartDate`/`lastModEndDate`, `resultsPerPage` and `startIndex`. NVD capped it at 500 results per page from 15 April 2024. Rate limits are 5 requests per 30 s without a key and 50 per 30 s with one — [NVD news: cpematch resultsPerPage update](https://nvd.nist.gov/general/news/cpematch-resultsperpage-update); [apis.io NVD CPE Match spec](https://apis.io/apis/nvd/nvd-cpe-match-api/)
- The CPE Match feed exists so consumers do not have to compute matches themselves. Searching it for an identical set of match criteria gives the concrete dictionary CPE names that satisfy those criteria (originally in a `cpe_name` array, updated nightly). The 1.0 feed is being retired in favour of the 2.0 APIs and 2.0 feed files — [NVD: CPE Match Feed 1.0 release](https://nvd.nist.gov/general/News/CPE-Match-Feed-1-0-Release); [NVD Data Feeds](https://nvd.nist.gov/download.aspx)
- CPE 2.3 name matching (NISTIR 7696, August 2011) defines a one-to-one comparison of a source CPE name against a target CPE name — [NIST IR 7696](https://csrc.nist.gov/pubs/ir/7696/final) ([PDF](https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf))

**Name-to-CPE tools**
- **CIRCL / vulnerability-lookup cpe-guesser** splits vendor and product names from the NVD CPE Dictionary 2.0 feed into single canonicalised words and builds an inverted index from each word to vendor:product pairs. Results are ranked by how common the vendor:product tuple is. It can optionally re-rank using CPEs found in cvelistV5 records (`import_cvelistv5.py`). It runs on Valkey and Python and has a `/search` endpoint (with a `part` filter of a/o/h) and a `/unique` endpoint that returns the single best match. A public instance runs at cpe-guesser.cve-search.org. The README's own example `microsoft sql server` also returns unrelated products (an IBM Tivoli entry), and `/unique` for "outlook connector" returns `oracle:corporate_time_outlook_connector`. The output is only a vendor:product guess with no version — [GitHub vulnerability-lookup/cpe-guesser](https://github.com/vulnerability-lookup/cpe-guesser); [CIRCL mirror README v1.2](https://helga.circl.lu/adulau/cpe-guesser/raw/tag/v1.2/README.md)
- **Dependency-Track Internal Analyzer** matches components that have a valid CPE or purl against a vulnerable-software dictionary built from NVD, GitHub Advisories, OSV or VulnDB mirroring. It follows the NIST CPE name matching spec with customisations. To cut false positives it discards a match when vendor=SUBSET and product=SUPERSET, or the reverse. Its example is a `zstandard` component CPE that would otherwise match `pascom_cloud_phone_system` — [Dependency-Track docs: Known vulnerabilities](https://docs.dependencytrack.org/analysis-types/known-vulnerabilities/)
- **Grype/Syft** has per-ecosystem `using-cpes` switches. Golang, JavaScript, Python, Ruby, Rust, Hex, dpkg and rpm all default to `false`. There is a separate `use-cpes-for-eol` option for end-of-life distros, and the "stock" matcher defaults to `true` — [Grype configuration reference](https://oss.anchore.com/docs/reference/grype/configuration/); [testdocs mirror (shows JVM=true)](https://testdocs.anchore.com/docs/reference/grype/configuration)
- Anchore stopped default CPE matching because NVD CPEs do not separate ecosystems: a package "foo" in one ecosystem matches an unrelated "foo" in another. On their labelled test data, dropping CPEs removed 2,000+ false-positive matches and added 11 false negatives. One example was Protobuf CVEs being applied to Go packages, 44 instances in etcd, Prometheus and kubectl — [Anchore: False positives and false negatives (29 May 2025)](https://anchore.com/blog/false-positives-and-false-negatives-in-vulnerability-scanning); [Anchore: Say goodbye to false positives](https://anchore.com/blog/say-goodbye-to-false-positives/)
- The trade-off is visible: a CVE that exists only as an NVD CPE can be missed, and correcting CPEs in the SBOM restored the expected results — [syft issue #2281](https://github.com/anchore/syft/issues/2281); [Anchore community: Grype doesn't match CVE-2025-24813](https://anchorecommunity.discourse.group/t/grype-doesnt-match-cve-2025-24813/363)
- **Trivy** checks OS packages (dpkg/yum/apk) only against the OS vendor's advisories: the Debian Security Tracker and OVAL, the Ubuntu CVE Tracker, Red Hat OVAL/Security Data, Alpine secdb and Amazon ALAS. It checks language packages against GHSA, the Go vulndb and OSV. The docs describe no NVD CPE matching; NVD is used only as a severity fallback — [Trivy docs: Vulnerability scanner](https://trivy.dev/docs/latest/scanner/vulnerability/)
- **nmap vulners NSE** takes the CPE that nmap `-sV` emits for an open port, sends the CPE and version to the vulners.com API, and falls back to the software name alone. Matching happens on the server. The script's source carries TODOs about pulling the version from the wrong CPE field — [nmap NSE: vulners](https://nmap.org/nsedoc/scripts/vulners.html); [vulners.nse source](https://svn.nmap.org/nmap/scripts/vulners.nse)
- **Wazuh (before 4.8)** mapped Windows packages through a "CPE Helper" translation dictionary covering common programs. A package with no translation could not get a CPE and so could not be matched to NVD — [Wazuh Google Group: Windows only detects OS CVEs?](https://groups.google.com/g/wazuh/c/HzKJuw8qDgA); [Wazuh Google Group: False positives for Windows](https://groups.google.com/g/wazuh/c/lu0Fdr1cuC4). For 4.8 and later, see Q3.
- A USPTO patent notes that Windows installation records generally lack CPE names. The publisher registry key helps for some vendors, such as Microsoft Office, but not for most Windows software — [USPTO 12361138](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/12361138)

**Benchmarks of tool retrieval accuracy (inventory → CVE)**
- VulCPE (arXiv 2505.13895, NUS/NCS, May 2025, preprint) tested retrieval on a test system with a network segment (4 components), a Linux VM (46 components) and a Windows VM (22 components). Average precision / coverage:

  | Method | Precision | Coverage |
  |---|---|---|
  | NVD keyword | 0.149 | 0.017 |
  | NVD exact keyword | 0.278 | 0.010 |
  | cve-search keyword | 0 | 0 |
  | OpenCVE keyword | 0.096 | 0.136 |
  | NVD CPE query | 0.709 | 0.954 |
  | cve-search product query | 0.679 | 0.809 |
  | OpenCVE CPE query | 0.276 | 0.314 |
  | VulCPE | 0.766 | 0.926 |

  Its prose gives VulCPE's average precision as 72.6%, which does not match the table's 0.766 — [VulCPE arXiv HTML](https://arxiv.org/html/2505.13895v1)
- VulCPE also reports vendor-name inconsistency in 50.18% of NVD vendors and 47.07% of CVEdetails vendors. It cites Anwar et al. 2020 ("Cleaning the NVD") as finding 1,835 inconsistent vendor names in 871 groups — [VulCPE](https://arxiv.org/html/2505.13895v1). The Anwar paper itself was not retrieved.
- A 2025–26 empirical study of SBOM-based scanning (Zhou, Dacier, Konstantinou; 2,414 repositories) found a 92.0% false-positive rate for downstream scanners in its case study, mainly from vulnerabilities in **unreachable code**, not from identifier mismatch. Function-call analysis pruned 61.9% of those false alarms. Lock-file-based SBOMs were accurate and consistent — [arXiv 2511.20313](https://arxiv.org/abs/2511.20313) (DOI 10.1145/3800506.3803490)

### Inferences
- **Route each inventory source to the right matcher.** These are design recommendations derived from the sources above:
  1. **Distro packages (dpkg/rpm from syscollector)** should not go through NVD CPE at all. Use distro data: Wazuh's own vendor-feed results, or the Debian/Ubuntu/RHEL OVAL and trackers (see Q3). Every serious open-source scanner (Trivy, Grype, Wazuh) does this.
  2. **Windows registry programs and macOS apps** have no ecosystem ID, so CPE matching is the only route. Normalise, generate candidates, fuzzy-score (Vajra-style, Q2), and keep a manual override table. This fits the project's `overrides/*.csv` convention.
  3. **nmap `-sV`** already emits a CPE, which may be in the older CPE 2.2 URI form (`cpe:/a:vendor:product:version`); this form was not verified against nmap docs here. Convert it to 2.3 formatted-string form and treat it as a concrete CPE. Its version is often coarse or missing, and backported distro banners (e.g., OpenSSH on Debian) will over-match.
  4. **Language packages (pip/npm)** should use purl and OSV/GHSA, not CPE.
- For a thesis, cpe-guesser is the quickest candidate generator, run locally against the same NVD dictionary. Its frequency ranking favours popular products, though, so it needs a vendor check (inventory vendor vs CPE vendor) and a version-existence check against the CPE dictionary before accepting a match.
- VulCPE's table suggests that once a correct CPE is in hand, NVD-CPE-based retrieval reaches roughly 0.7 precision and 0.95 coverage. The bottleneck is getting the CPE right, not the CVE lookup.

### Gaps
- No peer-reviewed precision/recall figure was found for cpe-guesser, OpenCVE or cve-search in inventory→CPE mapping specifically. VulCPE's small three-system test is the only head-to-head.
- The exact JSON field names of the NVD `/cpematch/2.0` response (the list of concrete `cpeName`/`cpeNameId` matches under each match criteria record) could not be confirmed because the NVD developer page failed to load. Verify against a live API response.
- How Syft generates CPEs for packages (its vendor/product candidate heuristics) was not retrieved; the Anchore docs URL returned 404.
- NISTIR 7696's full attribute-relation table (EQUAL/SUBSET/SUPERSET/DISJOINT, with ANY/NA handling) was not fetched as text. Only SUBSET/SUPERSET use is confirmed, via Dependency-Track's docs.

---

## Q2. Research papers (2019–2026) on automatic CPE assignment and software-to-CPE matching: methods and results

### Takeaway
The literature splits into two different tasks that should not be conflated. (a) **Extracting CPEs from CVE text**, on the NVD side, is a NER/RE task, and recent models report F1 of 0.86 to 0.96. (b) **Mapping a host's inventory to CPEs**, the task this project needs, has far fewer and smaller studies, using fuzzy matching, ML ranking or graph matching. These report candidate reduction or detection-rate gains, not rigorous precision/recall.

### Cited Findings

**(a) CPE extraction from CVE descriptions (NVD side; not inventory matching)**
- Wåreus & Hell, "Automated CPE Labeling of CVE Summaries with Machine Learning" (DIMVA 2020) use a BLSTM-CRF NER over CVE summaries. They report P=0.8571, R=0.8637, F=0.8604, and full reconstruction of all CPEs in 67.44% of CVE summaries — [Springer](https://link.springer.com/chapter/10.1007/978-3-030-52683-2_1); [Lund University record](https://www.lunduniversity.lu.se/publication/55a6bc35-97e0-4b67-b7c8-a4c0c9bedf77)
- Hu & Thing, "CPE-Identifier" (arXiv 2405.13568, May 2024, ST Engineering) use a BERT auto-annotator plus DistilRoBERTa augmentation, with roughly 361k sentences and 5 entity types (vendor, product, version, update, edition). BERT reaches P=94.83%, R=96.14%, F1=95.48%; the product class alone is about 87% F1. They state that prior CPE work generally had F1 < 90%, and they describe Huff et al. 2021's data as insufficient — [arXiv 2405.13568](https://arxiv.org/html/2405.13568v1)
- VulCPE's NER (RoBERTa plus a CVEdetails gazetteer) reaches P=95.77%, R=97.54%, F1=96.53%, and its RE reaches F1=93.74% on NER input. It compares against VIEM (USENIX Sec 2019) and VERNIER (2023). VulCPE also turns phrases like "before X" into explicit release lists to handle non-sequential version histories — [VulCPE](https://arxiv.org/html/2505.13895v1)
- Høst, Lison & Moonen extract vendor→product→version relations from NVD text by word order. TuckER entity prediction over their KG scores Hits@10=0.760, Hits@3=0.728, Hits@1=0.682 and MRR=0.710, against Rastogi et al. 2023's Hits@10=0.804. These are aggregate KG link-prediction metrics, not a CPE-matching accuracy — local PDF `ref_papers/Constructing a Knowledge Graph ... National Vulnerability Database.pdf`, Table 3

**(b) Inventory/asset → CPE matching**
- Huff, McClanahan, Le & Li, "A Recommender System for Tracking Vulnerabilities" (ARES/NG-SOC workshop 2021; University of Arkansas and Bastazo) combine NLP, fuzzy matching and machine learning (Random Forest, per the CPE-Identifier paper) to narrow each inventory software name to a minimal set of candidate CPE vendor/product names. They report about 2 candidates on average versus about 119 with manual search — [ACM DL 10.1145/3465481.3470039](https://dl.acm.org/doi/abs/10.1145/3465481.3470039); [NSF PAR](https://par.nsf.gov/biblio/10321252)
- Sawant, Hanawal & Kabra, "Improving Discovery of Known Software Vulnerability" ("Vajra", arXiv 2412.16607, December 2024, IIT Bombay), pipeline:
  1. Collect inventory with osquery.
  2. Sanitise names: strip "Inc./LLC/Technologies", architecture strings, language codes, parentheses and `.app`; lower-case.
  3. Normalise vendors, e.g. "Microsoft Corp." → "microsoft".
  4. Trim versions, e.g. "2.4.11-I602-Win10" → "2.4.11".
  5. Run SQL UNION queries over a local CPE dictionary at four priority weights:
     - weight 1: title + vendor + version
     - weight 2: product + vendor + version
     - weight 3: relaxed title/product + version
     - weight 4: title + version
  6. Score candidates with RapidFuzz `fuzz.ratio`, using a ≥70% threshold at weight 1 and lower thresholds for the other weights.

  On 10 Windows applications it found vulnerabilities in 7/10 versus 5/10 for FleetDM ("40% improvement"); on a second sample, 4/6 versus 2/6. The evaluation is tiny and measures detection, not verified precision — [arXiv 2412.16607](https://arxiv.org/pdf/2412.16607) (PDF text read directly)
- Tovarňák, Sadlek & Čeleda, "Graph-Based CPE Matching for Identification of Vulnerable Asset Configurations" (IFIP/IEEE IM 2021, pp. 986–991) store CVE configurations and CPE-classified asset configurations in one graph. A single Gremlin traversal finds vulnerable CVE↔asset-configuration pairs, avoiding brute-force comparison — [MUNI publication record](https://ics.muni.cz/en/research/publications/1786631); [IEEE 9463994](https://ieeexplore.ieee.org/document/9463994)
- VulCPE builds on Tovarňák et al. It represents configurations as directed AND/OR graphs (uCPE) and checks whether a system's configuration graph satisfies a CVE's configuration graph, which filters out "running-on" false positives. It argues that keyword search and static CPE matching ignore configuration dependencies — [VulCPE](https://arxiv.org/html/2505.13895v1)
- Sadlek, Čeleda & Tovarňák, "Current Challenges of Cyber Threat and Vulnerability Identification Using Public Enumerations" (ARES 2022) list asset discovery, vulnerability-detection precision and data volume as open problems. They also note that cooperation between asset-management, vulnerability and threat standards is unresolved — [arXiv 2206.14539](https://arxiv.org/abs/2206.14539)
- A USPTO patent describes field-by-field CPE matching with a text-distance threshold (e.g., d ≥ 0.9) to tolerate imprecise names — [USPTO 10089473](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/10089473)

### Inferences
- The NER work in (a) is only indirectly useful. It could recover CPEs for CVEs that NVD has not yet analysed (the backlog), using cvelistV5 `affected` text, to fill in missing `VULNERABLE_TO` edges. It does not solve inventory matching.
- A defensible thesis pipeline for (b) is Vajra-style sanitisation, then candidate generation (cpe-guesser or SQL/Cypher over CPE dictionary nodes), then RapidFuzz scoring on vendor and product separately, then a version-existence check, then a manual override CSV. Report precision/recall against a hand-labelled set of the lab's own packages (a few hundred rows is feasible). This gives a measured number where the literature gives none.
- Tovarňák and VulCPE are the closest prior art to "asset KG + CVE KG in a graph DB". They are the right citations for the graph-modelling choice in Q4.

### Gaps
- The full-text evaluation numbers (precision/top-k accuracy) for Huff et al. 2021 could not be retrieved: ACM returned 403 and NSF PAR refused the connection. Only the abstract's ~2-vs-~119 candidate figure is cited.
- Tovarňák et al.'s evaluation details (graph size, query time) were not retrieved; only the abstract was available.
- No 2019–2026 paper using sentence embeddings or LLMs for inventory→CPE matching with a reported precision/recall was found within this search budget.

---

## Q3. Correct version-range evaluation, distro backports and OVAL/trackers; how Wazuh does it; Wazuh as ground truth

### Takeaway
NVD version ranges use upstream versions. Distros backport fixes without changing the upstream version string, so comparing a dpkg/rpm version against NVD ranges systematically over-reports. Correct evaluation for OS packages needs the distro's own fixed version (Debian/Ubuntu trackers and OVAL, Red Hat OVAL) and a distro-aware version comparator (epoch:upstream-revision). Wazuh ≥4.8 already does this with its CTI feed. Its `wazuh-states-vulnerabilities-*` state index, not its alert stream, can serve as a validation reference, but it measures agreement rather than a gold standard.

### Cited Findings

**Backports and distro feeds**
- Trivy's Red Hat example: `requests` 2.20.0 is fixed for CVE-2023-32681 by a backport, so comparing against the upstream version would be a false positive. Trusting vendor advisories cuts false positives but can cause false negatives if the vendor is slow; `--detection-priority comprehensive` also checks upstream advisories. Unfixed vulnerabilities can be hidden with `--ignore-unfixed` — [Trivy docs](https://trivy.dev/docs/latest/scanner/vulnerability/)
- Trivy's Debian page gives an example: for CVE-2023-3269, the Debian 12 fixed version in the Security Tracker is `6.1.37-1`, and typically only upstream information is listed on NVD — [Trivy docs: Debian](https://trivy.dev/docs/v0.67/coverage/os/debian/)
- Backporting is described as a persistent source of scanner false positives because distros keep the upstream version string — [Pagely support](https://support.pagely.com/hc/en-us/articles/360020671131-Vulnerability-Scanners-returning-false-positives-due-to-backporting); [DevGuard: False positive detection](https://docs.devguard.org/explanations/vulnerability-management/false-positive-detection)
- Ubuntu publishes OVAL at security-metadata.canonical.com/oval/. The USN feed `com.ubuntu.<release>.usn.oval.xml.bz2` is generated from USNs and can be used to check for missing patches. The CVE feed `com.ubuntu.<release>.cve.oval.xml.bz2` covers all tracked CVEs, including unfixed ones. There are OCI-specific variants such as `oci.com.ubuntu.focal.usn.oval.xml.bz2`. The usual evaluation tool is `oscap oval eval` — [Ubuntu OVAL docs](https://documentation.ubuntu.com/security/security-updates/oval/); [ubuntu.com/security/oval](https://ubuntu.com/security/oval)
- A dpkg epoch-handling bug in OpenSCAP's comparator (it errored when no epoch was given) was fixed via a stable release update. This shows that comparator details matter — [Ubuntu sponsors list, Feb 2023](https://lists.ubuntu.com/archives/ubuntu-sponsors/2023-February/075122.html)

**Version comparators in Python**
- `univers` (aboutcode) implements per-ecosystem version comparison and range parsing. It uses `packaging` for PyPI, `debian-inspector` for Debian, an embedded `rpm_vercmp` for RPM, and `semantic_version` for npm/semver. It also converts native ranges to the `vers:` unified range syntax, e.g. `vers:pypi/>=1.2.3` — [PyPI univers](https://pypi.org/project/univers)

**Wazuh vulnerability detection (4.8+, current docs 4.14.x)**
- Since 4.8.0, vulnerability detection no longer pulls external feeds directly from distributions and NVD. It uses Wazuh's own CTI platform and needs the Wazuh indexer — [Wazuh 4.8.0 release notes](https://documentation.wazuh.com/4.8/release-notes/release-4-8-0.html)
- The CTI sources are OS vendors (AlmaLinux, Amazon Linux, Arch, Canonical/Ubuntu, Debian, Fedora, Oracle, RHEL, Rocky, SUSE), Microsoft Security Updates (MSU), NVD, OSV and CISA. npm and PyPI come from OSV. The Vulnerability Detector Provider normalises everything to CVE JSON 5, sanitises it (e.g. fixing version mismatches) and merges internal "product name mappings, product translations, OS base rules", producing one document per CVE. macOS and Windows apps are covered via NVD; Linux distros via vendor feeds — [Wazuh docs: How it works (current)](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html)
- Matching correlates syscollector inventory with CTI by CVE and version: a package is vulnerable if its version falls in the affected range. The alert condition reads like "Package less than 136.0.7103.59". The docs do not describe CPE use or per-format comparators — [Wazuh docs: How it works](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html)
- On Windows, the syscollector `hotfixes` option lets Wazuh mark CVEs as solved using Microsoft data — [Wazuh docs](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html). Known Windows issues include cumulative KBs and gaps in MSU data for new builds, causing stale "missing patch" findings (tracked in wazuh/wazuh#15160) — [Wazuh Google Group: Windows patch false positives](https://groups.google.com/g/wazuh/c/O5_x2fLko-c)
- A Wazuh maintainer reply in a Google Groups thread (Wazuh version not stated) says the vendor feed is checked first and NVD is used only if the package is not found in the vendor feed — [Wazuh Google Group: debian-security false positives](https://groups.google.com/g/wazuh/c/yD2wGnkdrwY)
- **Output:** the index `wazuh-states-vulnerabilities-server` (state, only unresolved vulnerabilities). Fields include:
  - `agent.id/name/version`
  - `host.os.*`
  - `package.name/version/architecture/type/size`
  - `vulnerability.id/severity/category/classification/enumeration/detected_at/published_at/reference/under_evaluation`
  - `vulnerability.scanner.{condition, reference, source, vendor}`
  - `vulnerability.score.{base, version}`

  — [Wazuh docs](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html)
- **The alert stream undercounts.** Alerts are not generated for: the initial inventory sync; changes made while the agent was stopped or detected only after a restart; re-sync after switching cluster node; and re-evaluations caused by CTI content updates. OS-level alerts do not appear on the first scan — [Wazuh docs](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html)
- Scans run when new syscollector inventory arrives. The CTI feed update interval defaults to 60 minutes (values under 60m are ignored, per the 5.0 beta docs) — [Wazuh 5.0-beta docs](https://documentation.wazuh.com/5.0-beta/user-manual/capabilities/vulnerability-detection/index.html)
- There is no dedicated Wazuh manager REST endpoint for vulnerabilities (stated for v4.14.4). Query the indexer's OpenSearch `_search` on `wazuh-states-vulnerabilities-*` (port 9200) with a read-only indexer user — [Wazuh Google Group: Vulnerability detection - API](https://groups.google.com/g/wazuh/c/4muQrHHqc40); [DefectDojo Wazuh connector](https://docs.defectdojo.com/connectors/toolreference/wazuh/)

### Inferences
- **Version-range evaluation rules for the KG**, applied in Python:
  - For each `(:CPE)-[r:VULNERABLE_TO]->(:Vulnerability)`:
    - If the criteria CPE's `version` is `*` (ANY), evaluate the edge range: `start_incl ≤ v`, `start_excl < v`, `v ≤ end_incl`, `v < end_excl`. A missing bound means unbounded.
    - If no bounds are set and the version is `*`, every version is affected.
    - If the version is concrete, require equality, or a full CPE 2.3 match including `update`.
    - If the version is `-` (NA), it is a "no version" product and should be matched specially, not as a wildcard.
  - Use `univers` for the comparator family: generic/semver for Windows and app versions, debian for dpkg, rpm for rpm.
  - NVD ranges are upstream versions, so strip the Debian revision and epoch before comparing a dpkg version to an NVD range, and accept that this cannot see backports.
- **Recommended split.** For distro-managed packages, take the asset→CVE fact from Wazuh's state index, or from Debian/Ubuntu tracker/OVAL data. Use the KG's NVD-CPE route only for Windows/macOS applications, nmap-discovered services and anything not covered by a distro feed. This mirrors Trivy, Grype and Wazuh, which all prefer vendor feeds for OS packages.
- **Using Wazuh as a validation reference:**
  1. Pull the state index via the indexer `_search`, not alerts.
  2. Join with the KG's computed links on (`agent.id`, `package.name`, `package.version`, `vulnerability.id`).
  3. Report precision and recall of the KG against Wazuh, partitioned by `vulnerability.scanner.source`/`vendor` (distro feed vs NVD) and by OS.
  4. Adjudicate disagreements by hand against the Debian/Ubuntu tracker or NVD. Wazuh has its own known false positives (Windows MSU gaps, missing translations), so it is a reference for agreement, not ground truth.
  5. A small hand-verified sample gives the true error rate of both.
- `vulnerability.scanner.condition` (e.g. "Package less than X") gives the distro fixed version when the source is a distro feed, and only an upstream bound when the source is NVD. Either way, it can be stored on the edge to explain each link.
- **The validation is circular if done naively.** If distro-package links in the KG are taken from Wazuh, comparing them back to Wazuh only measures Wazuh against itself. KG-vs-Wazuh agreement is meaningful only for links the KG computes independently: the NVD-CPE route for Windows/macOS apps and nmap services. For distro packages, either drop that partition from the comparison, or compute the links independently from Debian/Ubuntu OVAL or trackers and compare those. Even on Windows, both sides ultimately rely on NVD, so agreement tests the consistency of CPE matching, not its correctness. That is why the hand-adjudicated sample is still needed.

### Gaps
- The exact string values of `vulnerability.scanner.source` (e.g., "Canonical Security Tracker" vs "National Vulnerability Database") were not confirmed. Inspect a real document with a `size:1` query.
- Wazuh's internal version comparator per package format (dpkg/rpm/Windows/macOS) and how "product translations" map Windows DisplayNames to CVE products in 4.8+ are not documented publicly.
- No source was found quantifying how often NVD ranges disagree with distro fixed versions across a whole distro (a backport false-positive rate).
- The internal field structure of Ubuntu OVAL definitions (package name, fixed-version test) was not retrieved; check the XML directly.
- The Red Hat OVAL/CSAF (VEX) feed details were not researched within budget.

---

## Q4. Graph modelling: concrete CPEs per installed software vs direct Asset-[:HAS_VULNERABILITY]->CVE; Cypher for version comparison

### Takeaway
Use a hybrid model. Store a normalised software-instance node per host with its concrete CPE, linked to the NVD match-criteria CPE node(s) it satisfies via `MATCHES_CPE`. Then materialise `HAS_VULNERABILITY` edges computed in Python, with provenance (source, matched range, confidence). Neo4j cannot natively order dpkg/rpm/semver versions, so range evaluation should happen in Python, not Cypher.

### Cited Findings
- Nagaty et al. already model `CPE-[:VULNERABLE_TO]->CVE` with an `AFFECTS_VERSION` sub-relation "when version detail is available", distinguishing vulnerable from patched builds. Their KG has 101,644 CPE identifiers — local PDF `ref_papers/Construction_of_a_Unified_Knowledge_Graph_for_Cyber_Threat_Intelligence.pdf`, §IV.B.2
- The project's schema keys CPE nodes by the NVD criteria string and stores the ranges on `VULNERABLE_TO`. It also **drops the non-vulnerable "running on" platform CPE from AND configurations** — `/home/panodmanodee/projects/cyber_crime_projects/schema.md` (lines 36, 54–57)
- Tovarňák et al. store CVE configurations and asset configurations as graphs and find vulnerable pairs in one traversal instead of brute force — [IM 2021](https://ics.muni.cz/en/research/publications/1786631)
- VulCPE evaluates AND/OR configuration graphs to filter false positives caused by configuration dependencies, e.g. an application vulnerable only when running on a particular OS — [VulCPE](https://arxiv.org/html/2505.13895v1)
- NVD's match-criteria design: each criteria record (`matchCriteriaId`) resolves to a list of concrete dictionary CPE names, so consumers do not need to compute matches themselves — [NVD CPE Match Feed release note](https://nvd.nist.gov/general/News/CPE-Match-Feed-1-0-Release); [NVD news on /cpematch/](https://nvd.nist.gov/general/news/cpematch-resultsperpage-update)
- `univers` provides per-ecosystem comparators that can evaluate the ranges — [PyPI univers](https://pypi.org/project/univers)

### Inferences
- **Suggested schema** (design proposal, not from a source):
  ```
  (:Host {agent_id})-[:HAS_INSTALLED {source:'syscollector', first_seen, last_seen}]->(:SoftwareInstance {name, vendor, version, format:'deb|rpm|win|macos|pypi', arch})
  (:SoftwareInstance)-[:IDENTIFIED_AS {method:'override|exact|fuzzy|guesser|nmap', score}]->(:ConcreteCPE {cpe23})   // concrete version
  (:ConcreteCPE)-[:MATCHES_CRITERIA]->(:CPE {cpe23})   // NVD criteria node already in the KG (wildcard version)
  (:Host)-[:HAS_VULNERABILITY {via:'nvd_cpe|wazuh|distro_oval', matched_range, fixed_version, confidence, computed_at}]->(:Vulnerability)
  ```
  This keeps the alignment step explicit and auditable, which matches Nagaty's Phase 3 "entity alignment then resolution" (Q5). It keeps the evidence chain Host→Software→CPE→CVE for explaining the rescoring. It also gives fast `HAS_VULNERABILITY` lookups at alert time.
- **Why not compute only in Cypher.** String comparison orders "10.0" before "9.0", and Debian `1:2.3-1ubuntu0.4` or rpm release strings need specialised algorithms. Two Cypher-only workarounds exist:
  - Store a sortable key, e.g. `version_key` as a list of integers padded per segment, computed in Python. Lists compare element-wise in Cypher.
  - Pre-compute in Python and write boolean edges. This is simpler and is the recommended route.
- **Illustrative Cypher once Python has parsed versions into integer lists** (assumes the edge properties `start_incl_key`, etc. were written as lists):
  ```cypher
  MATCH (h:Host)-[:HAS_INSTALLED]->(s:SoftwareInstance)-[:IDENTIFIED_AS]->(:ConcreteCPE)-[:MATCHES_CRITERIA]->(c:CPE)-[r:VULNERABLE_TO]->(v:Vulnerability)
  WHERE (r.start_incl_key IS NULL OR s.version_key >= r.start_incl_key)
    AND (r.start_excl_key IS NULL OR s.version_key >  r.start_excl_key)
    AND (r.end_incl_key   IS NULL OR s.version_key <= r.end_incl_key)
    AND (r.end_excl_key   IS NULL OR s.version_key <  r.end_excl_key)
  MERGE (h)-[:HAS_VULNERABILITY {via:'nvd_cpe'}]->(v)
  ```
  Not verified on the lab Neo4j: the container was not running, so the claim that Cypher compares integer lists element-wise is untested. Run `RETURN [1,10,0,0] > [1,9,0,0], [1,2] < [1,2,0]` to check. Version keys must be zero-padded to a fixed length, otherwise 1.2 sorts below 1.2.0. This approach works only for plain dotted-numeric versions. Anything with letters, epochs or distro revisions should be evaluated in Python with `univers`.
- **Criteria CPE forms.** Criteria nodes whose version field is concrete (not `*`) must be matched by equality on the node (vendor, product, version, update), not via the edge ranges. The matcher has to handle both forms.
- **Project-specific pitfall.** Dropping the "running on" platform CPE from AND configurations will create false positives for configuration-dependent CVEs, e.g. an app CVE that applies only on Windows, or firmware+hardware pairs. Options:
  - Store the configuration tree, e.g. a `(:Configuration {operator:'AND'})` node with `HAS_VULNERABLE_PART`/`REQUIRES_PLATFORM` edges.
  - At minimum, store `platform_cpes` as a list property on `VULNERABLE_TO` and check it against the host OS CPE when computing `HAS_VULNERABILITY`.

  This is exactly the problem Tovarňák and VulCPE address.
- **Alternative via `matchCriteriaId`.** The KG keys CPE nodes by the cpe23 string, so NVD criteria that share a string but carry different ranges collapse onto one node, and their ranges live only on the separate edges. Storing `matchCriteriaId` on each `VULNERABLE_TO` edge would allow using NVD's own `/cpematch/2.0` expansion, where criteria plus range are already resolved to concrete dictionary CPE names, so NVD has done the range evaluation. The limit is that this covers only versions present in the CPE dictionary. Inventory versions absent from it (e.g. Windows build strings, distro revisions) still need evaluation in Python with `univers`.
- Keep the full NVD criteria→concrete-names expansion (`/cpematch/2.0`) only for products present in the lab inventory. Expanding all of NVD is millions of rows and unnecessary.

### Gaps
- No primary source was found on Cypher or APOC functions for semantic/Debian version comparison. Any APOC-based approach was not verified and is not recommended here.
- No published benchmark compares materialised `HAS_VULNERABILITY` edges with on-the-fly traversal in Neo4j for this use case.

---

## Q5. Entity alignment/resolution between asset KG and CTI KG beyond CPE (Nagaty Phase 3)

### Takeaway
Nagaty's Phase 3 is described only at a high level: an NLP pipeline of entity alignment, then entity resolution (NER, word embeddings, string matching on names and descriptions), then merge and iterative validation. For software↔CPE, that maps directly onto: normalise, block candidates, string-similarity (fuzzy) matching, an optional embedding re-rank, and human verification of low-confidence cases. CPE/version logic remains the deterministic core.

### Cited Findings
- Nagaty Phase 3 "adopts an NLP pipeline involving two steps Entity Alignment and Entity Resolution". Similar entities in the two graphs are aligned (e.g., a malicious IP in the threat graph matched to a server in the asset graph), forming a "Product Combination Graph". Entity linking and resolution use NER and word embeddings to disambiguate (e.g., "MITM" ≡ "Man in the Middle Attack"). In practice, they "applied string-matching methods on entity names as well as their descriptions" using text similarity. Validation compares against domain datasets and refines iteratively — local PDF, §IV.C
- Nagaty Phase 1 explicitly names asset data sources as "OCS Inventory or Common Platform Enumeration (CPE)", i.e., an inventory tool plus CPE as the bridge — local PDF, §IV.A
- Høst et al. derive vendor→product→version relations from text and use TuckER embeddings for entity prediction (Hits@10 0.760). This shows KG embeddings can suggest missing product links but with only moderate top-1 accuracy (Hits@1 0.682) — local PDF, Table 3
- Fuzzy string matching with RapidFuzz `fuzz.ratio` and tiered thresholds (≥70% for the highest-confidence tier) is a concrete, implementable inventory→CPE resolution method — [Vajra, arXiv 2412.16607](https://arxiv.org/pdf/2412.16607)
- NLP + fuzzy + Random Forest ranking cut candidate CPEs to about 2 per software name — [Huff et al. 2021](https://dl.acm.org/doi/abs/10.1145/3465481.3470039)
- VulCPE builds a canonical vendor/product dictionary with heuristics (format variation, spelling, substrings, shared products) to resolve NVD naming inconsistency — [VulCPE](https://arxiv.org/html/2505.13895v1)
- Dependency-Track's SUBSET/SUPERSET guard is a cheap rule to reject spurious partial-name alignments — [Dependency-Track docs](https://docs.dependencytrack.org/analysis-types/known-vulnerabilities/)

### Inferences
- **A Phase-3-faithful but practical pipeline** for SoftwareInstance → CPE:
  1. **Normalise.** Apply Vajra rules; map vendor aliases ("Microsoft Corporation" → microsoft); for dpkg/rpm, map the source package name.
  2. **Block.** Take candidates from CPE nodes sharing a token (cpe-guesser index, or a Neo4j full-text index on `vendor`/`product`).
  3. **Score.** Combine RapidFuzz token_set_ratio on vendor and product, a vendor-agreement bonus, a version-exists-in-dictionary bonus, and optionally the cosine similarity of sentence embeddings (e.g. a MiniLM-class model) of "vendor product" strings for re-ranking.
  4. **Decide.** Auto-accept above a high threshold. Queue the middle band for manual review into `overrides/*.csv`. Reject below.
  5. **Validate.** Report precision/recall on a labelled sample and agreement with Wazuh (Q3).

  This mirrors Nagaty's "string-matching on names and descriptions", then embeddings/NER, then iterative validation, with numbers the paper does not provide.
- Beyond software, the other alignment targets in the asset KG are:
  - OS: syscollector `os.name/version` → `cpe:2.3:o:...` (e.g. canonical:ubuntu_linux:22.04).
  - Services/ports: nmap CPE → application CPE.
  - IPs/hostnames in alerts → Host nodes, by exact key.

  These are mostly deterministic joins; fuzzy/embedding resolution is needed mainly for Windows/macOS application names.
- KG embedding link prediction (TuckER-style, as in Høst et al.) is better suited to suggesting candidates than to asserting vulnerability edges, given Hits@1 ≈ 0.68.

### Gaps
- Nagaty et al. give no quantitative results for the Phase 3 alignment step itself, and do not specify the similarity measure or thresholds.
- No 2019–2026 study was found that evaluates embedding-based (sentence-transformer/LLM) alignment of inventory software names to CPEs with reported precision/recall.
