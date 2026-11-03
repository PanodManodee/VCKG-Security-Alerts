# Asset Knowledge Graph Modelling for Linking to a CTI KG (Python + Neo4j + Wazuh lab)

Scope note: these notes cover ontologies and schemas for computer assets and network topology, asset value and criticality modelling, asset-data collection tools, and topology and reachability representation. CPE matching of inventory to CVEs, alert mapping and re-scoring are covered by other researchers. They appear here only where they affect the schema. Pre-2019 work is marked **[foundational]**.

Project anchor: Nagaty et al. (ICCA 2025) is the method being replicated. It is the local PDF `/home/panodmanodee/projects/cyber_crime_projects/ref_papers/Construction_of_a_Unified_Knowledge_Graph_for_Cyber_Threat_Intelligence.pdf`, cited below as [Nagaty, local PDF].

---

## Q1. Which existing ontologies/models represent assets and network topology for security reasoning, what node/edge types do they use, and which is most suitable to adopt or adapt?

### Takeaway
No single standard ontology gives a ready-made, Neo4j-friendly host/service/topology schema. The models that are concrete and implementable are:
- MITRE CyGraph's property graph **[foundational, 2015]**: Machine, Domain, Exploit and Vulnerability nodes, with IN, ROUTES, LAUNCHES, VICTIM, PREPARES and ON edges.
- MulVAL's Datalog fact vocabulary **[foundational, 2005]**: hacl, networkService, vulExists, hasAccount.
- D3FEND's Digital Artifact Ontology, which supplies class names such as Network Node, Software, User Account and Configuration Resource.

UCO/CASE is good for vocabulary alignment (facets for IP, interfaces and connections), but RDF-heavy. Nagaty's own "Computer Asset Graph" is only a product catalogue. For the lab, the best fit is a CyGraph/MulVAL-style property graph whose class names are borrowed from D3FEND.

### Cited Findings
**Nagaty et al. 2025: what the "Computer Asset Graph" actually is**
- It "consolidates product and deployment information around three core concepts: CPE, Weakness, and Platform." It contains 101,644 CPE identifiers, each joined to CVEs by VULNERABLE_TO, with AFFECTS_VERSION as a sub-property "when version detail is available". AFFECTS edges link weaknesses to 54 platform categories such as cloud, mobile and SCADA. — [Nagaty, local PDF, §B.2]
- Asset data sources named are "internal databases, and IT asset management tools that are the sources used for hardware, software and network data, for example OCS Inventory or Common Platform Enumeration (CPE)." — [Nagaty, local PDF, §A]
- Phase 3 integration uses entity alignment. Its example: "an IP address labeled as malicious in the Cyber Threat Graph should match its matching entity in the Computer Asset Graph, which may be a server or network node owned by the organization." — [Nagaty, local PDF, §C]

**MITRE CyGraph (Noel, Harley, Tam, Gyor), "Big-Data Architecture for Cyber Attack Graphs" [foundational, 2015]**
- The Neo4j model has node labels {Exploit, Machine, Vulnerability, Domain} and relationship labels {IN, ON, LAUNCHES, AGAINST, VICTIM}. Machine–domain membership is stored as IN edges "in both directions to support graph traversal". — [Noel et al. 2015](https://csis.gmu.edu/noel/pubs/2015_IEEE_HST.pdf)
- "Protection domains (e.g., a subnet or enclave)" keep the number of intra-domain edges "linear in the number of machines rather than quadratic". The authors note that "we can simply omit protection domains, and explicitly connect machines through exploits" when full intra-domain access does not hold. — [Noel et al. 2015](https://csis.gmu.edu/noel/pubs/2015_IEEE_HST.pdf)
- The model is extended with "network topology (placement of firewalls between domains), attack patterns from CAPEC, vulnerability details from NVD, and intrusion alerts". `IN|ROUTES` edges "define the network topology (domains, machines, and firewall devices)". PREPARES "represents the idea that one exploit prepares for another". — [Noel et al. 2015](https://csis.gmu.edu/noel/pubs/2015_IEEE_HST.pdf)
- A CVE node is "the root of a subtree" with nodes for CVSS score, CWE and references. — [Noel et al. 2015](https://csis.gmu.edu/noel/pubs/2015_IEEE_HST.pdf)
- CyGraph layers: "network infrastructure, cyber defensive posture and threats, mission dependencies". Data is normalised in MongoDB, then loaded into Neo4j. Model extension is "simply the creation of additional nodes, relationships and properties". Mission dependencies come from MITRE's Crown Jewels Analysis. — [Neo4j blog on CyGraph](https://neo4j.com/blog/cygraph-cybersecurity-situational-awareness/) (vendor page, secondary)

**MulVAL (Ou, Govindavajhala, Appel, USENIX Security 2005) [foundational]**
- Network: `hacl(Source, Destination, Protocol, DestPort)`, e.g. `hacl(internet, webServer, TCP, 80)`, an abstract host access-control list.
- Host configuration:
  - `networkService(Host, Program, Protocol, Port, Priv)`, e.g. `networkService(webServer, httpd, TCP, 80, apache)`. It is called `networkServiceInfo/5` in the appendix trace.
  - `clientProgram(Host, Program, Priv)`, `setuidProgram(Host, Program, Owner)`, `nfsExport` and `nfsMountTable`.
- Vulnerabilities: `vulExists(Host, VulID, Program)` and `vulProperty(VulID, Range, Consequence)`.
- Principals, data and policy: `hasAccount(Principal, Host, Account)`, `dataBind(Data, Host, Path)`, `malicious(Attacker)` and `allow(...)`.
- Sources: an augmented OVAL scanner, ICAT, a firewall management tool for hacl, and manual administrator input for accounts and data bindings.
- [Ou et al. 2005](https://static.usenix.org/event/sec05/tech/full_papers/ou/ou_html/index.html)

**MITRE D3FEND**
- The Digital Artifact Ontology has high-level classes "Digital Artifact", "Physical Artifact", "System", "Network Node", "Process", "User Account" (Domain/Local User Account), "Software" (with Application: Client Application, Web Application), "File" (Executable File, Configuration File), "Host"/"Server" (e.g. Web Server, Host-based Firewall) and "Network Traffic". It also lists dependency classes "Dependency", "Data Dependency", "System Dependency" and "Service Dependency", and hardware such as "Network Interface Card". — [D3FEND DAO](https://d3fend.mitre.org/dao/)
- The defensive technique Asset Inventory (D3-AI) has subtechniques Data Inventory, Network Node Inventory, Hardware Component Inventory, Software Inventory, Asset Vulnerability Enumeration, Container Image Analysis and Configuration Inventory. Its relations are `inventories` → Database, Network Node, Document File, Configuration Resource, Hardware Device, Software, plus `evaluates` → Software. — [D3FEND Asset Inventory](https://d3fend.mitre.org/technique/d3f:AssetInventory/)

**UCO / CASE**
- UCO observable facets include:
  - `IPAddressFacet`, with addressValue.
  - `NetworkInterfaceFacet`, with ip, macAddress, ipGateway and dhcpServer.
  - `NetworkConnectionFacet`, with src, dst, protocols, sourcePort, destinationPort, startTime, endTime and isActive.
  - [UCO IPAddressFacet](https://w3id.org/lmodel/uco-observable/IPAddressFacet); [UCO NetworkInterfaceFacet](https://w3id.org/lmodel/uco-observable/NetworkInterfaceFacet); [UCO NetworkConnectionFacet](https://w3id.org/lmodel/uco-master/NetworkConnectionFacet)
- Syed et al. built UCO (2016) "to support information integration and cyber situational awareness", mapped to other cybersecurity ontologies and Linked Open Data. **[foundational]** — [UCO paper](https://mdsoar.org/items/698dfefa-b9fe-495b-b03e-6d6b925e1984/full)

**SEPSES, STUCCO and other ontologies**
- SEPSES CSKG (Kiesling et al., ISWC 2019) integrates CAPEC, CPE, CVE, CVSS and CWE as RDF with a SPARQL endpoint. Its use cases show it "can be easily linked to locally available information" for vulnerability assessment and intrusion detection. I found no asset-ontology component. — [SEPSES KG (WU)](https://research.wu.ac.at/en/publications/the-sepses-knowledge-graph-an-integrated-resource-for-cybersecuri-4/); [SEPSES project](https://sepses.ifs.tuwien.ac.at/?p=29)
- STUCCO ("Situation and Threat Understanding by Correlating Contextual Observations", Iannacone et al. 2015) is described as an ontology on top of a KG database integrating 13 structured sources. **[foundational]** — [CTI ontology survey, arXiv 2103.03530](https://arxiv.org/pdf/2103.03530)
- One surveyed knowledge base uses three ontologies (assets, vulnerability, attack), with software and OS as asset subclasses and each vulnerability tied to a CVE ID. Another domain ontology uses five core concepts: asset, vulnerability, attacker, attack and attack medium. — [Encyclopedia.pub summary of KG application scenarios](https://encyclopedia.pub/entry/25890) (secondary)
- Cybersecurity Ontology Network (CON), from the Siemens Energy group, is an OWL2 ontology built on the CycloneDX SBOM spec, covering software components, libraries and vulnerabilities. It is used in "A comprehensive view of software vulnerability risks through enterprise knowledge graphs" (Egaña Aranguren et al., Computers & Security, DOI 10.1016/j.cose.2025.104815). — [CEUR-WS OK4I paper](https://ceur-ws.org/Vol-3882/ok4i-4.pdf); [ScienceDirect record](https://www.sciencedirect.com/science/article/pii/S0167404825005048)

### Inferences
- Nagaty's "Computer Asset Graph" has no **instance layer**: no hosts, IPs, services, subnets or values. The thesis's Asset KG therefore has to add an instance layer and attach it to the existing CTI KG at two points:
  - `(:Software)-[:MATCHES_CPE {method, confidence}]->(:CPE)`. This is a schema slot only; how the matching is done belongs to the CPE-matching researcher.
  - `(:Host)-[:HAS_PLATFORM]->(:Platform)`, using the same ATT&CK platform names already on `Technique-[:AFFECTS]->Platform` (e.g. "Linux", "Windows", "Network").

  With these two edges, Host → Software → CPE → Vulnerability → Weakness → AttackPattern → Technique becomes traversable.
- What to adopt, model by model:
  - **CyGraph**: the overall pattern (property graph, Domain/zone abstraction, ROUTES via firewall nodes, Alert -[:AGAINST]-> Vulnerability -[:ON]-> Machine).
  - **MulVAL**: the fact vocabulary as the checklist of what the graph must encode for attack-path reasoning (hacl, networkService, vulExists, hasAccount).
  - **D3FEND**: class names, to make the schema defensible in the thesis (Network Node, Software, User Account, Configuration Resource, Service Dependency).
  - **UCO/CASE**: map property names to it only if RDF export is wanted.
- Proposed lab schema. This is my synthesis, not taken from any single paper:
  - Nodes:
    - `Asset`/`Host` {hostname, wazuh_agent_id, os_name, os_version, role, zone, cr, ir, ar, criticality}
    - `Software` {name, version, vendor, format}
    - `Service` {name, protocol, port, process, user}
    - `Interface` {name, mac}
    - `IPAddress` {address}
    - `Subnet` {cidr}
    - `Zone` {name, trust_level}
    - `FirewallRule` {src, dst, proto, dport, action}
    - `Router` or `Firewall`
    - `UserAccount`
    - `BusinessFunction`/`Mission`
    - `Owner`/`Team`
  - Edges:
    - `Host-[:RUNS]->Software`
    - `Host-[:EXPOSES]->Service`, with `Service-[:PROVIDED_BY]->Software`
    - `Host-[:HAS_INTERFACE]->Interface-[:HAS_IP]->IPAddress-[:IN_SUBNET]->Subnet-[:IN_ZONE]->Zone`
    - `Router-[:ROUTES]->Subnet`
    - `Firewall-[:HAS_RULE]->FirewallRule`
    - derived `Host-[:CAN_REACH {proto, port}]->Service|Host`
    - `Host-[:DEPENDS_ON]->Host|Service`
    - `Host-[:SUPPORTS]->BusinessFunction`
    - `UserAccount-[:HAS_ACCOUNT_ON]->Host`
    - `Host-[:HAS_PLATFORM]->Platform`
    - `Software-[:MATCHES_CPE]->CPE`
- Edge names such as HOSTS, RUNS, CONNECTS_TO, EXPOSES_PORT, HAS_ROLE and DEPENDS_ON are not standardised across sources. Each paper invents its own: CyGraph uses IN/ROUTES, Salayma uses CONNECTS_TO/REACHES/HAS, Neo4j uses DEPENDS_UPON. The thesis should fix its own vocabulary and cite the source each one is adapted from.

### Gaps
- STUCCO's actual class and relation list was not retrieved. Only a survey mention was found, and the stucco.github.io schema was not fetched.
- UCO `DeviceFacet` fields were not confirmed from the schema page.
- D3FEND relations linking offensive ATT&CK techniques to artifacts (e.g. names like "may-access") were not shown on the pages fetched. Only `inventories`, `evaluates` and `analyzes` were confirmed. The D3FEND pages call ATT&CK mappings for Asset Inventory "inferred, experimental".
- The full text of the Siemens Energy C&S paper was not accessible (403). Only the abstract and the CON conference paper were seen.

---

## Q2. How have papers (2019–2026) built asset or "infrastructure" knowledge graphs and linked them to vulnerability KGs? Concrete schemas.

### Takeaway
Concrete published host-level asset KG schemas are surprisingly rare. Most 2019–2026 cybersecurity KG work is vulnerability-centric (CVE/CWE/CAPEC/ATT&CK) without hosts. The usable concrete examples are:
- Salayma 2023/2024: Neo4j topology, reachability and attack graph with explicit Cypher.
- BRIDG-ICS 2025: an ICS asset ontology linked through CPE to CVE→CWE→CAPEC→ATT&CK, with risk-weighted communication edges.
- The Neo4j "Graphs for Cybersecurity" white paper: an infrastructure digital twin with DEPENDS_UPON, FIREWALL_INGRESS and POSSIBLE_ATTACK.
- CyGraph **[foundational]**.

The asset-to-vulnerability link is almost always product/CPE-based.

### Cited Findings
**Salayma, "Threat Modelling in IoT Environment Using Dynamic Attack Graphs" (arXiv 2310.01689v2, Feb 2024; later Frontiers in IoT 2024, per search summary, unverified)**
- Graph G_N = {V, E, A, C}. Nodes are devices (end devices V_e and network devices V_n such as routers and switches), vulnerabilities V_v "that may exist in devices' software services", and firewall rules V_r "implemented in the routers". — [Salayma 2024](https://arxiv.org/pdf/2310.01689)
- Edges:
  - physical point-to-point links (`CONNECTS_TO`, with attribute `via` = TCP/IP or Bluetooth; also `CONNECTS_VIA_TCP` and `CONNECTS_VIA_UDP` variants)
  - device→vulnerability (`HAS`)
  - router→rule (`ALLOWS` and `DENIES`)
  - [Salayma 2024](https://arxiv.org/pdf/2310.01689)
- Device attributes: {name, subnet, floor, accessibility, privilege}, where accessibility is a list of protocols/services the device can use to initiate connections. Vulnerability attributes: {preConditions, postConditions}. Categories are implemented as multiple Neo4j labels (e.g. `ClinicTopology:EndDevice`, `ClinicTopology:Router`). — [Salayma 2024](https://arxiv.org/pdf/2310.01689)
- Firewall rule node example: `MERGE(f2:ClinicTopology:Firewall{name:'Rule2', source: s1.name, destination:'Database', srcPort:'any', dstPort:'any', protocol:'TCP'})` then `MERGE(r2)-[:DENIES]->(f2)`. — [Salayma 2024](https://arxiv.org/pdf/2310.01689)
- Attack-graph generation runs in three steps:
  1. A `Condition` node is created for the attacker's privilege.
  2. For `(n)-[:REACHES]->(m)-[:HAS]->(v:Vulnerability)`, the device accessibility list is matched against `v.preConditions`.
  3. `Condition`, `Exploit` and post-condition nodes are created with `(cond)-[:EXPLOITS]->(exploit)-[:LEADS]->(postcond)`.

  [Salayma 2024](https://arxiv.org/pdf/2310.01689)
- The paper argues that prior Neo4j attack-graph work did not make clear how firewall rules affect reachability between hosts and services. — [Salayma 2024](https://arxiv.org/pdf/2310.01689)

**BRIDG-ICS (Nandiya, Mohsin, Ibrahim, Sarker, Janicke; arXiv 2512.12112, Dec 2025)**
- Five linked sub-ontologies: ICS, CVE, CWE, CAPEC and ATT&CK. — [BRIDG-ICS](https://arxiv.org/html/2512.12112v1)
- ICS layer nodes:
  - Product (vendor device)
  - Asset (ATT&CK-for-ICS category such as PLC, HMI, Historian), with I5_Asset mapping Product→Asset
  - Software, Component, Protocol, Zone, Account, ProcessVariable, Observation

  The Vulnerability node merges EPSS, KEV, CPE metadata and NVD vendor statements. — [BRIDG-ICS](https://arxiv.org/html/2512.12112v1)
- Edges:
  - `COMMUNICATES_WITH` (observed dataflow), carrying riskWeight, pExploit and attackCost
  - `CONTROLLED_COMMUNICATES_WITH` (links under SP 800-53 / IEC 62443 controls)
  - `HAS_POSSIBLE_COMMUNICATION` (inferred by FastRP + KNN, top 5 per product)
  - `HAS_POSSIBLE_CWE`, `HAS_POSSIBLE_TECHNIQUE` and `SUGGESTED_TACTIC` (inferred by CySecBERT / SecRoBERTa)

  [BRIDG-ICS](https://arxiv.org/html/2512.12112v1)
- Products are linked to CVEs through ICSA product names mapped to CPE. Adversary behaviour is routed CVE→CWE→CAPEC→ATT&CK rather than directly. Asset metadata comes from a Purdue-model (ISA-95) testbed. — [BRIDG-ICS](https://arxiv.org/html/2512.12112v1)

**Neo4j "Graphs for Cybersecurity" white paper (Voutila, Bello, Jana, Cameron; practitioner guide, year not stated)**
- The "digital footprint" to model is:
  - which systems connect to which
  - which are open to the Internet
  - users and groups, and group permissions
  - policies and the systems they apply to
  - crown jewels

  [Neo4j white paper](https://go.neo4j.com/rs/710-RRC-335/images/Neo4j-Graphs-for-Cybersecurity-Whitepaper.pdf)
- Advice: "Give special labels or properties to nodes for valuable resources" and add "relationships that mark critical access paths (our sample graph includes relationships such as FIREWALL_INGRESS)". Nessus or Nmap is suggested if no configuration-management tool exists. — [Neo4j white paper](https://go.neo4j.com/rs/710-RRC-335/images/Neo4j-Graphs-for-Cybersecurity-Whitepaper.pdf)
- Example labels and edges in its Cypher: `User`, `SecurityGroup`, `IN_GROUP`, `InstalledSoftware`, `Policy`, `ALLOWED_BY_POLICY`, `MfaPolicy`, `DataStore`-`HAS`->`Backup`, `ExternalFacingNode`, `System`, `DEPENDS_UPON`, `Team`, `SUPPORTED_BY`, `CONNECTED_TO_SYSTEM` and `POSSIBLE_ATTACK`. — [Neo4j white paper](https://go.neo4j.com/rs/710-RRC-335/images/Neo4j-Graphs-for-Cybersecurity-Whitepaper.pdf)
- Points to Cartography (Lyft, Neo4j-based infrastructure graph) and GraphKer (loads CVE/CWE/CAPEC into Neo4j). — [Neo4j white paper](https://go.neo4j.com/rs/710-RRC-335/images/Neo4j-Graphs-for-Cybersecurity-Whitepaper.pdf)

**Other 2022–2026 work**
- Sadlek, Čeleda, Tovarňák (arXiv 2206.10272, 2022) build attack graphs whose inputs are network topology, hosts, services and CVE IDs. Techniques are chained by the "violated security properties" of assets, with asset type determining the potential security properties (CIA/STRIDE). — [Sadlek et al. 2022](https://arxiv.org/pdf/2206.10272)
- An ICS attack-graph generator (arXiv 2603.24888, 2026) parses a network description into a directed connectivity graph, matches assets to CVEs, and converts each CVE into pre/post-conditions. Unmatched CVEs are "conservatively excluded". — [arXiv 2603.24888](https://arxiv.org/pdf/2603.24888) (seen via search summary only)
- CVE-TTP KG (arXiv 2606.31557, 2026) is a Neo4j KG linking CVEs to ATT&CK. It is vulnerability-centric with no topology or hosts. — [CVE-TTP KG](https://arxiv.org/abs/2606.31557) (search summary only)
- Cartography models cloud assets in Neo4j, e.g. `(EC2Instance)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(EC2SecurityGroup)`. Third-party sources conflict on rule-node naming (`IpRule` vs `IpPermissionInbound`/`IpRange`). — [terraform-aws-cartography-demo](https://github.com/kmcquade/terraform-aws-cartography-demo)

### Inferences
- The common linking pattern across BRIDG-ICS, CyGraph and Nagaty is **asset → product identity (CPE) → CVE → CWE/CAPEC → ATT&CK**. For this thesis, the asset layer only needs a clean `Software` node with vendor/product/version and an edge slot to `CPE`. The rest of the chain already exists in the CTI KG.
- The second link is **Host → Platform**, which lets ATT&CK techniques that have no CVE (e.g. Atomic Red Team tests of T1059 etc.) still reach hosts. Nagaty already has `Technique-[:AFFECTS]->Platform`.
- Salayma's design (derived `REACHES` + `Condition`/`Exploit` nodes with pre/post-conditions) is the most directly reusable Cypher recipe for a small lab. CyGraph's Domain abstraction is the better choice once there are more than a handful of hosts per subnet.
- Storing provenance on inferred edges is good practice to copy (BRIDG-ICS separates `HAS_POSSIBLE_*` inferred edges from observed ones). Use e.g. `{source:'wazuh', observed_at, confidence}`.

### Gaps
- No paper building an asset KG from **Wazuh syscollector** data in Neo4j was found in limited searching (two queries). Confirm with a Google Scholar/arXiv search before claiming novelty in the thesis.
- Full texts of arXiv 2603.24888 and 2606.31557 were not read. Their descriptions come from search summaries.
- Exact Cartography relationship names for firewall rules could not be confirmed from official docs.

---

## Q3. How is asset value/criticality modelled?

### Takeaway
There are four families:
1. **Per-asset CIA requirement levels**: FIPS 199 LOW/MODERATE/HIGH per C/I/A with a high-water mark, and CVSS CR/IR/AR (H/M/L).
2. **Business/mission tiers from workshops**: MITRE Crown Jewels Analysis, via mission → task → function → asset decomposition.
3. **Dependency-propagated criticality**: Jakobson Impact Dependency Graph with operational capacity in [0,1] and AND/OR propagation; Neo4j `DEPENDS_UPON*`.
4. **Graph-centrality or PageRank-style ranking**: AssetRank, betweenness.

For a lab, the cleanest choice is to store per-host CR/IR/AR (H/M/L) derived from a FIPS 199-style categorisation, plus an optional propagated score. **Note:** CVSS v3.1 and v4.0 treat "Not Defined" differently.

### Cited Findings
**FIPS 199 (Feb 2004) [foundational, still current]**
- Impact levels per security objective: LOW = "limited adverse effect", MODERATE = "serious adverse effect", HIGH = "severe or catastrophic adverse effect" on operations, assets or individuals. — [NIST FIPS 199](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.199.pdf)
- Notation: `SC information type = {(confidentiality, impact), (integrity, impact), (availability, impact)}`. For an information system, each objective takes "the highest values (i.e., high water mark)" among its information types. — [NIST FIPS 199](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.199.pdf)

**CVSS v3.1 environmental metrics**
- `MISS = Min[1 − (1 − CR×MC)(1 − IR×MI)(1 − AR×MA), 0.915]`.
- ModifiedImpact = 6.42×MISS if scope is Unchanged, otherwise 7.52×(MISS−0.029) − 3.25×(MISS×0.9731−0.02)^13.
- Security Requirement values: **H = 1.5, M = 1.0, L = 0.5, Not Defined = 1.0** (same as Medium).
- [FIRST CVSS v3.1 spec](https://www.first.org/cvss/v3.1/specification-document)

**CVSS v4.0 environmental metrics**
- CR/IR/AR "enable the consumer to customize the assessment depending on the importance of the affected IT asset". The levels are:
  - H: "catastrophic adverse effect"
  - M: "serious"
  - L: "limited"
  - **Not Defined defaults to High** (worst case)

  [FIRST CVSS v4.0 spec](https://www.first.org/cvss/v4.0/specification-document)
- In v4.0, the requirements enter scoring through EQ6. Level 0 applies when a High requirement pairs with a High impact on the same property (e.g. CR:H with VC:H); otherwise Level 1 applies. EQ6 is evaluated jointly with EQ3. — [FIRST CVSS v4.0 spec](https://www.first.org/cvss/v4.0/specification-document)
- Modified Base metrics (MAV, MPR, MVC, MSI, MSA, and so on) can represent mitigations or compensating controls. MSI:S / MSA:S (Safety) applies when exploitation can impact human safety. A score using all three groups is labelled CVSS-BTE. — [FIRST CVSS v4.0 spec](https://www.first.org/cvss/v4.0/specification-document)

**MITRE Crown Jewels Analysis (CJA)**
- CJA is a mission-decomposition process to identify the cyber assets most critical to a mission. You read down the dependency map to find crown jewels and read up for impact analysis. The decomposition runs objectives → tasks → functions → assets. — [MITRE CJA](https://www.mitre.org/our-impact/intellectual-property/crown-jewels-analysis); [MITRE CJA for ICS](https://www.mitre.org/sites/default/files/2023-02/PR-23-0249-Crown-Jewels-Analysis-for-Industrial-Control-Systems.pdf)
- Scoring uses expert workshops with AHP, QFD and FMEA to produce a Mission Impact Analysis. A crown jewel is a device "whose failure, or failure to perform as intended, can cause mission failure". — [MITRE CJA for ICS (2023)](https://www.mitre.org/sites/default/files/2023-01/PR-22-2824-Crown-Jewels-for-Industrial-Control-Systems.pdf) (via search summary)

**Dependency-propagated criticality**
- Jakobson (CyCon 2013) **[foundational]**:
  - The "cyber terrain" has hardware, software and service sub-terrains with intra- and inter-dependencies ("a HW sub-terrain component may 'house' SW sub-terrain components and a SW sub-terrain component may enable some services").
  - Operational capacity (OC) is in [0,1], where 1 means fully operational and 0 totally compromised. Directly hit assets lose OC permanently. Indirectly impacted assets lose OC via dependencies. Missions use AND/OR nodes.
  - [Jakobson 2013](https://www.ccdcoe.org/uploads/2018/10/3_d1r2s1_jakobson.pdf)
- Neo4j white paper impact query: `MATCH (compromisedSystem)<-[:DEPENDS_UPON*]-(system:System) RETURN system`, extended with `<-[:SUPPORTED_BY]-(team:Team)` to find responsible teams. — [Neo4j white paper](https://go.neo4j.com/rs/710-RRC-335/images/Neo4j-Graphs-for-Cybersecurity-Whitepaper.pdf)
- AssetRank (Sawilla & Ou, ESORICS 2008) **[foundational]** generalises PageRank to dependency attack graphs, respecting AND/OR vertex semantics. It can be personalised toward protecting specific critical assets. — [Sawilla & Ou 2008](https://cse.usf.edu/~xou/publications/esorics08.pdf)
- A USPTO patent describes asset criticality on a 1–5 scale (default 1 if undefined), propagated from an IT service to its network assets and combined with threat and vulnerability severity into a 1–100 score. — [US 8201257](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/8201257); [US 11677773](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11677773) (patents, via search summary)

**Graph and risk formulas from recent work**
- BRIDG-ICS (2025):
  - `pExploit(u,v) = EPSS × [1 − controlStrength(u,v)]`, with `controlStrength = a·c·e·h`
  - multiple CVEs on one link: `1 − ∏(1 − e_i)`
  - `riskWeight(u,v) = pExploit(u,v) × criticality(v) / 10`
  - path likelihood `p(P) = ∏ pExploit`
  - `Exposure(v) = Σ incoming riskWeight`
  - edges with riskWeight < 0.05 are pruned

  [BRIDG-ICS](https://arxiv.org/html/2512.12112v1)
- Jiang et al., vulnerability-prioritisation survey (arXiv 2502.11070, Feb 2025):
  - Generic `RS_i = α·I_i + β·E_i + γ·C_i`, with contextual term `C_i = L_i + D_i` (criticality level + system dependence).
  - Asset-context metrics: Criticality Level, Operational Disruption, Business Impact, Network Exposure, Host Exposure, Compliance Impact.
  - Contextual metrics appear in 48 studies (graph-based 21, rule-based 17, ML 8, multi-objective 5, statistical 3).

  [Jiang et al. 2025](https://arxiv.org/html/2502.11070v1)
- Secondary only, cited via Jiang et al. 2025 and **not read by me**:
  - Mahmood 2021: betweenness/closeness centrality finds some low-CVSS flaws critical.
  - Cheng et al. 2023: modified PageRank over severity, exposure and asset criticality in a KG.
  - Wang et al. 2020b: heterogeneous information network plus PageRank-style ranking.
  - Hu et al. 2023: asset value score.
  - Yadav et al. 2022: functional and topological dependency scores.
  - Keskin et al. 2021: operability-loss propagation to business functions.
  - Walkowski et al. 2021: CVSS environmental extensions with asset value.
  - Farris et al. 2018 (VULCON): mission-criticality of hosts.

  [Jiang et al. 2025](https://arxiv.org/html/2502.11070v1)

### Inferences
- **Schema implication, important for the re-scoring researcher.** Store explicit `cr`, `ir` and `ar` ∈ {H, M, L} on each `Host` (or on the `BusinessFunction` it supports, inherited by high-water mark). Never leave them null. A null maps to Medium under v3.1 (no change) but to High under v4.0 (worst case), so the same graph would silently give different environmental scores depending on the CVSS version used.
- A practical lab pipeline, which is my synthesis:
  1. Assign each `BusinessFunction`/data store a FIPS 199-style triple (C, I, A) ∈ {L, M, H}.
  2. For each `Host-[:SUPPORTS|STORES]->BusinessFunction`, set host CR/IR/AR to the high-water mark over its functions.
  3. Optionally propagate along `DEPENDS_ON`. A host that a HIGH-availability host depends on inherits AR = H, following the Jakobson and patent "service → asset" propagation.
  4. Compute an optional numeric `criticality` (e.g. map L/M/H to 0.5/1.0/1.5 as in v3.1), plus centrality (betweenness on the reachability graph via Neo4j GDS) as a separate `exposure` property.

  Keep value (business) and exposure (topological) as separate properties so the classifier can weigh them.
- The lab outline's "priority classification" maps naturally onto a small ordinal tier (e.g. crown-jewel / high / medium / low). CJA provides the justification method (workshop / mission decomposition) rather than a numeric scale.

### Gaps
- MITRE CJA publishes no numeric criticality scale that I could find. Only the method (AHP/QFD/FMEA workshops) is documented.
- BRIDG-ICS uses `criticality(v)` but does not define how it is computed, and the definitions of a, c, e and h are in an appendix I did not read.
- I did not read the original formulas of AssetRank, Cheng 2023 or Keskin 2021. Only abstracts and survey descriptions were seen.
- No SP 800-60 content was retrieved. SP 800-60 maps information types to provisional FIPS 199 levels, but this was not verified here.

---

## Q4. What tools can automatically collect asset data for a lab, and what fields do they provide?

### Takeaway
**Wazuh syscollector** alone covers most of the outline's asset needs (OS, hardware, packages, ports, processes, interfaces, addresses, routes/gateways, users, groups, services, hotfixes). It is already in the lab, and its results are stored in per-agent DB tables and in `wazuh-states-inventory-*` indexer indices. Wazuh gives host-local views only, so it should be complemented with:
- **nmap**, for the network-side view (what is actually reachable from where, e.g. from the Kali node)
- a hand-written or **NetBox** source of truth for topology, firewall rules, zones and asset value

osquery and OCS Inventory are alternatives with overlapping fields.

### Cited Findings
**Wazuh syscollector**
- Categories with their server DB tables and indexer indices:

  | Category | Server DB table | Indexer index |
  |---|---|---|
  | Hardware | `sys_hwinfo` | `wazuh-states-inventory-hardware-*` |
  | OS | `sys_osinfo` | `wazuh-states-inventory-system-*` |
  | Packages | `sys_programs` | `…-packages-*` |
  | Network interfaces | `sys_netiface` | `…-interfaces-*` |
  | Network addresses | `sys_netaddr` | `…-networks-*` |
  | Network protocols | `sys_netproto` | `…-protocols-*` |
  | Ports | `sys_ports` | `…-ports-*` |
  | Processes | `sys_processes` | `…-processes-*` |
  | Hotfixes | `sys_hotfixes` | `…-hotfixes-*` |
  | Users | `sys_users` | `…-users-*` |
  | Groups | `sys_groups` | `…-groups-*` |
  | Services | `sys_services` | `…-services-*` |

  [Wazuh inventory fields](https://documentation.wazuh.com/current/user-manual/capabilities/system-inventory/available-inventory-fields.html)
- Fields per category:
  - **OS**: hostname, architecture, os_name, os_version, os_codename, os_major/minor/patch/build, os_platform, sysname, release
  - **Hardware**: board_serial, cpu_name, cpu_cores, cpu_mhz, ram_total/free/usage
  - **Packages**: format, name, version, vendor, architecture, source, description, location, install_time
  - **Interfaces**: name, adapter, type, state, mtu, mac, tx/rx counters
  - **Addresses**: iface, proto, address, netmask, broadcast, dhcp, metric
  - **Protocols**: iface, type, gateway, dhcp, metric
  - **Ports**: protocol, local_ip, local_port, remote_ip, remote_port, state, PID, process
  - **Processes**: pid, name, ppid, cmd, argvs, euser/ruser, etc.
  - **Users**: user_name, user_id, user_groups, user_shell, user_home, login status, auth failures, etc.
  - **Services**: service_id, service_description, service_enabled, process_executable, process_user_name, etc.

  [Wazuh inventory fields](https://documentation.wazuh.com/current/user-manual/capabilities/system-inventory/available-inventory-fields.html)

**osquery**
- Cross-platform tables: `system_info`, `os_version`, `kernel_info`, `platform_info`, `interface_addresses`, `interface_details`, `routes`, `arp_cache`, `listening_ports`, `process_open_sockets`, `processes`, `users`, `groups`, `user_groups`, `logged_in_users`. — [osquery specs](https://github.com/osquery/osquery/tree/master/specs)
- Platform tables:
  - Linux: `deb_packages`, `rpm_packages`, `apt_sources`, `iptables`, `systemd_units`, `shadow`
  - Windows: `programs`, `patches`, `services`, `windows_firewall_rules`
  - POSIX: `sudoers`

  [osquery specs (GitHub API listing)](https://github.com/osquery/osquery/tree/master/specs)
- `listening_ports` columns: pid, port, protocol, family, address, fd, socket, path (plus net_namespace on Linux). — [osquery listening_ports.table](https://raw.githubusercontent.com/osquery/osquery/master/specs/listening_ports.table)

**OCS Inventory NG** (the tool named by Nagaty)
- The agent collects hardware (BIOS, CPU, memory, video, storage, network, I/O ports), OS, installed software and custom Windows registry entries. Agents push XML over HTTP(S). IpDiscover (reportedly Nmap-based) and SNMP scans inventory devices that cannot run agents. — [Rootshell book review](https://blog.rootshell.be/?p=6679); [NethServer OCS docs](https://docs.nethserver.org/en/v6/ocs.html)
- Sources conflict on the API: a SOAP web service vs a built-in REST API. — [NethServer OCS docs](https://docs.nethserver.org/en/v6/ocs.html) vs [Hostinger OCS page](https://www.hostinger.com/applications/ocs-inventory-ng)

**NetBox** (source of truth for topology and IPAM)
- The IPAddress model has: address (CIDR); VRF; status; role (Loopback, Secondary, Anycast, VIP, VRRP/HSRP/…); assignment to device or VM interfaces or FHRP groups; one primary IP per family per device; `nat_inside` (one-to-one NAT link); dns_name. — [NetBox IPAddress model](https://netboxlabs.com/docs/netbox/models/ipam/ipaddress/)
- Model groups: Circuits, DCIM, IPAM, Virtualization, VPN, Wireless, Extras, Tenancy. — [NetBox models index](https://netboxlabs.com/docs/netbox/models/)

**nmap XML output** (`-oX`)
- Per `host`: `status` {state, reason}, `address` {addr, addrtype}, `hostnames/hostname` {name, type}. — [Nmap XML output](https://nmap.org/book/output-formats-xml-output.html)
- `ports/port` {protocol, portid} with children:
  - `state` {state, reason, reason_ttl}
  - `service` {name, product, version, extrainfo, ostype, method (`table` = nmap-services lookup, `probed` = version detection), conf (1–10)}
  - a `cpe` child (e.g. `cpe:/a:openbsd:openssh:5.3p1`)
  - `script` {id, output}

  `extraports` {state, count} summarises filtered/closed ports. — [Nmap XML output](https://nmap.org/book/output-formats-xml-output.html)
- `os`: `osmatch` {name, accuracy, line}; `osclass` {type, vendor, osfamily, osgen, accuracy} with a `cpe` child (e.g. `cpe:/o:linux:linux_kernel:2.6.39`); and `portused`. — [Nmap XML output](https://nmap.org/book/output-formats-xml-output.html)

**nmap / Nessus and cloud APIs**
- The Neo4j white paper recommends Nessus or Nmap when no config-management tool exists, giving "versions, libraries, ports they use". Cloud inventory APIs (GCP Cloud Asset Inventory, Azure Resource Manager, AWS Organizations) or Cartography are suggested for cloud. — [Neo4j white paper](https://go.neo4j.com/rs/710-RRC-335/images/Neo4j-Graphs-for-Cybersecurity-Whitepaper.pdf)

### Inferences
- Mapping of Wazuh syscollector to the Asset KG. This is my synthesis; keys are chosen for idempotent `MERGE`.

  | Syscollector category (index) | Neo4j element | Merge key / properties |
  |---|---|---|
  | OS (`…-system-*`) | `(:Host)` props + `(:Host)-[:HAS_PLATFORM]->(:Platform)` + `(:Host)-[:RUNS_OS]->(:Software {type:'os'})` | key `wazuh_agent_id`; hostname, os_name, os_version, os_platform, architecture |
  | Hardware (`…-hardware-*`) | `(:Host)` props | cpu_name, cpu_cores, ram_total, board_serial |
  | Packages (`…-packages-*`) | `(:Host)-[:RUNS {install_time}]->(:Software)` | key (name, version, vendor, architecture); `format` (deb/rpm/win) helps CPE matching |
  | Ports (`…-ports-*`), state=listening | `(:Host)-[:EXPOSES]->(:Service {protocol, port, bind_ip})`; `(:Service)-[:PROVIDED_BY]->(:Process/Software)` | key (agent, protocol, local_ip, local_port); join `PID`/`process` with Processes and Packages |
  | Ports, established (remote_ip set) | observed `(:Host)-[:COMMUNICATES_WITH {port, seen_at}]->(:Host/IPAddress)` | evidence for DEPENDS_ON / reachability |
  | Interfaces (`…-interfaces-*`) | `(:Host)-[:HAS_INTERFACE]->(:Interface {name, mac, state})` | key (agent, name) |
  | Addresses (`…-networks-*`) | `(:Interface)-[:HAS_IP]->(:IPAddress)-[:IN_SUBNET]->(:Subnet {cidr})` | subnet CIDR computed from address + netmask in Python (`ipaddress` module) |
  | Protocols (`…-protocols-*`) | `(:Subnet)-[:DEFAULT_GW]->(:IPAddress)` or `(:Host)-[:ROUTES_VIA]->(:Router)` | gateway field |
  | Users / Groups | `(:UserAccount)-[:HAS_ACCOUNT_ON]->(:Host)`, `(:UserAccount)-[:MEMBER_OF]->(:Group)` | MulVAL `hasAccount` equivalent |
  | Services (`…-services-*`) | `(:Host)-[:HAS_SERVICE]->(:SystemService)` | service_id, enabled, process_executable |
  | Hotfixes (Windows) | `(:Host)-[:HAS_PATCH]->(:Hotfix)` | KB id; affects vulnerable-version reasoning |

- The MulVAL equivalence makes the attack-path relevance explicit:
  - `networkService(H, Prog, Proto, Port, Priv)` ≈ Wazuh Ports + Processes (euser gives Priv)
  - `hasAccount` ≈ Wazuh Users
  - `vulExists` ≈ Software→CPE→CVE in the CTI KG
  - `hacl` is **not** available from Wazuh. It must come from firewall configs (iptables via osquery or Wazuh command monitoring, router configs, or a hand-written YAML) or be inferred from nmap scans run from each zone.
- Things no collector gives you, which must be authored by hand (YAML/CSV → Python loader) or kept in NetBox custom fields:
  - asset value / CR-IR-AR
  - business function
  - owner
  - zone / trust level
  - inter-zone firewall policy

  For a small testbed, a single `assets.yaml` is simpler than deploying NetBox.
- nmap `-sV`/`-O` emits CPE strings directly (`service/cpe`, `osclass/cpe`, in the old CPE 2.2 URI form). `Service` and `Host` nodes can therefore carry a second, independently sourced CPE edge, `(:Service)-[:MATCHES_CPE {source:'nmap', conf}]->(:CPE)`, alongside the Wazuh package route. Include `source` on the edge so the two routes can be compared. This is a schema slot only; matching is out of scope.
- Wazuh's agent-local view misses network devices (routers, switches) and the attacker node. Represent these as manually defined nodes. nmap `-sV` output from the Kali node is a good ground truth for "externally exposed" services.

### Gaps
- The Wazuh server REST API `/syscollector/{agent_id}/...` endpoints were not retrieved (the API reference page is JS-rendered). The indexer index names above are confirmed and sufficient for implementation via the indexer/OpenSearch API. The exact REST paths should be verified against the installed Wazuh version.
- Field lists above are from the current docs. Verify the field names against the installed Wazuh version. The docs page lists the `sys_*` tables and `wazuh-states-inventory-*` indices side by side; version history was not checked.
- A browser-extensions category was not confirmed (the fetched page was truncated).
- OCS Inventory DB table names and API type (SOAP vs REST) are unresolved.
- NetBox: only the IPAddress model was confirmed in detail. Device, Interface, Prefix, VLAN, Service and Cable relationships were not fetched.
- osquery columns beyond `listening_ports` were not verified.

---

## Q5. How do you represent network topology/reachability (subnets, firewall rules, routes) in a graph so attack paths can be computed?

### Takeaway
There are two proven Neo4j patterns:
- **CyGraph** (Noel 2015) **[foundational]**: `Machine-[:IN]->Domain` (subnet/enclave), firewalls as nodes linked with `ROUTES`, and `Exploit` nodes with `LAUNCHES`/`VICTIM`/`PREPARES`. Domains keep edge counts linear.
- **Salayma** (2024): `CONNECTS_TO {via}` physical links, `Router-[:ALLOWS|DENIES]->Firewall {source, destination, srcPort, dstPort, protocol}` rule nodes, a **derived** `REACHES` edge materialised by a Cypher query, and then `Condition`/`Exploit` nodes chained with `EXPLOITS`/`LEADS` using vulnerability pre/post-conditions.

In both, reachability is a derived, materialised relation that must be recomputed whenever rules or topology change. Attack paths are then found with variable-length Cypher or GDS shortest-path.

### Cited Findings
- **CyGraph path query:** `MATCH path=(start:Machine{name:'Machine 1.1'})-[r:LAUNCHES|VICTIM|IN*]->(end:Machine{name:'Machine 3.1'}) RETURN path`. Topology-only view: `MATCH path=(start)-[r:IN|ROUTES*]->(end)`. From alerts: `MATCH path=(start:Alert)-[r:ALERT|AGAINST|VICTIM|ON|LAUNCHES*]->(end)`. — [Noel et al. 2015](https://csis.gmu.edu/noel/pubs/2015_IEEE_HST.pdf)
- **CyGraph example network:** an external firewall (Internet → DMZ) and an internal firewall protecting the data centre. One database vulnerability "is blocked (by the internal firewall) from the other domains". The query from alerts recovered a five-step chain: client-side overflow → credential theft → DB login → fingerprinting → SQL injection. — [Noel et al. 2015](https://csis.gmu.edu/noel/pubs/2015_IEEE_HST.pdf)
- **Salayma reachability materialisation:** `MATCH (n:EndDevice), (m:EndDevice) WHERE n.name<>m.name AND (n.subnet=m.subnet OR EXISTS((n)-[:CONNECTS_TO]->(m)) OR EXISTS((n)-[:CONNECTS_TO*{via:'TCP'}]->(m)) AND EXISTS((:Router)-[:ALLOWS]->(:Firewall{source:n.name, destination:m.name}))) MERGE (n)-[:REACHES]->(m)`. The default policy is deny between subnets. — [Salayma 2024](https://arxiv.org/pdf/2310.01689)
- **Salayma attack-graph step:** for `(n)-[:REACHES]->(m)-[:HAS]->(v:Vulnerability)`, if any of `n.accessibility` ∈ `v.preConditions`, create `Condition`, `Exploit` and post-condition nodes linked `EXPLOITS` and `LEADS`. The algorithms also update reachability incrementally when sub-networks join or leave. — [Salayma 2024](https://arxiv.org/pdf/2310.01689)
- **MulVAL** abstracts routers and firewalls into host-to-host `hacl(Src, Dst, Proto, Port)` facts. Reachability is then derived by Datalog rules together with `networkService` and `vulExists`. — [Ou et al. 2005](https://static.usenix.org/event/sec05/tech/full_papers/ou/ou_html/index.html)
- **Neo4j digital twin:** label `ExternalFacingNode`, then run `gds.shortestPath.dijkstra.stream` from each external node to a crown-jewel target and `MERGE` `POSSIBLE_ATTACK` edges along each path. Betweenness centrality on that subgraph ranks choke points. — [Neo4j white paper](https://go.neo4j.com/rs/710-RRC-335/images/Neo4j-Graphs-for-Cybersecurity-Whitepaper.pdf)
- **BRIDG-ICS** puts risk on communication edges (riskWeight, pExploit, attackCost) and computes path likelihood as the product of pExploit along the path. Zones follow the Purdue model. — [BRIDG-ICS](https://arxiv.org/html/2512.12112v1)

### Inferences
- Recommended lab design, synthesised from CyGraph, Salayma and MulVAL:
  1. **Topology layer (authored + Wazuh):**
     - `(:Host)-[:HAS_INTERFACE]->(:Interface)-[:HAS_IP]->(:IPAddress)-[:IN_SUBNET]->(:Subnet)-[:IN_ZONE]->(:Zone)`
     - `(:Router|Firewall)-[:CONNECTS {iface}]->(:Subnet)`
  2. **Policy layer (authored):**
     - `(:Firewall)-[:HAS_RULE {order}]->(:FirewallRule {src_cidr|src_zone, dst_cidr|dst_zone, proto, dport, action:'ALLOW'|'DENY'})`
     - Use zone/CIDR-level rules, as CyGraph's domains do, rather than per-host rules, to keep the graph small.
  3. **Service layer (Wazuh ports):** `(:Host)-[:EXPOSES]->(:Service {proto, port, bind_ip})`. A service bound to 127.0.0.1 is not network-reachable. Filter on `bind_ip`; this is a common error.
  4. **Derived reachability, computed in Python or Cypher and re-run on change:** `(:Host)-[:CAN_REACH {proto, port, via_rule}]->(:Service)`. It exists if the hosts are in the same subnet, or a path of `CONNECTS` exists through firewalls whose first matching rule is ALLOW. Doing first-match rule evaluation in Python is simpler and more correct than pure Cypher.
  5. **Attack layer:** join `CAN_REACH` with `Service-[:PROVIDED_BY]->Software-[:MATCHES_CPE]->CPE-[:VULNERABLE_TO]->Vulnerability` (existing CTI KG). Optionally materialise `(:Host)-[:CAN_EXPLOIT {cve}]->(:Host)` (CyGraph's Exploit/LAUNCHES/VICTIM, collapsed) so `shortestPath`/GDS Dijkstra can run from the attacker node (Kali, as an `Attacker` host in an `External` zone) to crown-jewel hosts.
  6. Use `Technique-[:AFFECTS]->Platform<-[:HAS_PLATFORM]-Host` for ATT&CK techniques without CVEs (e.g. Atomic Red Team credential-access or lateral-movement tests). These techniques' "reach" depends on `CAN_REACH` to management services (SSH/RDP/SMB) plus `HAS_ACCOUNT_ON`, which is MulVAL's `hasAccount` logic.
- Caution on copying Salayma's `REACHES` query as-is: it has the form `A OR B OR C AND D`. In Cypher, AND binds tighter than OR, so the firewall `ALLOWS` check applies only to the multi-hop TCP disjunct. Same-subnet pairs and direct `CONNECTS_TO` pairs skip the firewall check. This was read from the query text quoted above, and it is one more reason to evaluate rules in Python.
- Store edge provenance (`source: 'wazuh'|'nmap'|'manual'|'derived'`, `updated_at`) so derived edges can be wiped and rebuilt (`MATCH ()-[r:CAN_REACH]->() DELETE r`) without touching observed facts.
- Validation idea for the "test and validate the links" stage: compare derived `CAN_REACH` against nmap scans run from each zone (especially from the Kali node). Mismatches indicate missing firewall rules in the model.

### Gaps
- MulVAL's later predicates `attackerLocated`, `attackGoal` and `inCompetent` are widely used in MulVAL inputs but are not defined in the 2005 paper. The current MulVAL repo README returned 404, so their exact signatures were not verified.
- Salayma notes that firewall-rule semantics (bidirectionality, rule ordering) are under-specified in prior Neo4j work, and her own model uses name-level source/destination rather than CIDR/zone. I found no 2019–2026 paper giving a complete, ordered-rule Cypher implementation. First-match evaluation in Python is my recommendation, not a sourced method.
- Routing tables (beyond the default gateway) are not covered by Wazuh syscollector. osquery `routes` covers them, but I found no paper using routes explicitly in a Neo4j reachability model.
