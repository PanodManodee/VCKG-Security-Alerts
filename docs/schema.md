# CTI Knowledge Graph — schema

Replicates the threat layer of Nagaty et al., *Construction of a Unified Knowledge Graph for Cyber
Threat Intelligence* (ICCA 2025, §IV.B), plus the CPE bridge that the asset graph will link to.
The code source of truth is `cti_kg/schema.py`.

```
                         (Group)                          (Tactic)
                            │ USES_TECHNIQUE                  ▲ IMPLEMENTS
                            ▼                                 │
 (AttackPattern) ──USES_TECHNIQUE──▶ (Technique) ──SUBTECHNIQUE_OF──▶ (Technique)
   ▲      │ IS_PARENT                   │  │ MITIGATED_BY ──▶ (Mitigation)
   │      ▼                             │  └ AFFECTS ───────▶ (Platform)
   │ (AttackPattern)                    │
   │ CAUSES_WEAKNESS                    │
 (Weakness) ──EXPLOITED_BY──▶ (Vulnerability) ◀──VULNERABLE_TO── (CPE)
   │  │  │  └ IS_PARENT ──▶ (Weakness)
   │  │  └── MITIGATED_BY ─▶ (Mitigation)
   │  └───── DETECTED_BY ──▶ (DetectionMethod)
   └──────── AFFECTS ──────▶ (Platform)
```

## Nodes

| Label | Key | Source | Notable properties |
|---|---|---|---|
| Weakness | `cwe_id` (CWE-732) | CWE XML | name, abstraction, description, likelihood_of_exploit, consequence_scopes, consequence_impacts |
| Vulnerability | `cve_id` | cvelistV5 + NVD 2.0 feeds | description, published, cvss3_/cvss4_/cvss2_ {score, vector, severity, source}, ssvc_*, kev_date_added |
| AttackPattern | `capec_id` (CAPEC-1) | CAPEC XML | name, abstraction, likelihood_of_attack, typical_severity |
| Technique | `attack_id` (T1574.010) | ATT&CK enterprise | name, is_subtechnique, x_mitre_platforms |
| Tactic | `attack_id` (TA0005) | ATT&CK | name, shortname |
| Group | `attack_id` (G0016) | ATT&CK | name, aliases |
| Mitigation | `mit_id` | CWE (MIT-n or CWE-MIT-&lt;hash&gt;) / ATT&CK (M1047) | name, description, origin |
| DetectionMethod | `name` | CWE | |
| Platform | `name` | CWE Applicable_Platforms, ATT&CK platforms | kind |
| CPE | `cpe23` | NVD configurations (fallback: CNA `affected.cpes`) | part, vendor, product, version, target_sw, ... |

Every node and edge has `sources` (e.g. `cwe-4.20`, `capec-3.9`, `attack-19.2`, `nvd`, `cvelistV5`,
`cna`, `cisa-adp`, `manual`). Nodes folded together by alignment have `merged_from`.

## Edge direction rules

| Edge | Direction | Origin |
|---|---|---|
| EXPLOITED_BY | Weakness → Vulnerability | NVD weaknesses, CNA/ADP problemTypes, CWE Observed_Examples |
| CAUSES_WEAKNESS | Weakness → AttackPattern | CWE Related_Attack_Patterns ∪ CAPEC Related_Weaknesses |
| USES_TECHNIQUE | AttackPattern → Technique, Group → Technique | CAPEC taxonomy mappings (revoked ids remapped), ATT&CK `uses` |
| IMPLEMENTS | Technique → Tactic | ATT&CK kill-chain phases |
| SUBTECHNIQUE_OF | sub-technique → parent | ATT&CK |
| MITIGATED_BY | Weakness → Mitigation, Technique → Mitigation | CWE Potential_Mitigations, ATT&CK `mitigates` |
| DETECTED_BY | Weakness → DetectionMethod | CWE Detection_Methods (`effectiveness` on edge) |
| AFFECTS | Weakness → Platform, Technique → Platform | CWE Applicable_Platforms (`prevalence` on edge), ATT&CK platforms |
| IS_PARENT | parent → child (Weakness, AttackPattern) | CWE / CAPEC ChildOf |
| VULNERABLE_TO | CPE → Vulnerability | NVD `vulnerable: true` cpeMatch. The paper's AFFECTS_VERSION is the list `version_ranges` on the edge, one interval per cpeMatch, e.g. `["[12.0,12.20)", "[15.0,15.8)"]`: `[`/`]` include a bound, `(`/`)` exclude it, an empty side is open, and `(,)` means all versions. It is set only for wildcard CPEs (`version = *`) or bounded matches; a CPE with a concrete version needs no range. |

Simplification: NVD configurations that combine an application CPE with a non-vulnerable
"running on" platform CPE (AND nodes) only keep the vulnerable CPE.

## Manual adjustments

`overrides/*.csv` are applied after automatic parsing and alignment; see the header of each file.
Automatic merges are listed in `data/processed/alignment_report.csv` for review.

## Asset graph and bridges (`asset_kg`)

The asset graph lives in the same Neo4j database. It is loaded from `lab/*.csv`, which describe the
Docker lab in `lab_env/`. Every node and edge it writes has `sources = ['asset_kg']`.
It never creates or edits CTI nodes: `CPE`, `Vulnerability` and `Platform` are only matched.

| Node | Key | Example |
|---|---|---|
| Zone | name | DMZ, Internet |
| Asset | hostname | Jenkins (`ip`, `os`, `role`, `cr`/`ir`/`ar`, `internet_exposed`) |
| Service | id | Jenkins:8080/tcp |
| Software | id | jenkins 2.441 (`cpe_vendor`, `cpe_product`) |

| Edge | Direction | Origin |
|---|---|---|
| IN_ZONE | Asset → Zone | assets.csv |
| ALLOWED_TO_REACH | Zone → Zone | zone_edges.csv (= firewall rules) |
| CONNECTS_TO | Asset → Asset | asset_edges.csv (application flows) |
| RUNS | Asset → Service | services.csv |
| IMPLEMENTED_BY | Service → Software | services.csv |
| **IDENTIFIED_AS** | Software → CPE | `link`: exact vendor:product, version inside the CPE range |
| **HAS_VULNERABILITY** | Software → Vulnerability | `link`. Upstream builds: CVEs whose NVD range covers the version (`via: nvd`). Distro packages (`distro_package` in services.csv): CVEs from the distribution's security data in OSV, so backported fixes count (`via: osv:Debian:12`, plus `fixed_version`, which is empty when no fix exists) |
| **RUNS_ON** | Asset → Platform | `link`: OS family via `lab/os_platforms.csv` (Debian → Linux) |
| **CAN_REACH** | Asset → Service, Zone → Service | `link`: same zone, or zone ALLOWED_TO_REACH zone (`via` = `same-zone` / `firewall`); Zone sources are zones without assets (the Internet) |

The bold edges are the bridges. `link` rebuilds them every time it runs. Through them, an alert can reach:

```
Asset ─RUNS→ Service ─IMPLEMENTED_BY→ Software ─HAS_VULNERABILITY→ Vulnerability ←EXPLOITED_BY─ Weakness ─CAUSES_WEAKNESS→ AttackPattern ─USES_TECHNIQUE→ Technique
Asset ─RUNS_ON→ Platform ←AFFECTS─ Technique                      (alerts that carry only an ATT&CK id)
Zone/Asset ─CAN_REACH→ Service ←RUNS─ Asset                       (attack paths, blast radius)
```

Example queries:

```cypher
// technique from an alert -> hosts it can run on
MATCH (t:Technique {attack_id: 'T1059.004'})-[:AFFECTS]->(:Platform)<-[:RUNS_ON]-(a:Asset)
RETURN a.hostname

// attack paths from the Internet to the database through reachable services
MATCH p = (:Zone {name: 'Internet'})-[:CAN_REACH]->(:Service)<-[:RUNS]-(:Asset)
          (()-[:CAN_REACH]->(:Service)<-[:RUNS]-(:Asset)){0,3}
WHERE last(nodes(p)).hostname = 'PostgreSQL'
RETURN p LIMIT 25

// the same paths, keeping only hops onto services with a known CVE
MATCH p = (:Zone {name: 'Internet'})-[:CAN_REACH]->(s1:Service)<-[:RUNS]-(:Asset)
          (()-[:CAN_REACH]->(s:Service)<-[:RUNS]-(:Asset)
             WHERE EXISTS { (s)-[:IMPLEMENTED_BY]->()-[:HAS_VULNERABILITY]->() }){0,3}
WHERE EXISTS { (s1)-[:IMPLEMENTED_BY]->()-[:HAS_VULNERABILITY]->() }
  AND last(nodes(p)).hostname = 'PostgreSQL'
RETURN p LIMIT 25
```

## Alerts (`alert_kg`)

| Edge | Direction | Origin |
|---|---|---|
| TARGETS | Alert → Asset | `agent.name` (case-insensitive), else `agent.ip` |
| INDICATES | Alert → Technique | `rule.mitre.id` (revoked ids remapped), else `overrides/wazuh_rule_techniques.csv` (`via` on the edge) |
| MENTIONS | Alert → Vulnerability | `data.vulnerability.cve` |
| FROM | Alert → Asset, Alert → Zone | `data.srcip` = a lab host's IP, otherwise the Internet zone (loopback ignored) |

`Alert` key: `alert_id` (indexer `_id`). It also stores `rule_id`, `rule_level`, `description`, `groups`,
`techniques`, `techniques_original`, `cves`, `srcip`, `dstip`, `dstport`, `timestamp` and `full_log`.
After `python -m score_kg alerts`, it also has `event_score` / `event_band` / `event_basis` (how dangerous the event is, 0–10, and whether it is based on a linked CVE or the Wazuh level), `host_risk` / `host_band` / `host_top_cve` (how dangerous the host is) and `ssvc` (CISA SSVC decision). See [scoring.md](scoring.md).
