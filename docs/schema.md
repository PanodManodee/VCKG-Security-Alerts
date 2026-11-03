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
| VULNERABLE_TO | CPE → Vulnerability | NVD `vulnerable: true` cpeMatch; version ranges on the edge (`version_start_including`, `version_end_excluding`, …) — the paper's AFFECTS_VERSION |

Simplification: NVD configurations that combine an application CPE with a non-vulnerable
"running on" platform CPE (AND nodes) only keep the vulnerable CPE.

## Manual adjustments

`overrides/*.csv` are applied after automatic parsing and alignment; see the header of each file.
Automatic merges are listed in `data/processed/alignment_report.csv` for review.
