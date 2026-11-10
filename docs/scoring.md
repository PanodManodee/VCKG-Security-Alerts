# Stage 4: context-aware scoring (method)

This document describes how `score_kg` turns the unified graph into a priority for each vulnerability on each
host, and for each alert. It is written so it can be lifted into the paper's method section.
Code: `score_kg/` (`cvss31.py`, `ssvc.py`, `model.py`). Design rationale and literature:
`reports/Asset KG linking and alert rescoring.md`.

## 1. Score for one asset × CVE

The score is built in layers. Each layer is a standard metric or a bounded, documented addition, so it can be
explained and ablated.

### 1.1 Standard part: CVSS v3.1 Environmental score `S_env`

The CVE's CVSS v3.1 base vector (NVD, or the CNA when NVD has none) is extended with metrics taken from the graph.
It is then scored with the standard formula (FIRST CVSS v3.1 specification, via the `cvss` library).

| Metric | Value | Source in the graph |
|---|---|---|
| E (Exploit Code Maturity) | **H** if the CVE is in CISA KEV or CISA vulnrichment says `exploitation = active`; **P** if `poc`; **U** if `none`; **X** if unknown | `Vulnerability.kev_date_added`, `ssvc_exploitation` |
| CR / IR / AR (security requirements) | the host's confidentiality / integrity / availability requirement, L/M/H | `Asset.cr/ir/ar` (`lab/assets.csv`) |
| MAV (Modified Attack Vector) | the **less exposed** of the CVE's own AV and the host's position: **N** if a zone without assets (the Internet) can reach one of its services; **A** if only other hosts can reach it; **L** if nothing can | `Asset.internet_exposed`, `CAN_REACH` |

Design choices:

- **MAV can only lower exposure.** A network-exploitable bug on a host that no one can reach is effectively
  local, but a local bug never becomes network-exploitable because the host is exposed.
- **Using A for "reachable only from inside"** reads CVSS's *adjacent* as "the attacker must already be inside
  the network". This is a documented interpretation, not a literal subnet test.
- CVSS threat metrics can only lower a score (E = X is the worst case). So in `S_env`, threat information
  demotes CVEs nobody exploits. Promotion comes from the environment and from the uplift below.

### 1.2 Context uplift `R`

```
R = min(10, S_env + (10 − S_env) · (α·T + β·G + γ·A) / (α + β + γ))
```

| Term | Meaning | Range | Computation |
|---|---|---|---|
| T | threat: probability of exploitation activity | 0–1 | EPSS percentile of the CVE (FIRST, daily file; model and date are printed in the report). A CVE without a score counts as 0 |
| G | blast radius: value reachable *from* the host once compromised | 0–1 | Σ value(b) / hops(a→b) over the hosts b reachable in 1–3 `CAN_REACH` hops, ÷ Σ value of all other hosts. value = highest of CR/IR/AR (H 1.5, M 1.0, L 0.5) / 1.5 |
| A | alert evidence | 0 or 1 | 1: an alert on the host names this CVE, or its ATT&CK technique leads to the CVE (Technique ← CAPEC ← CWE → CVE). 0: otherwise |
| α, β, γ | weights | ≥ 0 | 1, 1, 1 by default (`SCORE_WEIGHTS`). `score_sensitivity.md` reports how the ranking changes under 63 other settings |

Properties:

1. With no context evidence (T = G = A = 0), R equals the standard CVSS v3.1 environmental score.
2. Every context signal closes part of the remaining gap to 10, so R ≤ 10 always.
3. A score can only go **down** through standard CVSS metrics (low requirements, less exposed MAV, E = U).
4. G measures the consequences *beyond* the host, and MAV measures the exposure *of* the host. They are kept
   apart so they are not counted twice, and each can be ablated on its own.

The **band** is the CVSS qualitative rating applied to R (None / Low / Medium / High / Critical). The report
compares it with the band of the CVSS base score.

### 1.3 Categorical outcome: CISA SSVC

Each pair also gets a CISA SSVC decision (Track / Track* / Attend / Act), from CISA's SSVC Guide, Tables 8
and 9. The inputs:

- **Exploitation, Automatable, Technical Impact:** CISA vulnrichment (`ssvc_*`). If the CVE is in KEV,
  exploitation is set to *active*.
- **Mission Prevalence:** the host's highest requirement. H = Essential, M = Support, L = Minimal.
- **Public Well-Being:** *Minimal* for every lab host, since none is safety-relevant.

SSVC is a second, independent baseline. It is not an input to R.

## 2. Scores of an alert

Alert contexts come from `alert_kg`. Alerts with the same rule, target and source are grouped and counted.
Each group gets two scores on the same 0–10 scale.

**Event severity: how dangerous this event is. This is the ranking key.**

- *The alert leads to a CVE on its host.* Either the alert names the CVE, or its ATT&CK technique reaches the
  CVE through Technique ← CAPEC ← CWE → CVE. The event severity is then the highest R among those CVEs, with
  A = 1. The CVE's SSVC decision applies.
- *The alert leads to no CVE.* This covers, for example, brute force or account changes, whose techniques
  have no CAPEC/CWE path to a vulnerability. The event severity is then built the same way as a CVE score,
  from Wazuh's own severity:

  ```
  base     = rule.level × 10 / 15                        Wazuh levels 0–15 mapped to 0–10
  S_event  = min(10, Roundup(base × w))                  w = highest of the host's CR/IR/AR weights (H 1.5, M 1.0, L 0.5)
  R_event  = S_event + (10 − S_event) · β·G / (α + β + γ)
  ```

  w plays the role of CVSS's security requirements: the same event matters more on a valuable host.
  The uplift keeps only the blast radius G. There is no CVE, so there is no EPSS (T = 0). The alert itself
  is already the base, so alert evidence would count it twice (A = 0). Because the denominator is the same
  as for CVEs, both kinds of event severity sit on one scale and can be ranked together.

- If an alert leads to a CVE but `R_event` is higher, the higher value is used, and the report names the basis.

**Host risk: how dangerous the host is, whatever the event.** This is the highest R among all CVEs on the host,
with no alert evidence (A = 0), together with that CVE's SSVC decision.

The report puts both scores side by side with two baselines, Wazuh's `rule.level` and the highest CVSS base
score on the host. A low-level event on a very vulnerable host therefore shows as *low event severity, high
host risk*. It is not promoted above a more serious event on a less vulnerable host.

## 3. Outputs

| File | Content |
|---|---|
| `data/scores/asset_cve_scores.csv` | every asset × CVE: base, E, MAV, CR/IR/AR, environmental vector, S_env, EPSS, T, G, A, R, band, SSVC, KEV, CVE source (NVD / OSV) |
| `data/scores/alert_scores.csv` | every alert group: event severity (and what it is based on), host risk, host SSVC, Wazuh level, highest CVSS on the host |
| `data/reports/threat_report.md` | alerts ranked by priority with explanations, assets, top vulnerabilities, CVSS-band → R-band matrix |
| `data/reports/score_sensitivity.md` | Kendall τ and top-k overlap of the ranking under 63 weight settings |
| Neo4j | `Alert.event_score`, `event_band`, `event_basis`, `host_risk`, `host_band`, `host_top_cve`, `ssvc` |

## 4. Known limits

- **Alerts that lead to no CVE** are scored from Wazuh's `rule.level`. Their event severity is only as good
  as Wazuh's rule levels, scaled by host value and blast radius. The linear mapping of levels 0–15 to 0–10 is
  a design choice.
- **Few techniques lead to CVEs.** Only about 174 ATT&CK techniques reach a CVE through CWE/CAPEC, so most
  alerts are scored from the Wazuh level. Alerts from real exploit attempts that name a CVE are scored from
  the CVE.
- **CVSS v3.1 is the standard used.** Only a few lab CVEs have v4 vectors. CVSS v4 BTE is future work.
- **The weights are not elicited from experts yet** (AHP is planned). The sensitivity report shows how much the
  ranking depends on them.
- **EPSS is today's score.** A forward-in-time evaluation (stage 5, tier A) must use EPSS as of the evaluation date.
