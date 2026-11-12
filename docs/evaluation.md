# Stage 5: evaluation protocol (ablation against lab ground truth)

The EVS is built from parts: CVSS base, asset requirements, Internet reachability, exploit maturity, and
propagation. The blast radius is built from design choices: edge type, zone policy, direction and depth. The
evaluation adds or swaps one part at a time. If it only showed that each part *changes* the ranking, it would be a
sensitivity analysis. To show that a part *helps*, every variant is scored against **ground truth that does not
come from the score or from the files the algorithm reads**. Code: `eval_kg/`. Commands: `python -m eval_kg --help`.

## Part A: score ladder

| Step | Adds | Question |
|---|---|---|
| L0 | CVSS v3.1 base | baseline |
| L1 | + CR/IR/AR (Environmental, E = X, MAV = base) | does asset value change the ranking? |
| L2 | + MAV from Internet reachability (Table I) | does network position? |
| L3 | + E from alert / KEV / SSVC (Eq. 14) | does exploitation evidence? |
| L4 | + P(u), giving the EVS (Eqs. 16–17) | does the propagation (blast radius) term? |
| Baselines | EPSS percentile, KEV (0/1), CISA SSVC decision, Wazuh `rule.level` | is the EVS better than what a SOC uses today? |

**Ground truth: the pentest record** (`evaluation/`, filled in by the team).

- **A1, asset × CVE:** `pentest_results.csv` says whether each examined vulnerability was exploited in the lab. Relevance is 1 or 0; `not_tried` rows are left out, because unknown is not the same as negative.
- **A2, alerted vulnerability instances:** each scenario (`scenarios/*.yaml`) lists its steps with time windows and outcomes. An alert instance (asset, CVE) inside a scenario's window gets the grade of the step it matches (same target, same CVE if the step names one, overlapping time ± 120 s):

  | Grade | Step outcome |
  |---:|---|
  | 3 | success with data access, or used as a pivot onward |
  | 2 | success on the target |
  | 1 | attempted, failed |
  | 0 | the alert matches no step (noise) |

  The grades come only from what the attacker achieved. CR/IR/AR are deliberately **not** used for grading, because they are an input of L1–L4, and using them would make the evaluation circular.

**Metrics.**

- NDCG@5 and NDCG@10, with gain 2^g − 1;
- P@5 and P@10 (relevant = grade ≥ 2, or exploited);
- MRR;
- rank of the first true attack-chain item (grade 3).

For A2 these are computed per scenario and then averaged. Each step's gain L(i) − L(i−1), and L4 against each
baseline, is reported as ΔNDCG@10 with a 95% paired-bootstrap confidence interval (1000 resamples, seed 7). The
resampling is over scenarios, or over items when there are fewer than five scenarios; the report says which. Ties
in a score are broken by item id.

## Part B: blast-radius algorithm

| Variant | What it does | What it shows |
|---|---|---|
| B0 | no blast radius (P = 0) | what is lost without one |
| B1 | unrestricted: every Asset within k hops (k = 1, 2) over any edge type of the unified graph | the "no rules" query (it also returns zones, services, alerts, CVEs) |
| B2 | zone-level: hosts in the same or an allowed zone (outbound for compromise, inbound for disruption), ignoring CONNECTS_TO | the coarse subnet approach |
| B3 | ours, undirected: no impact mode | does direction matter? |
| B4 | ours: CONNECTS_TO with the π(u, v) zone rule, direction by impact mode, k = 1 (Algorithm 1) | the proposed algorithm |
| B5 | ours at k = 2 and k = 3 | is the depth choice justified? |

**Ground truth: measured in the running lab** (`python -m eval_kg measure`). It is never read from `lab/*.csv`.

| Truth set | Mode | How it is measured |
|---|---|---|
| network | compromise | from every host, a TCP connect to every other host on the lab's service ports. This is what the firewall really lets through |
| usable | compromise | on every host, `lab_env/eval/harvest.sh` looks for stored targets and credentials, the way post-compromise enumeration does: environment, config files, home directories, Jenkins jobs. It then tries a harmless authenticated access with each (HTTP GET, `psql select 1`, `smbclient ls`). It is not told where to look for any particular host |
| dependents | disruption | stop one host (`docker compose stop`), run every other host's health check (`lab_env/eval/checks.csv`), then start it again. The hosts whose service fails are the real dependents |

The lab's dependencies are real: Nginx proxies Web, Web proxies `/api/` to the API, the API reads PostgreSQL,
Jenkins' `api-smoke` job calls the API, and Admin-PC maps the finance share with stored credentials. The network
set alone would favour B2, because this lab's firewall works per zone. The usable and dependents sets measure what
an intruder or an outage actually affects.

**Metrics.**

- Per asset, and per (asset, CVE) pair with the CVE's impact mode choosing the direction and the truth set: precision, recall and F1 of the predicted affected set. An empty prediction has precision 1, and an empty truth set has recall 1.
- Cost: runtime per query and set size. B1 also reports the non-asset nodes it returns.
- Downstream: L4 recomputed with each variant's reachable set feeding P(u), then NDCG@10 on the A1 labels.

## Threats to validity (to state in the paper)

- **Small lab:** 8 hosts. The CIs will be wide, and they are reported rather than hidden.
- **Labels from the same team:** the pentest is run and recorded by the authors. Grading by outcome rather than by asset value limits, but does not remove, the bias.
- **Lab-specific ground truth:** the measured sets describe this lab. Another network would need its own measurement, which the scripts automate.
- **CTI holds CVEs from 2024 on:** A1 can only use those CVEs.
- **Usable reach:** it finds what is stored on a host in common places. It is a lower bound on what a skilled intruder could use.

## Running

```powershell
cd lab_env; docker compose up -d; cd ..        # the lab must run for the measurements
python -m eval_kg measure                       # Part B ground truth -> data/eval/*.json
python -m eval_kg all                           # both reports -> data/reports/eval_*.md (+ CSV)
python -m eval_kg all --labels evaluation/dry_run   # pipeline test with synthetic labels (never report these)
```
