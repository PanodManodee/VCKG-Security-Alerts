# Evaluation ground truth (pentest record)

This folder holds the labels for Part A of the evaluation (the score ladder L0 → L4, see `docs/evaluation.md`).
The labels come only from what the pentest team **did and achieved** in the lab. They never come from CR/IR/AR
or any other input of the score, because that would make the evaluation circular.

| File | What the team fills in |
|---|---|
| `scenarios/<id>.yaml` | one file per attack scenario: its time window and every step (start/end in UTC, target asset, CVE if any, outcome) |
| `pentest_results.csv` | for each asset × CVE the team examined: was it exploited (`yes` / `no` / `not_tried`) |
| `dry_run/` | **synthetic** files to test the pipeline. Its numbers are never reported |

## Scenario file

Copy `scenarios/TEMPLATE.yaml.example` to `scenarios/<id>.yaml`. Record times in **UTC**, and record them while
the scenario runs (the lab clocks are the host's clock). Alerts are matched to a step when their target asset is
the step's `target`, their CVE is the step's `cve` (if the step names one), and their time falls in the step's
window, ± `EVAL_MATCH_SLACK` seconds (default 120).

Grades, computed from each step:

| Grade | Step |
|---:|---|
| 3 | `outcome: success` and (`achieved: data_access` or `pivot: true`) |
| 2 | `outcome: success` |
| 1 | `outcome: failed`: attempted but did not work |
| 0 | an alert in the scenario's window that matches no step (noise) |

## Running

```powershell
python -m eval_kg measure                                       # Part B ground truth from the running lab
python -m eval_kg all                                           # both reports, labels from this folder
python -m eval_kg all --labels evaluation/dry_run               # pipeline test with the synthetic labels
```
