"""Evaluation metrics: graded ranking metrics, set overlap, and a paired bootstrap for differences.

Relevance grades (docs/evaluation.md): 3 successful step with data access or a pivot, 2 successful step,
1 attempted / failed step, 0 noise. "Relevant" for P@k is grade >= 2; the "first true attack-chain item"
is the first item with grade 3.
"""
import math
import random


def dcg(rels: list[int]) -> float:
    return sum((2 ** r - 1) / math.log2(i + 2) for i, r in enumerate(rels))


def ndcg_at_k(ranked_rels: list[int], k: int) -> float | None:
    """NDCG@k with exponential gain; None when the list has no relevant item (undefined)."""
    ideal = dcg(sorted(ranked_rels, reverse=True)[:k])
    return None if ideal == 0 else dcg(ranked_rels[:k]) / ideal


def precision_at_k(ranked_rels: list[int], k: int, threshold: int = 2) -> float:
    top = ranked_rels[:k]
    return sum(r >= threshold for r in top) / k if top else 0.0


def first_hit(ranked_rels: list[int], threshold: int = 3) -> int | None:
    """1-based rank of the first item with grade >= threshold, None if there is none."""
    return next((i + 1 for i, r in enumerate(ranked_rels) if r >= threshold), None)


def reciprocal_rank(ranked_rels: list[int], threshold: int = 2) -> float:
    rank = first_hit(ranked_rels, threshold)
    return 1.0 / rank if rank else 0.0


def ranked(items: list[dict], score_key: str, rel_key: str = "grade") -> list[int]:
    """Relevance grades in the order of the score (highest first; ties broken by item id, stated in reports)."""
    order = sorted(items, key=lambda x: (-(x[score_key] if x[score_key] is not None else -1), x["id"]))
    return [x[rel_key] for x in order]


def set_prf(predicted: set, observed: set) -> tuple[float, float, float]:
    """Precision, recall, F1. An empty prediction has precision 1 (it claims nothing false); an empty
    observed set has recall 1 (there is nothing to find)."""
    tp = len(predicted & observed)
    p = tp / len(predicted) if predicted else 1.0
    r = tp / len(observed) if observed else 1.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)


def paired_bootstrap(units: list, metric_a, metric_b, n: int = 1000, seed: int = 7) -> dict:
    """Mean difference metric_a - metric_b over the units, with a 95% percentile CI.

    metric_x(sample) receives a resampled list of units (with replacement) and returns a number or None;
    resamples where either is None are skipped. Both metrics see the same resample (paired).
    """
    rng = random.Random(seed)
    observed_a, observed_b = metric_a(units), metric_b(units)
    if observed_a is None or observed_b is None or not units:
        return {"diff": None, "lo": None, "hi": None, "n": 0}
    diffs = []
    for _ in range(n):
        sample = [units[rng.randrange(len(units))] for _ in units]
        a, b = metric_a(sample), metric_b(sample)
        if a is not None and b is not None:
            diffs.append(a - b)
    diffs.sort()
    if not diffs:
        return {"diff": observed_a - observed_b, "lo": None, "hi": None, "n": 0}
    lo, hi = diffs[int(0.025 * (len(diffs) - 1))], diffs[int(0.975 * (len(diffs) - 1))]
    return {"diff": observed_a - observed_b, "lo": lo, "hi": hi, "n": len(diffs)}
