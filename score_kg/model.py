"""Environmental Vulnerability Score (paper §III.A.2-3, Eqs. 5-17, Algorithm 1). Pure functions.

    G_R      Asset Reachability Graph: CONNECTS_TO edges (u, v) whose zones allow the flow (Eqs. 5-6)
    m(c)     impact mode: compromise if the CVSS C or I impact is not None, otherwise disruption
    BR_k     blast radius: BFS over G_R to depth k, out-edges for compromise, in-edges for disruption (Eqs. 7-9)
    Env      CVSS v3.1 Environmental score with graph-derived metrics (Eqs. 10-13, Table I; cvss31.py)
    crit(v)  max(CR, IR, AR) - 0.5 with weights H 1.5, M 1.0, L 0.5  ->  H 1, M 0.5, L 0 (Eq. 14)
    P(u)     1/(|V_A| - 1) * sum over v reachable from u of crit(v) * gamma^d(u,v) (Eq. 15)
    EVS      min(10, Env * (1 + beta * P(u)))  (Eq. 16), level by the CVSS qualitative scale (Eq. 17)
"""
import math
from collections import deque

from . import cvss31

WEIGHT = {"H": 1.5, "M": 1.0, "L": 0.5}           # CVSS v3.1 security-requirement weights


def crit(cr: str, ir: str, ar: str) -> float:
    """Eq. 14: the asset's highest security requirement, normalised to [0, 1]."""
    return max(WEIGHT[cr], WEIGHT[ir], WEIGHT[ar]) - 0.5


def impact_mode(base_vector: str) -> str:
    """compromise if the vulnerability affects confidentiality or integrity, else disruption."""
    m = cvss31.metrics(base_vector)
    return "compromise" if m.get("C", "N") != "N" or m.get("I", "N") != "N" else "disruption"


def reachability_edges(connects: list[tuple[str, str]], zone: dict[str, str],
                       allowed: set[tuple[str, str]]) -> set[tuple[str, str]]:
    """E_R (Eqs. 5-6): CONNECTS_TO edges permitted by the network policy (same zone or zones allowed)."""
    return {(u, v) for u, v in connects
            if u != v and (zone[u] == zone[v] or (zone[u], zone[v]) in allowed)}


def _neighbours(edges: set[tuple[str, str]], reverse: bool = False) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for u, v in edges:
        a, b = (v, u) if reverse else (u, v)
        out.setdefault(a, set()).add(b)
    return out


def distances(edges: set[tuple[str, str]], start: str, reverse: bool = False, k: int | None = None) -> dict[str, int]:
    """Shortest hop distance from `start` over the edges (in-edges if reverse), optionally bounded at k."""
    nbr = _neighbours(edges, reverse)
    dist, frontier = {start: 0}, deque([start])
    while frontier:
        u = frontier.popleft()
        if k is not None and dist[u] >= k:
            continue
        for v in nbr.get(u, ()):
            if v not in dist:
                dist[v] = dist[u] + 1
                frontier.append(v)
    return dist


def blast_radius(edges: set[tuple[str, str]], asset: str, mode: str, k: int = 1) -> dict[str, int]:
    """Algorithm 1: BR_k(a, c) as {asset: hops}; the asset itself is included at 0."""
    return distances(edges, asset, reverse=(mode == "disruption"), k=k)


def propagation(edges: set[tuple[str, str]], asset: str, crit_of: dict[str, float], gamma: float) -> float:
    """Eq. 15: discounted criticality of every asset reachable from `asset`, divided by |V_A| - 1."""
    others = len(crit_of) - 1
    if others <= 0:
        return 0.0
    dist = distances(edges, asset)
    return sum(crit_of[v] * gamma ** d for v, d in dist.items() if v != asset) / others


def roundup(x: float) -> float:
    """Smallest one-decimal number >= x (CVSS v3.1 Roundup, integer form to avoid float error)."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def evs(env: float, p: float, beta: float) -> float:
    """Eq. 16 (rounded up to one decimal, like every CVSS score)."""
    return min(10.0, roundup(env * (1 + beta * p)))


def score(asset: dict, vuln: dict, internet_path: bool, p: float, beta: float, alerted: bool = False) -> dict:
    """EVS(c, u) with every intermediate value, so a report can show how it was reached.

    asset: hostname, cr, ir, ar     vuln: cve, cvss3_vector
    """
    mav = cvss31.modified_av(vuln["cvss3_vector"], internet_path)
    e, e_reason = cvss31.exploit_maturity(alerted, bool(vuln.get("kev")), vuln.get("ssvc_exploitation"))
    env = cvss31.environmental(vuln["cvss3_vector"], e, asset["cr"], asset["ir"], asset["ar"], mav)
    value = evs(env["environmental"], p, beta)
    return {
        "asset": asset["hostname"], "cve": vuln["cve"],
        "cvss_base": env["base"], "base_band": cvss31.band(env["base"]),
        "AV": cvss31.metrics(vuln["cvss3_vector"]).get("AV"), "MAV": mav, "E": e, "E_reason": e_reason,
        "CR": asset["cr"], "IR": asset["ir"], "AR": asset["ar"], "internet_path": internet_path,
        "env_vector": env["vector"], "env": env["environmental"], "P": round(p, 4),
        "evs": value, "level": cvss31.band(value), "impact_mode": impact_mode(vuln["cvss3_vector"]),
    }
