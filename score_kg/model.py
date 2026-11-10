"""The context-aware score for one asset x CVE (docs/scoring.md).

    S_env = CVSS v3.1 Environmental (E from KEV/SSVC, CR/IR/AR from the asset, MAV from reachability)
    R     = min(10, S_env + (10 - S_env) * (aT + bG + cA) / (a + b + c))

    T  EPSS percentile of the CVE                         (threat outside CVSS: CVSS threat can only lower)
    G  blast radius of the asset in [0, 1]                (value reachable from it once it is compromised)
    A  alert evidence: 1 an alert points at this CVE, 0 otherwise

With T = G = A = 0, R equals the standard environmental score; every context signal closes part of the
gap to 10, and a score can only go down through the standard CVSS metrics.
"""
import math

from . import cvss31, ssvc

VALUE = {"H": 1.5, "M": 1.0, "L": 0.5}       # CVSS v3.1 security-requirement weights


def asset_value(cr: str, ir: str, ar: str) -> float:
    """Asset value in (0, 1]: its highest requirement weight / 1.5 (FIPS 199 high-water mark)."""
    return max(VALUE[cr], VALUE[ir], VALUE[ar]) / 1.5


def blast_radius(reachable: list[tuple[float, int]], total_other_value: float) -> float:
    """G: sum of value / hops over the assets reachable from this one, normalised by all other assets' value."""
    if total_other_value <= 0:
        return 0.0
    return min(1.0, sum(value / hops for value, hops in reachable) / total_other_value)


def combine(s_env: float, t: float, g: float, a: float, weights=(1.0, 1.0, 1.0)) -> float:
    wa, wb, wc = weights
    total = wa + wb + wc
    uplift = (wa * t + wb * g + wc * a) / total if total else 0.0
    return round(min(10.0, s_env + (10.0 - s_env) * uplift), 1)


WAZUH_MAX_LEVEL = 15


def event_score(rule_level: int, cr: str, ir: str, ar: str, g: float, weights=(1.0, 1.0, 1.0)) -> dict:
    """Severity of an alert that leads to no CVE on its host, on the same 0-10 scale as R.

    base    Wazuh's own severity, rule.level 0-15 mapped linearly to 0-10
    S_event base x the host's highest security-requirement weight (H 1.5, M 1.0, L 0.5), rounded up to
            one decimal and capped at 10, the way CVSS v3.1 lets CR/IR/AR scale impact
    R       S_event + the same uplift as for CVEs, with only the blast radius G: there is no CVE (so no EPSS),
            and the alert itself is already the base (so no extra alert evidence)
    """
    base = min(10.0, max(0, rule_level) * 10.0 / WAZUH_MAX_LEVEL)
    weight = max(VALUE[cr], VALUE[ir], VALUE[ar])
    s_event = min(10.0, math.ceil(round(base * weight * 10, 6)) / 10)
    return {"base": round(base, 1), "weight": weight, "s_event": s_event, "G": round(g, 3),
            "R": combine(s_event, 0.0, g, 0.0, weights)}


def score_pair(asset: dict, vuln: dict, epss: dict, g: float, a: float, weights=(1.0, 1.0, 1.0)) -> dict:
    """Every layer of the score, so a report can show how the number was reached.

    asset: hostname, cr, ir, ar, internet_exposed, reached_by_assets
    vuln:  cve, cvss3_vector, cvss3_score, kev (bool), ssvc_exploitation, ssvc_automatable, ssvc_technical_impact
    """
    e = cvss31.exploit_maturity(vuln["kev"], vuln.get("ssvc_exploitation"))
    mav = cvss31.modified_av(vuln["cvss3_vector"], asset["internet_exposed"], asset["reached_by_assets"])
    env = cvss31.environmental(vuln["cvss3_vector"], e, asset["cr"], asset["ir"], asset["ar"], mav)
    t = epss.get(vuln["cve"], (0.0, 0.0))[1]
    r = combine(env["environmental"], t, g, a, weights)
    mission = ssvc.mission_prevalence(asset["cr"], asset["ir"], asset["ar"])
    return {
        "asset": asset["hostname"], "cve": vuln["cve"],
        "cvss_base": env["base"], "base_band": cvss31.band(env["base"]),
        "E": e, "MAV": mav, "CR": asset["cr"], "IR": asset["ir"], "AR": asset["ar"],
        "env_vector": env["vector"], "s_env": env["environmental"],
        "epss": epss.get(vuln["cve"], (None, None))[0], "T": t, "G": round(g, 3), "A": a,
        "R": r, "band": cvss31.band(r),
        "ssvc": ssvc.outcome(vuln.get("ssvc_exploitation"), vuln.get("ssvc_automatable"),
                             vuln.get("ssvc_technical_impact"), vuln["kev"], vuln["cvss3_vector"], mission),
        "kev": vuln["kev"],
    }
