"""CVSS v3.1 Environmental score for one asset x CVE, using the standard formula (FIRST spec).

Scoring is done by the `cvss` library (RedHat), not by hand, so the numbers are the standard ones.
This module only decides the metric values that come from the environment:

    E    exploit code maturity (temporal)  KEV / SSVC exploitation
    CR/IR/AR  security requirements         the asset's confidentiality / integrity / availability value
    MAV  modified attack vector             how exposed the asset is in the graph (CAN_REACH)
"""
from cvss import CVSS3

AV_ORDER = "PLAN"           # least -> most exposed: Physical, Local, Adjacent, Network
BANDS = [(9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"), (0.0, "None")]


def band(score: float) -> str:
    """CVSS qualitative severity rating."""
    for low, name in BANDS:
        if score >= low:
            return name
    return "None"


def exploit_maturity(kev: bool, ssvc_exploitation: str | None) -> str:
    """E: High when exploited in the wild (KEV or SSVC 'active'), PoC, Unproven, or Not defined (no data)."""
    expl = (ssvc_exploitation or "").strip().lower()
    if kev or expl == "active":
        return "H"
    if expl == "poc":
        return "P"
    if expl == "none":
        return "U"
    return "X"


def reachability_av(internet_exposed: bool, reached_by_assets: bool) -> str:
    """Attack vector the network position allows: N from the Internet, A from inside the network, L otherwise."""
    if internet_exposed:
        return "N"
    return "A" if reached_by_assets else "L"


def modified_av(base_vector: str, internet_exposed: bool, reached_by_assets: bool) -> str:
    """MAV = the less exposed of the CVE's own AV and what the asset's position allows.

    The environment can only *restrict* access (a network-exploitable bug on a host nobody can
    reach is effectively local); it never turns a local bug into a network one.
    """
    base_av = metrics(base_vector).get("AV", "N")
    reach = reachability_av(internet_exposed, reached_by_assets)
    return min(base_av, reach, key=AV_ORDER.index)


def metrics(vector: str) -> dict:
    return dict(part.split(":", 1) for part in vector.split("/")[1:])


def environmental(base_vector: str, e: str, cr: str, ir: str, ar: str, mav: str) -> dict:
    """Base, temporal and environmental scores of the vector extended with the environment."""
    vector = f"{base_vector}/E:{e}/CR:{cr}/IR:{ir}/AR:{ar}/MAV:{mav}"
    base, temporal, env = (float(s) for s in CVSS3(vector).scores())
    return {"vector": vector, "base": base, "temporal": temporal, "environmental": env}
