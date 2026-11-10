"""CISA SSVC decision tree (CISA SSVC Guide, Tables 8 and 9): Track / Track* / Attend / Act.

Inputs from the graph:
    Exploitation, Automatable, Technical Impact   Vulnerability.ssvc_* (CISA vulnrichment)
    Mission Prevalence                            the asset's highest CR/IR/AR: H Essential, M Support, L Minimal
    Public Well-Being Impact                      Minimal for every lab asset (no safety-relevant systems)
"""

# Table 8: (mission prevalence, well-being) -> mission & well-being impact
MISSION_WELLBEING = {
    ("minimal", "minimal"): "low", ("minimal", "material"): "medium", ("minimal", "irreversible"): "high",
    ("support", "minimal"): "medium", ("support", "material"): "medium", ("support", "irreversible"): "high",
    ("essential", "minimal"): "high", ("essential", "material"): "high", ("essential", "irreversible"): "high",
}

# Table 9: (exploitation, automatable, technical impact) -> outcome for mission&well-being low / medium / high
TABLE9 = {
    ("none", "no", "partial"): ("Track", "Track", "Track"),
    ("none", "no", "total"): ("Track", "Track", "Track*"),
    ("none", "yes", "partial"): ("Track", "Track", "Attend"),
    ("none", "yes", "total"): ("Track", "Track", "Attend"),
    ("poc", "no", "partial"): ("Track", "Track", "Track*"),
    ("poc", "no", "total"): ("Track", "Track*", "Attend"),
    ("poc", "yes", "partial"): ("Track", "Track", "Attend"),
    ("poc", "yes", "total"): ("Track", "Track*", "Attend"),
    ("active", "no", "partial"): ("Track", "Track", "Attend"),
    ("active", "no", "total"): ("Track", "Attend", "Act"),
    ("active", "yes", "partial"): ("Attend", "Attend", "Act"),
    ("active", "yes", "total"): ("Attend", "Act", "Act"),
}
ORDER = ["Track", "Track*", "Attend", "Act"]
LEVEL = {"L": 0, "M": 1, "H": 2}


def mission_prevalence(cr: str, ir: str, ar: str) -> str:
    return ["minimal", "support", "essential"][max(LEVEL[cr], LEVEL[ir], LEVEL[ar])]


def outcome(exploitation: str | None, automatable: str | None, technical_impact: str | None,
            kev: bool, cvss_vector: str, mission: str, well_being: str = "minimal") -> str:
    """SSVC action. Missing vulnrichment values fall back to: KEV -> active else none; automatable no;
    technical impact total if the CVSS vector has C:H and I:H, else partial."""
    expl = (exploitation or "").strip().lower() or ("active" if kev else "none")
    if kev:
        expl = "active"                      # in KEV = exploited in the wild, whatever vulnrichment said
    auto = (automatable or "").strip().lower() or "no"
    impact = (technical_impact or "").strip().lower()
    if not impact:
        impact = "total" if "/C:H" in cvss_vector and "/I:H" in cvss_vector else "partial"
    mwb = MISSION_WELLBEING[(mission, well_being)]
    return TABLE9[(expl, auto, impact)][["low", "medium", "high"].index(mwb)]
