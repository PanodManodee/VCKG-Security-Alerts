"""Graph schema: node labels with their key property, and allowed edge types.

Follows Nagaty et al. (ICCA 2025) section IV.B. See schema.md for the diagram.
"""

NODE_KEYS = {
    "Weakness": "cwe_id",          # CWE-732
    "Vulnerability": "cve_id",     # CVE-2021-34563
    "AttackPattern": "capec_id",   # CAPEC-1
    "Technique": "attack_id",      # T1574.010
    "Tactic": "attack_id",         # TA0004
    "Group": "attack_id",          # G0016
    "Mitigation": "mit_id",        # M1047 | CWE-MIT-<hash> | MIT-5
    "DetectionMethod": "name",     # Automated Static Analysis
    "Platform": "name",            # Windows
    "CPE": "cpe23",                # cpe:2.3:a:vendor:product:*:...
}

# (edge type, source label, target label)
EDGE_TYPES = {
    ("EXPLOITED_BY", "Weakness", "Vulnerability"),
    ("CAUSES_WEAKNESS", "Weakness", "AttackPattern"),
    ("USES_TECHNIQUE", "AttackPattern", "Technique"),
    ("USES_TECHNIQUE", "Group", "Technique"),
    ("IMPLEMENTS", "Technique", "Tactic"),
    ("SUBTECHNIQUE_OF", "Technique", "Technique"),
    ("MITIGATED_BY", "Weakness", "Mitigation"),
    ("MITIGATED_BY", "Technique", "Mitigation"),
    ("DETECTED_BY", "Weakness", "DetectionMethod"),
    ("AFFECTS", "Weakness", "Platform"),
    ("AFFECTS", "Technique", "Platform"),
    ("IS_PARENT", "Weakness", "Weakness"),            # parent -> child
    ("IS_PARENT", "AttackPattern", "AttackPattern"),  # parent -> child
    ("VULNERABLE_TO", "CPE", "Vulnerability"),
}
