"""CAPEC catalog -> AttackPattern nodes.

Edges produced: CAUSES_WEAKNESS (Related_Weaknesses), USES_TECHNIQUE (ATT&CK taxonomy
mappings) and IS_PARENT (ChildOf between attack patterns, parent -> child).
"""
from pathlib import Path

from lxml import etree

from ..graph import Graph
from .xmlutil import text

NS = {"c": "http://capec.mitre.org/capec-3"}
SKIP_STATUS = {"Deprecated", "Obsolete"}


def parse_capec(path: Path, g: Graph, attack_revoked: dict[str, str] | None = None) -> str:
    """Populate g from the CAPEC XML. `attack_revoked` maps revoked ATT&CK ids to their
    replacements so stale CAPEC->ATT&CK mappings still land on a live technique."""
    attack_revoked = attack_revoked or {}
    root = etree.parse(str(path)).getroot()
    version = root.get("Version")
    src = f"capec-{version}"

    for ap in root.iterfind("c:Attack_Patterns/c:Attack_Pattern", NS):
        if ap.get("Status") in SKIP_STATUS:
            continue
        capec = f"CAPEC-{ap.get('ID')}"
        g.add_node("AttackPattern", capec, src,
                   name=ap.get("Name"), abstraction=ap.get("Abstraction"), status=ap.get("Status"),
                   description=text(ap.find("c:Description", NS)),
                   likelihood_of_attack=text(ap.find("c:Likelihood_Of_Attack", NS)),
                   typical_severity=text(ap.find("c:Typical_Severity", NS)))

        for rw in ap.iterfind("c:Related_Weaknesses/c:Related_Weakness", NS):
            g.add_edge("CAUSES_WEAKNESS", "Weakness", f"CWE-{rw.get('CWE_ID')}", "AttackPattern", capec, src)

        for rel in ap.iterfind("c:Related_Attack_Patterns/c:Related_Attack_Pattern", NS):
            if rel.get("Nature") == "ChildOf":
                g.add_edge("IS_PARENT", "AttackPattern", f"CAPEC-{rel.get('CAPEC_ID')}",
                           "AttackPattern", capec, src)

        for tm in ap.iterfind("c:Taxonomy_Mappings/c:Taxonomy_Mapping", NS):
            if tm.get("Taxonomy_Name") != "ATTACK":
                continue
            entry = text(tm.find("c:Entry_ID", NS))
            if not entry:
                continue
            tid = entry if entry.startswith("T") else f"T{entry}"
            replaced = attack_revoked.get(tid)
            g.add_edge("USES_TECHNIQUE", "AttackPattern", capec, "Technique", replaced or tid, src,
                       mapped_from=tid if replaced else None)

    return version
