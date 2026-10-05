"""CWE catalog -> Weakness, Mitigation, DetectionMethod, Platform nodes and their edges.

Edges produced: IS_PARENT (ChildOf, parent -> child), MITIGATED_BY, DETECTED_BY, AFFECTS,
CAUSES_WEAKNESS (from Related_Attack_Patterns) and EXPLOITED_BY (from Observed_Examples).

Deprecated weaknesses are kept (with their status), as NVD still references some of them.
CWE Categories become Weakness nodes with abstraction="Category" because NVD assigns
categories (e.g. CWE-264, CWE-310) to CVEs; their Has_Member lists are not turned into
IS_PARENT edges, since they mix taxonomy groupings (OWASP, CERT, 7PK) into the hierarchy.
"""
from pathlib import Path

from lxml import etree

from ..graph import Graph
from .xmlutil import local, text, text_hash

NS = {"c": "http://cwe.mitre.org/cwe-7"}
PLATFORM_KINDS = {"Language": "language", "Technology": "technology",
                  "Operating_System": "operating_system", "Architecture": "architecture"}


def find_cwe_xml(raw_dir: Path) -> Path:
    files = sorted(raw_dir.glob("cwec_v*.xml"))
    if not files:
        raise FileNotFoundError(f"no cwec_v*.xml in {raw_dir}; run `download` first")
    return files[-1]


def parse_cwe(path: Path, g: Graph) -> str:
    """Populate g from the CWE XML. Returns the catalog version (e.g. '4.20')."""
    root = etree.parse(str(path)).getroot()
    version = root.get("Version")
    src = f"cwe-{version}"

    for c in root.iterfind("c:Categories/c:Category", NS):
        g.add_node("Weakness", f"CWE-{c.get('ID')}", src, name=c.get("Name"), abstraction="Category",
                   status=c.get("Status"), description=text(c.find("c:Summary", NS)))

    for w in root.iterfind("c:Weaknesses/c:Weakness", NS):
        cwe = f"CWE-{w.get('ID')}"
        scopes, impacts = set(), set()
        for cons in w.iterfind("c:Common_Consequences/c:Consequence", NS):
            scopes.update(s.text for s in cons.iterfind("c:Scope", NS))
            impacts.update(i.text for i in cons.iterfind("c:Impact", NS))
        g.add_node("Weakness", cwe, src,
                   name=w.get("Name"), abstraction=w.get("Abstraction"), status=w.get("Status"),
                   description=text(w.find("c:Description", NS)),
                   likelihood_of_exploit=text(w.find("c:Likelihood_Of_Exploit", NS)),
                   consequence_scopes=scopes, consequence_impacts=impacts)

        for rel in w.iterfind("c:Related_Weaknesses/c:Related_Weakness", NS):
            if rel.get("Nature") == "ChildOf":
                g.add_edge("IS_PARENT", "Weakness", f"CWE-{rel.get('CWE_ID')}", "Weakness", cwe, src)

        for plat in w.iterfind("c:Applicable_Platforms/*", NS):
            name = plat.get("Name") or plat.get("Class")
            if not name:
                continue
            g.add_node("Platform", name, src, kind=PLATFORM_KINDS.get(local(plat.tag)))
            g.add_edge("AFFECTS", "Weakness", cwe, "Platform", name, src,
                       prevalence=plat.get("Prevalence"))

        for m in w.iterfind("c:Potential_Mitigations/c:Mitigation", NS):
            desc = text(m.find("c:Description", NS))
            if not desc:
                continue
            mit_id = m.get("Mitigation_ID") or f"CWE-MIT-{text_hash(desc)}"
            strategy = text(m.find("c:Strategy", NS))
            g.add_node("Mitigation", mit_id, src, name=strategy or desc[:80], description=desc,
                       strategy=strategy, phases={p.text for p in m.iterfind("c:Phase", NS)},
                       origin="CWE")
            g.add_edge("MITIGATED_BY", "Weakness", cwe, "Mitigation", mit_id, src,
                       effectiveness=text(m.find("c:Effectiveness", NS)))

        for d in w.iterfind("c:Detection_Methods/c:Detection_Method", NS):
            method = text(d.find("c:Method", NS))
            if not method:
                continue
            g.add_node("DetectionMethod", method, src)
            g.add_edge("DETECTED_BY", "Weakness", cwe, "DetectionMethod", method, src,
                       effectiveness=text(d.find("c:Effectiveness", NS)))

        for ap in w.iterfind("c:Related_Attack_Patterns/c:Related_Attack_Pattern", NS):
            g.add_edge("CAUSES_WEAKNESS", "Weakness", cwe, "AttackPattern", f"CAPEC-{ap.get('CAPEC_ID')}", src)

        for ex in w.iterfind("c:Observed_Examples/c:Observed_Example", NS):
            ref = text(ex.find("c:Reference", NS))
            if ref.startswith("CVE-"):
                g.add_edge("EXPLOITED_BY", "Weakness", cwe, "Vulnerability", ref, f"{src}-observed-example")

    return version
