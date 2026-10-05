"""MITRE ATT&CK (enterprise STIX bundle) -> Technique, Tactic, Group, Mitigation nodes.

Edges produced: IMPLEMENTS (technique -> tactic via kill-chain phase), SUBTECHNIQUE_OF,
USES_TECHNIQUE (group -> technique), MITIGATED_BY (technique -> mitigation) and
AFFECTS (technique -> platform, from x_mitre_platforms).
"""
import json
from pathlib import Path

from mitreattack.stix20 import MitreAttackData

from ..graph import Graph


def _attack_id(obj) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def revoked_technique_map(path: Path) -> dict[str, str]:
    """Revoked technique id -> id of the technique that replaced it (follows chains)."""
    objects = json.loads(path.read_text())["objects"]
    ids = {o["id"]: _attack_id(o) for o in objects if o["type"] == "attack-pattern"}
    nxt = {o["source_ref"]: o["target_ref"] for o in objects
           if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by"
           and o["source_ref"] in ids}
    out = {}
    for stix_id in nxt:
        target, seen = stix_id, set()
        while target in nxt and target not in seen:
            seen.add(target)
            target = nxt[target]
        if ids.get(stix_id) and ids.get(target):
            out[ids[stix_id]] = ids[target]
    return out


def parse_attack(path: Path, g: Graph) -> str:
    """Populate g from enterprise-attack.json. Returns the ATT&CK release version."""
    data = MitreAttackData(str(path))
    collection = next((o for o in json.loads(path.read_text())["objects"]
                       if o["type"] == "x-mitre-collection"), {})
    version = collection.get("x_mitre_version", "unknown")
    src = f"attack-{version}"

    tactic_by_shortname = {}
    for t in data.get_tactics(remove_revoked_deprecated=True):
        tid = _attack_id(t)
        tactic_by_shortname[t["x_mitre_shortname"]] = tid
        g.add_node("Tactic", tid, src, name=t["name"], shortname=t["x_mitre_shortname"],
                   description=t.get("description"), stix_id=t["id"])

    stix_to_tech = {}
    for t in data.get_techniques(remove_revoked_deprecated=True):
        tid = _attack_id(t)
        stix_to_tech[t["id"]] = tid
        platforms = list(t.get("x_mitre_platforms", []))
        g.add_node("Technique", tid, src, name=t["name"], description=t.get("description"),
                   is_subtechnique=bool(t.get("x_mitre_is_subtechnique")),
                   x_mitre_platforms=platforms, stix_id=t["id"])
        for phase in t.get("kill_chain_phases", []):
            if phase["kill_chain_name"] == "mitre-attack" and phase["phase_name"] in tactic_by_shortname:
                g.add_edge("IMPLEMENTS", "Technique", tid, "Tactic", tactic_by_shortname[phase["phase_name"]], src)
        for p in platforms:
            g.add_node("Platform", p, src, kind="attack_platform")
            g.add_edge("AFFECTS", "Technique", tid, "Platform", p, src)

    for parent_id, subs in data.get_all_subtechniques_of_all_techniques().items():
        parent = stix_to_tech.get(parent_id)
        for s in subs:
            child = stix_to_tech.get(s["object"]["id"])
            if parent and child:
                g.add_edge("SUBTECHNIQUE_OF", "Technique", child, "Technique", parent, src)

    stix_to_group = {}
    for grp in data.get_groups(remove_revoked_deprecated=True):
        gid = _attack_id(grp)
        stix_to_group[grp["id"]] = gid
        g.add_node("Group", gid, src, name=grp["name"], aliases=list(grp.get("aliases", [])),
                   description=grp.get("description"), stix_id=grp["id"])
    for grp_id, used in data.get_all_techniques_used_by_all_groups().items():
        gid = stix_to_group.get(grp_id)
        for u in used:
            tid = stix_to_tech.get(u["object"]["id"])
            if gid and tid:
                g.add_edge("USES_TECHNIQUE", "Group", gid, "Technique", tid, src)

    stix_to_mit = {}
    for m in data.get_mitigations(remove_revoked_deprecated=True):
        mid = _attack_id(m)
        stix_to_mit[m["id"]] = mid
        g.add_node("Mitigation", mid, src, name=m["name"], description=m.get("description"),
                   origin="ATT&CK", stix_id=m["id"])
    for mit_id, techs in data.get_all_techniques_mitigated_by_all_mitigations().items():
        mid = stix_to_mit.get(mit_id)
        for u in techs:
            tid = stix_to_tech.get(u["object"]["id"])
            if mid and tid:
                g.add_edge("MITIGATED_BY", "Technique", tid, "Mitigation", mid, src)

    return version
