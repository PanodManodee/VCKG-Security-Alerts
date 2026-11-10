"""Parser tests on trimmed real records, centred on the paper's Fig. 5 chain:
CWE-732 -> CAPEC-1 -> T1574.010, plus CVE-2024-21732 (CWE-79, NVD CPE + CVSS)."""
import json
from pathlib import Path

import pytest

from cti_kg.align.resolve import merge_node
from cti_kg.graph import Graph
from cti_kg.parse.attack import parse_attack, revoked_technique_map
from cti_kg.parse.capec import parse_capec
from cti_kg.parse.cve import add_cve, parse_cpe
from cti_kg.parse.cwe import parse_cwe

FX = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def g():
    g = Graph()
    parse_attack(FX / "attack_sample.json", g)
    parse_cwe(FX / "cwe_sample.xml", g)
    parse_capec(FX / "capec_sample.xml", g, revoked_technique_map(FX / "attack_sample.json"))
    return g


def has_edge(g, etype, sl, s, dl, d):
    return (etype, sl, s, dl, d) in g.edges


def test_weakness_nodes(g):
    w = g.nodes[("Weakness", "CWE-732")]
    assert w["name"] == "Incorrect Permission Assignment for Critical Resource"
    assert w["abstraction"] == "Class"
    assert "Access Control" in w["consequence_scopes"]


def test_cwe_hierarchy_parent_to_child(g):
    assert has_edge(g, "IS_PARENT", "Weakness", "CWE-285", "Weakness", "CWE-732")


def test_fig5_chain(g):
    assert has_edge(g, "CAUSES_WEAKNESS", "Weakness", "CWE-732", "AttackPattern", "CAPEC-1")
    assert has_edge(g, "USES_TECHNIQUE", "AttackPattern", "CAPEC-1", "Technique", "T1574.010")
    assert has_edge(g, "SUBTECHNIQUE_OF", "Technique", "T1574.010", "Technique", "T1574")
    tactics = {d for (t, sl, s, dl, d) in g.edges if t == "IMPLEMENTS" and s == "T1574.010"}
    assert tactics == {"TA0002", "TA0005"}  # as of the ATT&CK release frozen in the fixture


def test_causes_weakness_asserted_by_both_catalogs(g):
    srcs = g.edges[("CAUSES_WEAKNESS", "Weakness", "CWE-732", "AttackPattern", "CAPEC-1")]["sources"]
    assert any(s.startswith("cwe-") for s in srcs) and any(s.startswith("capec-") for s in srcs)


def test_mitigation_detection_platform(g):
    mits = [d for (t, sl, s, dl, d) in g.edges if t == "MITIGATED_BY" and s == "CWE-732"]
    assert mits and all(g.has_node("Mitigation", m) for m in mits)
    assert has_edge(g, "DETECTED_BY", "Weakness", "CWE-732", "DetectionMethod", "Automated Static Analysis")
    assert has_edge(g, "AFFECTS", "Weakness", "CWE-732", "Platform", "Cloud Computing")


def test_observed_example_edges(g):
    assert has_edge(g, "EXPLOITED_BY", "Weakness", "CWE-732", "Vulnerability", "CVE-2022-29527")


def test_attack_mitigation_and_revoked_map():
    revoked = revoked_technique_map(FX / "attack_sample.json")
    assert revoked.get("T1044") == "T1574.010"
    g = Graph()
    parse_attack(FX / "attack_sample.json", g)
    assert any(t == "MITIGATED_BY" and sl == "Technique" for (t, sl, *_ ) in g.edges)


def test_cve_merge_cvelist_and_nvd():
    g = Graph()
    rec = json.loads((FX / "cvelist_CVE-2024-21732.json").read_text(encoding="utf-8"))
    nvd = json.loads((FX / "nvd_CVE-2024-21732.json").read_text(encoding="utf-8"))
    add_cve(g, "CVE-2024-21732", rec, nvd)
    v = g.nodes[("Vulnerability", "CVE-2024-21732")]
    assert v["sources"] == {"cvelistV5", "nvd"}
    assert v["cvss3_score"] == 6.1 and v["cvss3_source"] == "nvd-primary"
    assert v["ssvc_exploitation"] == "poc"
    edge = g.edges[("EXPLOITED_BY", "Weakness", "CWE-79", "Vulnerability", "CVE-2024-21732")]
    assert {"nvd", "cisa-adp"} <= edge["sources"]
    cpe = "cpe:2.3:a:flycms_project:flycms:*:*:*:*:*:*:*:*"
    assert g.edges[("VULNERABLE_TO", "CPE", cpe, "Vulnerability", "CVE-2024-21732")]["version_ranges"] == {"(,2019-12-20]"}
    assert g.nodes[("CPE", cpe)]["vendor"] == "flycms_project"


def test_several_ranges_for_one_cpe_are_all_kept():
    """NVD lists the same wildcard CPE once per affected branch (e.g. CVE-2024-7348, PostgreSQL 12-16).
    They used to collapse into one edge whose bounds overwrote each other."""
    cpe = "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"
    nvd = {"id": "CVE-2024-7348", "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": cpe, "versionStartIncluding": "12.0", "versionEndExcluding": "12.20"},
        {"vulnerable": True, "criteria": cpe, "versionStartIncluding": "15.0", "versionEndExcluding": "15.8"},
        {"vulnerable": True, "criteria": cpe, "versionStartIncluding": "16.0", "versionEndExcluding": "16.4"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:postgresql:postgresql:11.0:*:*:*:*:*:*:*"},
    ]}]}]}
    g = Graph()
    add_cve(g, "CVE-2024-7348", None, nvd)
    edge = g.edges[("VULNERABLE_TO", "CPE", cpe, "Vulnerability", "CVE-2024-7348")]
    assert edge["version_ranges"] == {"[12.0,12.20)", "[15.0,15.8)", "[16.0,16.4)"}
    concrete = g.edges[("VULNERABLE_TO", "CPE", "cpe:2.3:a:postgresql:postgresql:11.0:*:*:*:*:*:*:*",
                        "Vulnerability", "CVE-2024-7348")]
    assert "version_ranges" not in concrete      # a concrete CPE version needs no range


def test_parse_cpe_escaped_colon():
    p = parse_cpe(r"cpe:2.3:a:foo:bar\:baz:1.0:*:*:*:*:*:*:*")
    assert p == {"part": "a", "vendor": "foo", "product": r"bar\:baz", "version": "1.0"}


def test_merge_node_repoints_edges():
    g = Graph()
    g.add_node("Platform", "Windows NT", "x")
    g.add_node("Platform", "Windows", "y")
    g.add_node("Weakness", "CWE-1", "x")
    g.add_edge("AFFECTS", "Weakness", "CWE-1", "Platform", "Windows NT", "x")
    merge_node(g, "Platform", "Windows NT", "Windows")
    assert not g.has_node("Platform", "Windows NT")
    assert g.nodes[("Platform", "Windows")]["merged_from"] == ["Windows NT"]
    assert ("AFFECTS", "Weakness", "CWE-1", "Platform", "Windows") in g.edges


def test_save_load_roundtrip(g, tmp_path):
    g.save(tmp_path)
    g2 = Graph.load(tmp_path)
    assert g2.node_counts() == g.node_counts()
    assert g2.edge_counts() == g.edge_counts()
