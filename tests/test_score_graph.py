"""Stage 4 scores on the loaded lab graph. Needs Neo4j (CTI + asset graph) and data/raw/epss; skips otherwise."""
import pytest

from score_kg import config


@pytest.fixture(scope="module")
def scored():
    if not config.EPSS_CSV.exists():
        pytest.skip("no EPSS data (python -m score_kg epss-download)")
    from score_kg import epss
    from score_kg.run import graph_data, score_vulns
    try:
        assets, g, vulns, _ = graph_data(wait=5)
    except SystemExit:
        pytest.skip("Neo4j is not reachable")
    if not vulns:
        pytest.skip("asset graph not linked (python -m asset_kg all)")
    _, scores = epss.load()
    rows = score_vulns(assets, g, vulns, scores, (1, 1, 1))
    return assets, {(r["asset"], r["cve"]): r for r in rows}


def test_kev_cve_on_jenkins_is_exploited_and_act(scored):
    _, rows = scored
    r = rows[("Jenkins", "CVE-2024-23897")]
    assert r["E"] == "H" and r["kev"] and r["ssvc"] == "Act"
    assert r["R"] >= r["s_env"]


def test_low_value_unexposed_host_is_demoted(scored):
    _, rows = scored
    dep = [r for (asset, _), r in rows.items() if asset == "Dep-PC"]
    assert dep and all(r["s_env"] < r["cvss_base"] for r in dep if r["E"] != "X")


def test_internet_exposed_hosts_keep_network_attack_vector(scored):
    assets, rows = scored
    assert assets["Web"]["internet_exposed"] and assets["Nginx"]["internet_exposed"]
    for (asset, _), r in rows.items():
        if asset in ("Web", "Nginx") and "/AV:N/" in r["env_vector"]:
            assert r["MAV"] == "N"
        if asset in ("PostgreSQL", "Jenkins"):
            assert r["MAV"] != "N"
