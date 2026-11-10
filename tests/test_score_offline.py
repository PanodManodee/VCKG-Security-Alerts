"""Offline tests for stage 4 scoring (no Neo4j, no network)."""
from score_kg import cvss31, model, ssvc
from score_kg.epss import parse
from score_kg.run import kendall_tau

FULL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_environmental_scores_match_the_first_calculator():
    # values checked by hand against the CVSS v3.1 specification formulas
    assert cvss31.environmental(FULL, "X", "M", "M", "M", "N")["environmental"] == 9.8
    assert cvss31.environmental(FULL, "U", "M", "M", "M", "N")["environmental"] == 9.0      # 9.8 x 0.91 rounded up
    assert cvss31.environmental(FULL, "U", "L", "L", "L", "A")["environmental"] == 6.3
    assert cvss31.environmental(FULL, "H", "H", "H", "H", "N")["environmental"] == 9.8


def test_exploit_maturity_mapping():
    assert cvss31.exploit_maturity(True, "none") == "H"          # KEV wins
    assert cvss31.exploit_maturity(False, "active") == "H"
    assert cvss31.exploit_maturity(False, "PoC ") == "P"
    assert cvss31.exploit_maturity(False, "none") == "U"
    assert cvss31.exploit_maturity(False, None) == "X"


def test_mav_never_raises_exposure():
    local = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    assert cvss31.modified_av(local, internet_exposed=True, reached_by_assets=True) == "L"
    assert cvss31.modified_av(FULL, internet_exposed=True, reached_by_assets=True) == "N"
    assert cvss31.modified_av(FULL, internet_exposed=False, reached_by_assets=True) == "A"
    assert cvss31.modified_av(FULL, internet_exposed=False, reached_by_assets=False) == "L"


def test_bands():
    assert [cvss31.band(s) for s in (0.0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10.0)] == \
        ["None", "Low", "Low", "Medium", "Medium", "High", "High", "Critical", "Critical"]


def test_combine_is_anchored_at_the_environmental_score():
    assert model.combine(6.3, 0, 0, 0) == 6.3                 # no context evidence: standard score
    assert model.combine(6.3, 1, 1, 1) == 10.0                # all evidence: 10
    assert model.combine(6.0, 0.5, 0, 0, (1, 1, 1)) == round(6.0 + 4.0 * 0.5 / 3, 1)
    assert model.combine(6.0, 1, 1, 1, (1, 0, 0)) == 10.0     # only EPSS counts


def test_asset_value_and_blast_radius():
    assert model.asset_value("L", "L", "L") == 0.5 / 1.5
    assert model.asset_value("H", "L", "M") == 1.0
    assert model.blast_radius([(1.0, 1), (0.5, 2)], 2.0) == (1.0 + 0.25) / 2.0
    assert model.blast_radius([], 3.0) == 0.0


def test_ssvc_cisa_tree():
    assert ssvc.mission_prevalence("L", "L", "L") == "minimal"
    assert ssvc.mission_prevalence("M", "H", "L") == "essential"
    # active, yes, total: Attend / Act / Act
    assert ssvc.outcome("active", "yes", "total", False, FULL, "minimal") == "Attend"
    assert ssvc.outcome("active", "yes", "total", False, FULL, "essential") == "Act"
    assert ssvc.outcome("none", "no", "partial", False, FULL, "essential") == "Track"
    assert ssvc.outcome("none", "no", "partial", True, FULL, "essential") == "Attend"   # KEV -> active
    assert ssvc.outcome(None, None, None, False, FULL, "support") == "Track"           # fallbacks


def test_epss_csv_parsing():
    meta, scores = parse(["#model_version:v2026.06.15,score_date:2026-11-09T12:00:23Z\n",
                          "cve,epss,percentile\n", "CVE-2024-23897,0.99999,0.99995\n"])
    assert meta["model_version"] == "v2026.06.15"
    assert scores["CVE-2024-23897"] == (0.99999, 0.99995)


def test_kendall_tau():
    assert kendall_tau([1, 2, 3], [1, 2, 3]) == 1.0
    assert kendall_tau([1, 2, 3], [3, 2, 1]) == -1.0


def test_event_score_for_alerts_without_a_cve():
    # Wazuh level 5 -> 3.33; host H -> x1.5 = 5.0; uplift only from G (no EPSS, no extra alert evidence)
    ev = model.event_score(5, "H", "H", "L", 0.37, (1, 1, 1))
    assert ev["base"] == 3.3 and ev["weight"] == 1.5 and ev["s_event"] == 5.0
    assert ev["R"] == model.combine(5.0, 0, 0.37, 0, (1, 1, 1))
    # the same event on a low-value host scores lower, on a high-value one higher
    assert model.event_score(3, "L", "L", "L", 0.4)["R"] < model.event_score(3, "H", "M", "M", 0.4)["R"]
    assert model.event_score(15, "H", "H", "H", 1.0)["R"] == 10.0          # capped
    assert model.event_score(0, "M", "M", "M", 0.0)["R"] == 0.0
