"""Offline tests for the version comparison used when linking software to CVEs (no Neo4j needed)."""
from asset_kg.versions import compare, cpe_applies, in_range, parse_interval


def test_numeric_order_is_not_text_order():
    assert compare("10.0", "9.0") > 0
    assert compare("1.18.0", "1.2.0") > 0


def test_trailing_zeros_and_suffixes():
    assert compare("1.0", "1.0.0") == 0
    assert compare("1.0", "1.0rc1") > 0      # release is newer than its release candidate
    assert compare("2.4.1", "2.4.10") < 0


def test_range_bounds_follow_nvd_semantics():
    assert in_range("15.4", start_incl="15.0", end_excl="15.5")
    assert not in_range("15.5", start_incl="15.0", end_excl="15.5")
    assert not in_range("14.9", start_incl="15.0")
    assert in_range("15.5", end_incl="15.5")
    assert not in_range("15.0", start_excl="15.0")


def test_wildcard_cpe_uses_edge_range():
    edge = {"version_start_including": "1.0.0", "version_end_excluding": "1.20.2"}
    assert cpe_applies("1.18.0", "*", edge)
    assert not cpe_applies("1.20.2", "*", edge)


def test_interval_strings_round_trip():
    assert parse_interval("[12.0,12.20)") == {"start_incl": "12.0", "start_excl": None,
                                              "end_incl": None, "end_excl": "12.20"}
    assert parse_interval("(,4.4)") == {"start_incl": None, "start_excl": None, "end_incl": None, "end_excl": "4.4"}
    assert parse_interval("(,)") == {"start_incl": None, "start_excl": None, "end_incl": None, "end_excl": None}


def test_version_in_any_of_several_ranges():
    edge = {"version_ranges": ["[12.0,12.20)", "[15.0,15.8)", "[16.0,16.4)"]}   # CVE-2024-7348
    assert cpe_applies("15.5", "*", edge)
    assert cpe_applies("12.3", "*", edge)
    assert not cpe_applies("15.8", "*", edge)
    assert not cpe_applies("14.1", "*", edge)


def test_openssh_regresshion_ranges():
    edge = {"version_ranges": ["(,4.4)", "[8.6,9.8]"]}                         # CVE-2024-6387
    assert cpe_applies("8.9p1", "*", edge)
    assert not cpe_applies("8.0p1", "*", edge)
    assert cpe_applies("4.3", "*", edge)


def test_wildcard_without_bounds_matches_every_version():
    assert cpe_applies("3.4.5", "*", {})


def test_concrete_cpe_needs_equal_version():
    assert cpe_applies("15.4", "15.4", {})
    assert not cpe_applies("15.4", "15.3", {})


def test_dash_is_not_a_wildcard():
    assert not cpe_applies("1.0", "-", {})
