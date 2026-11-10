"""Offline tests for distro package versions (dpkg order) and OSV ranges (the backport fix)."""
from asset_kg.dpkg import compare, parse
from asset_kg.osv import affected_cves, in_range


def sign(x: int) -> int:
    return (x > 0) - (x < 0)


# Each pair was checked against `dpkg --compare-versions` in a Debian 12 container.
DPKG_PAIRS = [
    ("2:4.17.12+dfsg-0+deb12u4", "2:4.17.12+dfsg-0+deb12u3", 1),   # backported fix = newer revision
    ("1:8.9p1-3", "1:8.9p1-3ubuntu0.10", -1),
    ("2.36-9+deb12u3", "2.36-9+deb12u10", -1),                      # numeric, not text, order
    ("1.0~rc1", "1.0", -1),                                          # ~ sorts before the end
    ("1.0~~", "1.0~", -1),
    ("1.0", "1.0-0", 0),
    ("1:2.0", "3.0", 1),                                             # epoch wins
    ("0", "1:0", -1),
    ("1.25.3-1~bookworm", "1.25.3-1", -1),
    ("1.0a", "1.0+", -1),                                            # letters before other characters
]


def test_dpkg_order_matches_dpkg():
    for a, b, expected in DPKG_PAIRS:
        assert sign(compare(a, b)) == expected, (a, b)
        assert sign(compare(b, a)) == -expected, (b, a)


def test_parse_epoch_upstream_revision():
    assert parse("2:4.17.12+dfsg-0+deb12u4") == (2, "4.17.12+dfsg", "0+deb12u4")
    assert parse("1.2.3") == (0, "1.2.3", "")


def test_osv_range_fixed_and_unfixed():
    fixed = [{"introduced": "0"}, {"fixed": "2:4.17.12+dfsg-0+deb12u2"}]
    assert not in_range("2:4.17.12+dfsg-0+deb12u4", fixed)     # backport already applied
    assert in_range("2:4.17.12+dfsg-0+deb12u1", fixed)
    assert in_range("1:8.9p1-3", [{"introduced": "0"}])        # no fix released yet
    assert not in_range("1.0", [{"introduced": "2.0"}, {"fixed": "2.5"}])
    assert not in_range("3.1", [{"introduced": "0"}, {"last_affected": "3.0"}])


def test_affected_cves_reports_fixed_version():
    index = {"samba": [["CVE-2024-0001", [[{"introduced": "0"}, {"fixed": "2:4.17.12+dfsg-0+deb12u2"}]], []],
                       ["CVE-2024-0002", [[{"introduced": "0"}, {"fixed": "2:4.17.12+dfsg-0+deb12u9"}]], []],
                       ["CVE-2024-0003", [[{"introduced": "0"}]], []],
                       ["CVE-2024-0004", [], ["2:4.17.12+dfsg-0+deb12u4"]]]}
    got = affected_cves(index, "samba", "2:4.17.12+dfsg-0+deb12u4")
    assert got == {"CVE-2024-0002": "2:4.17.12+dfsg-0+deb12u9", "CVE-2024-0003": None, "CVE-2024-0004": None}
    assert affected_cves(index, "openssh", "1:8.9p1-3") == {}
