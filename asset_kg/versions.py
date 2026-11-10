"""Version comparison and CPE applicability.

Neo4j cannot order versions ("10.0" sorts before "9.0" as text), so the range check runs here.
The comparator handles dotted numeric versions and simple suffixes (rc, beta). For Debian/rpm
version strings (epochs, ubuntu revisions) switch to the `univers` package.
"""
import re
from itertools import zip_longest

_TOKEN = re.compile(r"\d+|[A-Za-z]+")
_ZERO = (1, 0, "")   # padding: "1.0" == "1.0.0"


def _key(version: str) -> list:
    out = []
    for tok in _TOKEN.findall(version.lower()):
        out.append((1, int(tok), "") if tok.isdigit() else (0, 0, tok))   # number > letters: 1.0 > 1.0rc1
    return out


def compare(a: str, b: str) -> int:
    for x, y in zip_longest(_key(a), _key(b), fillvalue=_ZERO):
        if x != y:
            return -1 if x < y else 1
    return 0


def in_range(version: str, start_incl=None, start_excl=None, end_incl=None, end_excl=None) -> bool:
    """True if `version` lies inside every bound that is set (NVD cpeMatch semantics)."""
    if start_incl and compare(version, start_incl) < 0:
        return False
    if start_excl and compare(version, start_excl) <= 0:
        return False
    if end_incl and compare(version, end_incl) > 0:
        return False
    if end_excl and compare(version, end_excl) >= 0:
        return False
    return True


_INTERVAL = re.compile(r"^([\[(])([^,]*),([^\])]*)([\])])$")


def parse_interval(text: str) -> dict:
    """'[12.0,12.20)' -> in_range() keyword bounds (format written by cti_kg.parse.cve.version_interval)."""
    m = _INTERVAL.match(text.strip())
    if not m:
        raise ValueError(f"not a version interval: {text!r}")
    lo_bracket, lo, hi, hi_bracket = m.groups()
    return {"start_incl": lo if lo and lo_bracket == "[" else None,
            "start_excl": lo if lo and lo_bracket == "(" else None,
            "end_incl": hi if hi and hi_bracket == "]" else None,
            "end_excl": hi if hi and hi_bracket == ")" else None}


def cpe_applies(installed: str, cpe_version: str, edge: dict) -> bool:
    """Does a VULNERABLE_TO edge from a CPE node apply to the installed version?

    * CPE version '*'  -> the edge's `version_ranges` decide: the version must fall in at least one
                          of them ('(,)' or no ranges = every version).
    * CPE version '-'  -> "not applicable", never a wildcard.
    * concrete version -> must equal the installed version.
    """
    if cpe_version in (None, "", "*"):
        ranges = edge.get("version_ranges")
        if ranges:
            return any(in_range(installed, **parse_interval(r)) for r in ranges)
        return in_range(installed,     # graphs built before version_ranges: one range per edge
                        edge.get("version_start_including"), edge.get("version_start_excluding"),
                        edge.get("version_end_including"), edge.get("version_end_excluding"))
    if cpe_version == "-":
        return False
    return compare(installed, cpe_version) == 0
