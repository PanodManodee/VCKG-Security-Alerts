"""Debian package version comparison (dpkg's algorithm), for distro security data (osv.py).

Distribution versions carry an epoch, the upstream version and a Debian revision:
    2:4.17.12+dfsg-0+deb12u4   = epoch 2, upstream 4.17.12+dfsg, revision 0+deb12u4
A backported fix only changes the revision (deb12u3 -> deb12u4), so upstream comparison
(versions.py) cannot see it; this module can.

Follows dpkg's verrevcmp (lib/dpkg/version.c): '~' sorts before everything, even the end of
the string; letters sort before other characters; digit runs compare numerically.
"""


def _order(c: str) -> int:
    if c == "~":
        return -1
    if c == "" or c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i] if i < len(a) else "")
            bc = _order(b[j] if j < len(b) else "")
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def parse(version: str) -> tuple[int, str, str]:
    """'2:4.17.12+dfsg-0+deb12u4' -> (2, '4.17.12+dfsg', '0+deb12u4')."""
    v = version.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    upstream, revision = (v.rsplit("-", 1) if "-" in v else (v, ""))
    return epoch, upstream, revision


def compare(a: str, b: str) -> int:
    """<0 if a < b, 0 if equal, >0 if a > b (dpkg --compare-versions)."""
    ea, ua, ra = parse(a)
    eb, ub, rb = parse(b)
    if ea != eb:
        return ea - eb
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)
