"""Small helpers for the namespaced CWE / CAPEC XML catalogs."""
import hashlib
import re

_WS = re.compile(r"\s+")


def text(el) -> str:
    """All text inside an element (including xhtml children), whitespace-collapsed."""
    if el is None:
        return ""
    return _WS.sub(" ", "".join(el.itertext())).strip()


def norm_key(s: str) -> str:
    """Normalization used for text-identity (dedup) of free-text entities."""
    return _WS.sub(" ", re.sub(r"[^a-z0-9 ]", " ", s.lower())).strip()


def text_hash(s: str) -> str:
    return hashlib.sha1(norm_key(s).encode()).hexdigest()[:12]


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]
