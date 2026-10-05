"""HTTP fetch with conditional requests, and the raw-data manifest (provenance)."""
import json
from datetime import datetime, timezone
from pathlib import Path

import requests
from tqdm import tqdm

from .. import config


def read_manifest() -> dict:
    if config.MANIFEST.exists():
        return json.loads(config.MANIFEST.read_text())
    return {}


def update_manifest(name: str, **info) -> None:
    m = read_manifest()
    m[name] = {**m.get(name, {}), **info}
    config.MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    config.MANIFEST.write_text(json.dumps(m, indent=2, sort_keys=True))


def fetch(url: str, dest: Path, name: str, force: bool = False) -> bool:
    """Download url to dest unless the server says it is unchanged. Returns True if downloaded."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    prev = read_manifest().get(name, {})
    headers = {}
    if dest.exists() and not force:
        if prev.get("etag"):
            headers["If-None-Match"] = prev["etag"]
        if prev.get("last_modified"):
            headers["If-Modified-Since"] = prev["last_modified"]
    with requests.get(url, headers=headers, stream=True, timeout=60) as r:
        if r.status_code == 304:
            print(f"  {name}: unchanged")
            return False
        r.raise_for_status()
        tmp = dest.with_suffix(dest.suffix + ".part")
        total = int(r.headers.get("Content-Length", 0)) or None
        with open(tmp, "wb") as fh, tqdm(total=total, unit="B", unit_scale=True, desc=name, leave=False) as bar:
            for chunk in r.iter_content(1 << 20):
                fh.write(chunk)
                bar.update(len(chunk))
        tmp.replace(dest)
        update_manifest(name, url=url, file=str(dest.relative_to(config.ROOT)),
                        etag=r.headers.get("ETag"), last_modified=r.headers.get("Last-Modified"),
                        downloaded_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    print(f"  {name}: downloaded")
    return True
