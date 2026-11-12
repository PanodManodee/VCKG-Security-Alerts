"""Part B ground truth, measured in the running lab (never read from lab/*.csv):

    measure-reach   from every host, TCP connect to every other host's ports        -> network reachability
    measure-usable  on every host, find stored targets/credentials and try them     -> usable reach (compromise)
    measure-deps    stop one host at a time, see which other hosts' health checks fail -> dependents (disruption)
"""
import csv
import json
import subprocess
import time
from datetime import datetime, timezone

from . import config


def compose(*args, input_text=None, timeout=120) -> subprocess.CompletedProcess:
    # stdin goes as bytes: in text mode Windows would turn "\n" into "\r\n" and break scripts piped to bash -s
    proc = subprocess.run(["docker", "compose", "-f", str(config.LAB_COMPOSE), *args],
                          input=input_text.encode("utf-8") if input_text is not None else None,
                          capture_output=True, timeout=timeout)
    proc.stdout = proc.stdout.decode("utf-8", errors="replace").replace("\r\n", "\n")
    proc.stderr = proc.stderr.decode("utf-8", errors="replace").replace("\r\n", "\n")
    return proc


def exec_sh(service: str, command: str, timeout=120) -> subprocess.CompletedProcess:
    return compose("exec", "-T", service, "sh", "-c", command, timeout=timeout)


def host_ips() -> dict:
    """asset -> lab IP, read from the running containers (docker inspect)."""
    out = {}
    for asset, svc in config.SERVICES.items():
        cid = compose("ps", "-q", svc).stdout.strip()
        if not cid:
            raise SystemExit(f"lab service {svc} is not running (cd lab_env && docker compose up -d)")
        ips = subprocess.run(["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
                              cid], capture_output=True, text=True).stdout.split()
        out[asset] = ips[0]
    return out


def _meta() -> dict:
    images = {}
    for asset, svc in config.SERVICES.items():
        cid = compose("ps", "-q", svc).stdout.strip()
        images[asset] = subprocess.run(["docker", "inspect", "-f", "{{.Image}}", cid],
                                       capture_output=True, text=True).stdout.strip()[:19] if cid else None
    return {"measured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "images": images}


def _save(path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"-> {path}")


def measure_reach() -> dict:
    ips = host_ips()
    result = {}
    for asset, svc in config.SERVICES.items():
        targets = " ".join(f"{ip}:{p}" for other, ip in ips.items() if other != asset for p in config.PROBE_PORTS)
        script = ('for t in ' + targets + '; do h=${t%:*}; p=${t#*:}; '
                  'timeout 2 bash -c "</dev/tcp/$h/$p" 2>/dev/null && echo "$h $p"; done; true')
        open_ports = [ln.split() for ln in exec_sh(svc, script, timeout=600).stdout.splitlines() if ln.strip()]
        by_ip = {ip: a for a, ip in ips.items()}
        reached = sorted({by_ip[h] for h, _ in open_ports if h in by_ip})
        result[asset] = {"reachable": reached, "open": sorted(f"{by_ip.get(h, h)}:{p}" for h, p in open_ports)}
        print(f"  {asset:<11} reaches {', '.join(reached) or '-'}")
    data = {**_meta(), "method": "TCP connect from each host to every other host on ports "
            + ",".join(map(str, config.PROBE_PORTS)), "hosts": result}
    _save(config.OBSERVED_NETWORK, data)
    return data


def measure_usable() -> dict:
    ips = host_ips()
    script = config.HARVEST_SH.read_text(encoding="utf-8").replace("\r\n", "\n")
    by_ip = {ip: a for a, ip in ips.items()}
    result = {}
    for asset, svc in config.SERVICES.items():
        proc = compose("exec", "-T", svc, "bash", "-s", "--", *ips.values(), input_text=script, timeout=300)
        attempts = [ln.split(" ", 3) for ln in proc.stdout.splitlines() if ln.count(" ") >= 2]
        ok = sorted({by_ip[a[0]] for a in attempts if len(a) >= 3 and a[2] == "ok" and a[0] in by_ip})
        result[asset] = {"usable": ok, "attempts": [" ".join(a) for a in attempts]}
        print(f"  {asset:<11} can use {', '.join(ok) or '-'}")
    data = {**_meta(), "method": "lab_env/eval/harvest.sh: stored targets and credentials found on the host, "
            "tried with a harmless authenticated access", "hosts": result}
    _save(config.OBSERVED_USABLE, data)
    return data


def load_checks() -> list[dict]:
    with open(config.CHECKS_CSV, newline="", encoding="utf-8") as fh:
        rows = (ln for ln in fh if ln.strip() and not ln.lstrip().startswith("#"))
        return list(csv.DictReader(rows))


def run_check(check: dict) -> bool:
    try:
        return exec_sh(check["service"], check["command"], timeout=90).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def wait_healthy(checks: list[dict], timeout: int = 240) -> list[str]:
    """Wait until every check passes; returns the assets still failing at the timeout."""
    deadline = time.time() + timeout
    failing = [c["asset"] for c in checks if not run_check(c)]
    while failing and time.time() < deadline:
        time.sleep(5)
        failing = [c["asset"] for c in checks if c["asset"] in failing and not run_check(c)]
    return failing


def measure_deps() -> dict:
    checks = load_checks()
    print("  baseline: all health checks must pass")
    failing = wait_healthy(checks)
    if failing:
        raise SystemExit(f"health checks failing before the experiment: {failing} (fix the lab first)")
    result = {}
    for target in checks:
        svc = target["service"]
        compose("stop", svc, timeout=180)
        time.sleep(3)
        failed = sorted(c["asset"] for c in checks if c["asset"] != target["asset"] and not run_check(c))
        compose("start", svc, timeout=180)
        still = wait_healthy(checks)
        result[target["asset"]] = {"dependents": failed, "recovered": not still}
        print(f"  stop {target['asset']:<11} -> fails: {', '.join(failed) or '-'}"
              + ("" if not still else f"   (not recovered: {still})"))
    data = {**_meta(), "method": "stop one host (docker compose stop), run every other host's health check "
            "(lab_env/eval/checks.csv), start it again", "hosts": result}
    _save(config.OBSERVED_DEPENDENTS, data)
    return data
