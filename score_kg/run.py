"""Stage 4 commands: score asset x CVE pairs and alerts, write the threat report and the sensitivity analysis."""
import csv
import json
from collections import Counter, defaultdict
from datetime import date
from itertools import product

from asset_kg.db import driver

from . import config, epss, model
from .cvss31 import band

# ------------------------------------------------------------------------------------------- graph data
Q_ASSETS = """
MATCH (a:Asset)-[:IN_ZONE]->(z:Zone)
RETURN a.hostname AS hostname, a.role AS role, z.name AS zone, a.cr AS cr, a.ir AS ir, a.ar AS ar,
       coalesce(a.internet_exposed, false) AS internet_exposed,
       EXISTS { (b:Asset)-[:CAN_REACH]->(:Service)<-[:RUNS]-(a) WHERE b <> a } AS reached_by_assets
ORDER BY hostname
"""
Q_REACH = """
MATCH (a:Asset)
MATCH p = SHORTEST 1 (a) ((x)-[:CAN_REACH]->(:Service)<-[:RUNS]-(y)){1,%d} (b:Asset)
WHERE b <> a
RETURN a.hostname AS src, b.hostname AS dst, length(p) / 2 AS hops
""" % config.BLAST_HOPS
Q_VULNS = """
MATCH (a:Asset)-[:RUNS]->(:Service)-[:IMPLEMENTED_BY]->(sw:Software)-[h:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE v.cvss3_vector IS NOT NULL
RETURN DISTINCT a.hostname AS asset, sw.id AS software, h.via AS via, v.cve_id AS cve,
       v.cvss3_vector AS cvss3_vector, v.cvss3_score AS cvss3_score, v.kev_date_added IS NOT NULL AS kev,
       v.ssvc_exploitation AS ssvc_exploitation, v.ssvc_automatable AS ssvc_automatable,
       v.ssvc_technical_impact AS ssvc_technical_impact
ORDER BY asset, cve
"""
Q_SET_ALERT = """
UNWIND $rows AS r
MATCH (al:Alert {alert_id: r.alert_id})
SET al.event_score = r.event_score, al.event_band = r.event_band, al.event_basis = r.event_basis,
    al.host_risk = r.host_risk, al.host_band = r.host_band, al.host_top_cve = r.host_top_cve, al.ssvc = r.ssvc
REMOVE al.risk_score, al.risk_band, al.top_cve
"""


def graph_data(wait: int = 60) -> tuple[dict, dict, list[dict], int]:
    """assets by hostname, G by hostname, vulnerability rows, and how many pairs had no CVSS v3 vector."""
    with driver(wait) as drv, drv.session() as s:
        assets = {r["hostname"]: r for r in s.run(Q_ASSETS).data()}
        reach = s.run(Q_REACH).data()
        vulns = s.run(Q_VULNS).data()
        no_vector = s.run("MATCH (:Software)-[:HAS_VULNERABILITY]->(v) WHERE v.cvss3_vector IS NULL "
                          "RETURN count(DISTINCT v) AS n").single()["n"]
    values = {h: model.asset_value(a["cr"], a["ir"], a["ar"]) for h, a in assets.items()}
    by_src = defaultdict(list)
    for r in reach:
        by_src[r["src"]].append((values[r["dst"]], r["hops"]))
    total = sum(values.values())
    g = {h: model.blast_radius(by_src[h], total - values[h]) for h in assets}
    for h, a in assets.items():
        a["value"], a["G"], a["reaches"] = values[h], g[h], len(by_src[h])
    return assets, g, vulns, no_vector


# ------------------------------------------------------------------------------------------- scoring
def score_vulns(assets, g, vulns, scores, weights, alert_evidence=None) -> list[dict]:
    """Score every asset x CVE. alert_evidence: {(asset, cve): A} (default: no alert, A = 0)."""
    out = []
    for v in vulns:
        a = alert_evidence.get((v["asset"], v["cve"]), 0.0) if alert_evidence else 0.0
        row = model.score_pair(assets[v["asset"]], v, scores, g[v["asset"]], a, weights)
        row["software"], row["source"] = v["software"], v["via"]
        out.append(row)
    return out


def alert_groups() -> list[dict]:
    """Alert contexts grouped by (rule, target, source): one row per kind of event, with a count."""
    groups: dict[tuple, dict] = {}
    for f in sorted(config.ALERT_CONTEXTS.glob("*.json")):
        ctx = json.loads(f.read_text(encoding="utf-8"))
        if not ctx.get("target"):
            continue
        al = ctx["alert"]
        key = (al["rule_id"], ctx["target"]["hostname"], (ctx["source"] or {}).get("name"))
        grp = groups.setdefault(key, {"ctx": ctx, "alert_ids": [], "times": []})
        grp["alert_ids"].append(al["alert_id"])
        grp["times"].append(al.get("timestamp") or "")
    return list(groups.values())


def _rank(rows: list[dict]) -> list[dict]:
    return sorted(rows, key=lambda r: (-r["R"], -r["s_env"], -r["cvss_base"], r["cve"]))


def score_alerts(assets, g, vulns, scores, weights) -> list[dict]:
    """Two scores per alert group (docs/scoring.md §2):

    event severity  how dangerous this event is. Alerts that lead to CVEs on the host (named in the alert, or
                    reached from its technique): the highest R of those CVEs with A = 1. Other alerts: the
                    Wazuh level scaled by the host's value, plus the blast-radius uplift (model.event_score).
                    Ranking key.
    host risk       how dangerous the host is: the highest R of all its CVEs with no alert evidence (A = 0).
    """
    by_asset = defaultdict(list)
    for v in vulns:
        by_asset[v["asset"]].append(v)
    out = []
    for grp in alert_groups():
        ctx, al = grp["ctx"], grp["ctx"]["alert"]
        target = ctx["target"]["hostname"]
        asset = assets[target]
        related = {v["cve"] for v in ctx["vulnerabilities"]["related_to_alert"]}

        host_rows = _rank([model.score_pair(asset, v, scores, g[target], 0.0, weights) for v in by_asset[target]])
        linked_rows = _rank([model.score_pair(asset, v, scores, g[target], 1.0, weights)
                             for v in by_asset[target] if v["cve"] in related])
        event = model.event_score(al["rule_level"], asset["cr"], asset["ir"], asset["ar"], g[target], weights)
        if linked_rows and linked_rows[0]["R"] >= event["R"]:
            ev_score, basis = linked_rows[0]["R"], f"CVE {linked_rows[0]['cve']} (linked to the alert)"
            ev_ssvc = linked_rows[0]["ssvc"]
        else:
            ev_score, basis, ev_ssvc = event["R"], f"Wazuh level {al['rule_level']}", "-"
        host = host_rows[0] if host_rows else None
        out.append({
            "rule_id": al["rule_id"], "description": al["description"], "rule_level": al["rule_level"],
            "techniques": ", ".join(t["id"] for t in ctx["techniques"]), "target": target,
            "zone": ctx["target"]["zone"], "source": (ctx["source"] or {}).get("name") or "unknown",
            "count": len(grp["alert_ids"]), "first_seen": min(grp["times"]), "last_seen": max(grp["times"]),
            "alert_ids": grp["alert_ids"],
            "event_score": ev_score, "event_band": band(ev_score), "event_basis": basis, "event_ssvc": ev_ssvc,
            "linked": bool(linked_rows), "linked_cves": len(linked_rows), "event": event,
            "host_risk": host["R"] if host else 0.0, "host_band": host["band"] if host else "None",
            "host_top_cve": host["cve"] if host else None, "host_ssvc": host["ssvc"] if host else "-",
            "max_cvss_base": max((r["cvss_base"] for r in host_rows), default=0.0), "cves_on_target": len(host_rows),
            "ctx": ctx, "linked_rows": linked_rows[:5], "host_rows": host_rows[:5],
        })
    out.sort(key=lambda x: (-x["event_score"], -x["host_risk"], -x["rule_level"], x["target"]))
    return out


# ------------------------------------------------------------------------------------------- outputs
VULN_FIELDS = ["asset", "software", "source", "cve", "cvss_base", "base_band", "E", "MAV", "CR", "IR", "AR",
               "env_vector", "s_env", "epss", "T", "G", "A", "R", "band", "ssvc", "kev"]
ALERT_FIELDS = ["rule_id", "description", "rule_level", "techniques", "target", "zone", "source", "count",
                "first_seen", "last_seen", "event_score", "event_band", "event_basis", "linked_cves",
                "host_risk", "host_band", "host_top_cve", "host_ssvc", "max_cvss_base", "cves_on_target"]


def write_csv(path, rows, fields) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def run_vulns(weights=config.WEIGHTS, wait=60):
    meta, scores = epss.load()
    assets, g, vulns, no_vector = graph_data(wait)
    rows = score_vulns(assets, g, vulns, scores, weights)
    write_csv(config.ASSET_CVE_CSV, rows, VULN_FIELDS)
    shift = Counter((r["base_band"], r["band"]) for r in rows)
    up = sum(n for (b, a), n in shift.items() if BAND_ORDER.index(a) > BAND_ORDER.index(b))
    down = sum(n for (b, a), n in shift.items() if BAND_ORDER.index(a) < BAND_ORDER.index(b))
    print(f"scored {len(rows)} asset x CVE pairs ({no_vector} CVEs without a CVSS v3 vector skipped): "
          f"{up} raised a band, {down} lowered, {len(rows) - up - down} unchanged -> {config.ASSET_CVE_CSV}")
    return meta, assets, g, vulns, scores, rows


def run_alerts(weights=config.WEIGHTS, wait=60, data=None):
    meta, assets, g, vulns, scores, _ = data or run_vulns(weights, wait)
    alerts = score_alerts(assets, g, vulns, scores, weights)
    write_csv(config.ALERT_CSV, alerts, ALERT_FIELDS)
    rows = [{"alert_id": aid, "event_score": a["event_score"], "event_band": a["event_band"],
             "event_basis": a["event_basis"], "host_risk": a["host_risk"], "host_band": a["host_band"],
             "host_top_cve": a["host_top_cve"], "ssvc": a["event_ssvc"] if a["linked"] else a["host_ssvc"]}
            for a in alerts for aid in a["alert_ids"]]
    with driver(wait) as drv, drv.session() as s:
        s.run(Q_SET_ALERT, rows=rows).consume()
    print(f"scored {len(alerts)} alert groups ({len(rows)} alerts) -> {config.ALERT_CSV}")
    return alerts


BAND_ORDER = ["None", "Low", "Medium", "High", "Critical"]


def _fmt(x, nd=2):
    return "-" if x is None else (f"{x:.{nd}f}" if isinstance(x, float) else str(x))


def write_report(meta, assets, vuln_rows, alerts, weights) -> None:
    from . import config as c
    osv_date = (c.ROOT / "data" / "raw" / "osv" / "downloaded_at.txt")
    L = ["# Threat report: context-aware alert and vulnerability priority", "",
         f"Generated {date.today().isoformat()} by `python -m score_kg report`. Method: `docs/scoring.md`.", "",
         "| Input | Version |", "|---|---|",
         "| CTI graph | CVEs published 2024 and later (NVD + cvelistV5, CWE, CAPEC, ATT&CK) |",
         f"| EPSS | model {meta.get('model_version', '?')}, scores of {meta.get('score_date', '?')[:10]} |",
         f"| Distro security data (OSV) | downloaded {osv_date.read_text().strip()[:10] if osv_date.exists() else '?'} |",
         f"| Weights α (EPSS), β (blast radius), γ (alert evidence) | {weights[0]:g}, {weights[1]:g}, {weights[2]:g} |",
         "",
         "`R = min(10, S_env + (10 − S_env)·(αT + βG + γA)/(α+β+γ))`. `S_env` is the standard CVSS v3.1 environmental "
         "score of the CVE on this host (E from KEV/SSVC, CR/IR/AR from the asset, MAV from reachability). "
         "T is the EPSS percentile, G the blast radius of the host, and A the alert evidence.", ""]

    # ---- alerts
    L += ["## 1. Alerts", "",
          "One row per kind of event (same rule, target and source), ranked by **event severity**:",
          "- **Event severity**: how dangerous this event is. If the alert leads to a CVE on the host (named in the "
          "alert, or reached from its ATT&CK technique), it is that CVE's score with alert evidence. Otherwise it is "
          "the Wazuh level scaled by the host's value, plus the host's blast radius.",
          "- **Host risk**: how dangerous the host itself is (its most severe CVE in context), whatever the event.",
          "- Baselines: the Wazuh level and the highest CVSS base score on the host.", "",
          "| # | Event severity (band) | Based on | Host risk (band) | Host SSVC | Wazuh level | Max CVSS on host | Event | Target (zone) | Source | Count |",
          "|---:|---|---|---|---|---:|---:|---|---|---|---:|"]
    for i, a in enumerate(alerts, 1):
        L.append(f"| {i} | **{a['event_score']}** ({a['event_band']}) | {a['event_basis']} | {a['host_risk']} ({a['host_band']}) | "
                 f"{a['host_ssvc']} | {a['rule_level']} | {a['max_cvss_base']} | "
                 f"{a['description']} (rule {a['rule_id']}; {a['techniques'] or '-'}) | {a['target']} ({a['zone']}) | "
                 f"{a['source']} | {a['count']} |")
    if not alerts:
        L.append("| | no alert contexts: run `python -m alert_kg all` | | | | | | | | | |")
    linked = sum(a["linked"] for a in alerts)
    L += ["", f"{linked} of {len(alerts)} alert groups lead to a CVE on their host; the rest are scored from the Wazuh level.", ""]

    L += ["## 2. Alert details", ""]
    for i, a in enumerate(alerts, 1):
        ctx, t, ev = a["ctx"], a["ctx"]["target"], a["event"]
        path = ctx["attack_paths"][0] if ctx["attack_paths"] else []
        route = " → ".join(h.get("node") or h.get("service") for h in path) or "-"
        src = ctx["source"] or {}
        L += [f"### {i}. {a['description']} → {a['target']}", "",
              f"- **Event severity {a['event_score']} ({a['event_band']})**, based on {a['event_basis']}.",
              f"- **Host risk {a['host_risk']} ({a['host_band']})**, from {a['host_top_cve']} (SSVC {a['host_ssvc']}). "
              f"Wazuh level {a['rule_level']}; highest CVSS base on the host {a['max_cvss_base']}.",
              f"- Seen {a['count']}× between {a['first_seen'][:19]} and {a['last_seen'][:19]} (rule {a['rule_id']}).",
              f"- Target: {t['hostname']} ({t['role']}, zone {t['zone']}, CR/IR/AR {t['cr']}/{t['ir']}/{t['ar']}, "
              f"{'reachable from the Internet' if t['internet_exposed'] else 'not reachable from the Internet'}).",
              f"- Source: {src.get('kind', 'unknown')} {src.get('name') or ''} {src.get('ip') or ''}. "
              f"Shortest path in the graph: {route}."]
        if not a["linked"]:
            L.append(f"- Event severity: Wazuh level {a['rule_level']} → {ev['base']} on 0–10, × host value weight "
                     f"{ev['weight']:g} = {ev['s_event']}, + blast radius G {ev['G']:.2f} → **{ev['R']}**. "
                     f"No CVE on the host is linked to this alert's technique.")
        for tech in ctx["techniques"]:
            mit = ", ".join(m["name"] for m in tech["mitigations"][:4]) or "-"
            L.append(f"- Technique {tech['id']} {tech['name']} ({', '.join(tech['tactics']) or '-'}); "
                     f"{'applies' if tech['applies_to_target'] else 'does not apply'} to the host's platform. Mitigations: {mit}.")
        blast = ", ".join(f"{b['asset']} ({b['hops']} hop{'s' if b['hops'] > 1 else ''})" for b in ctx["blast_radius"]) or "none"
        L += [f"- If compromised, it can reach: {blast}.", ""]
        for title, rows in (("CVEs linked to this alert (A = 1)", a["linked_rows"]),
                            ("Most severe CVEs on the host (host risk, A = 0)", a["host_rows"])):
            if not rows:
                continue
            L += [f"{title}:", "", "| CVE | CVSS base | E | MAV | S_env | EPSS pct | G | A | **R** | SSVC | KEV |",
                  "|---|---:|---|---|---:|---:|---:|---:|---:|---|---|"]
            for r in rows:
                L.append(f"| {r['cve']} | {r['cvss_base']} | {r['E']} | {r['MAV']} | {r['s_env']} | {_fmt(r['T'])} | "
                         f"{_fmt(r['G'])} | {r['A']:g} | **{r['R']}** | {r['ssvc']} | {'yes' if r['kev'] else ''} |")
            L.append("")

    # ---- assets
    L += ["## 3. Assets", "",
          "| Asset | Zone | CR/IR/AR | Internet | Blast radius G | CVEs | Highest CVSS base | Highest R | Act / Attend (SSVC) |",
          "|---|---|---|---|---:|---:|---:|---:|---:|"]
    by_asset = defaultdict(list)
    for r in vuln_rows:
        by_asset[r["asset"]].append(r)
    for h, a in sorted(assets.items(), key=lambda x: -max((r["R"] for r in by_asset[x[0]]), default=0)):
        rows = by_asset[h]
        act = sum(r["ssvc"] == "Act" for r in rows)
        attend = sum(r["ssvc"] == "Attend" for r in rows)
        L.append(f"| {h} | {a['zone']} | {a['cr']}/{a['ir']}/{a['ar']} | {'yes' if a['internet_exposed'] else 'no'} | "
                 f"{a['G']:.2f} | {len(rows)} | {max((r['cvss_base'] for r in rows), default='-')} | "
                 f"{max((r['R'] for r in rows), default='-')} | {act} / {attend} |")

    L += ["", "### Top vulnerabilities by contextual score (no alert evidence)", "",
          "| Asset | CVE | Source | CVSS base (band) | S_env | R (band) | Change | SSVC | KEV |",
          "|---|---|---|---|---:|---|---|---|---|"]
    for r in sorted(vuln_rows, key=lambda r: (-r["R"], -r["cvss_base"]))[:20]:
        change = BAND_ORDER.index(r["band"]) - BAND_ORDER.index(r["base_band"])
        L.append(f"| {r['asset']} | {r['cve']} | {r['source']} | {r['cvss_base']} ({r['base_band']}) | {r['s_env']} | "
                 f"{r['R']} ({r['band']}) | {'↑' * change or '↓' * -change or '='} | {r['ssvc']} | {'yes' if r['kev'] else ''} |")

    # ---- band shift
    shift = Counter((r["base_band"], r["band"]) for r in vuln_rows)
    present = [b for b in BAND_ORDER if any(b in k for k in shift)]
    L += ["", "## 4. How the context moved CVSS bands (asset × CVE, no alert evidence)", "",
          "Rows: CVSS v3.1 base band. Columns: contextual band (R).", "",
          "| CVSS \\ R | " + " | ".join(present) + " |", "|---|" + "---:|" * len(present)]
    for b in present:
        L.append(f"| {b} | " + " | ".join(str(shift.get((b, a), "")) for a in present) + " |")
    n = len(vuln_rows)
    up = sum(v for (b, a), v in shift.items() if BAND_ORDER.index(a) > BAND_ORDER.index(b))
    down = sum(v for (b, a), v in shift.items() if BAND_ORDER.index(a) < BAND_ORDER.index(b))
    L += ["", f"{n} asset × CVE pairs: {up} raised, {down} lowered, {n - up - down} unchanged.", "",
          "Scores per asset × CVE: `data/scores/asset_cve_scores.csv`. Per alert group: `data/scores/alert_scores.csv`.", ""]
    config.REPORTS.mkdir(parents=True, exist_ok=True)
    config.THREAT_REPORT.write_text("\n".join(L), encoding="utf-8")
    print(f"threat report -> {config.THREAT_REPORT}")


def run_report(weights=config.WEIGHTS, wait=60):
    data = run_vulns(weights, wait)
    alerts = run_alerts(weights, wait, data)
    meta, assets, *_rest, rows = data
    write_report(meta, assets, rows, alerts, weights)


# ------------------------------------------------------------------------------------------- sensitivity
def kendall_tau(a: list[float], b: list[float]) -> float:
    """Kendall tau-b between two score lists over the same items (ties handled)."""
    conc = disc = ties_a = ties_b = 0
    n = len(a)
    for i in range(n):
        for j in range(i + 1, n):
            da, db = a[i] - a[j], b[i] - b[j]
            if da == 0 and db == 0:
                continue
            if da == 0:
                ties_a += 1
            elif db == 0:
                ties_b += 1
            elif (da > 0) == (db > 0):
                conc += 1
            else:
                disc += 1
    denom = ((conc + disc + ties_a) * (conc + disc + ties_b)) ** 0.5
    return (conc - disc) / denom if denom else 1.0


def run_sensitivity(wait=60):
    meta, scores = epss.load()
    assets, g, vulns, _ = graph_data(wait)
    grid = [w for w in product([0, 0.5, 1, 2], repeat=3) if any(w)]
    base = score_vulns(assets, g, vulns, scores, (1, 1, 1))
    base_r = [r["R"] for r in base]
    top = lambda rows: {(r["asset"], r["cve"]) for r in sorted(rows, key=lambda r: (-r["R"], r["cve"]))[:10]}
    base_top, base_alerts = top(base), score_alerts(assets, g, vulns, scores, (1, 1, 1))
    base_alert_top = [a["target"] + "/" + a["rule_id"] for a in base_alerts[:5]]   # ranked by event severity
    lines = []
    for w in grid:
        rows = score_vulns(assets, g, vulns, scores, w)
        alerts = score_alerts(assets, g, vulns, scores, w)
        lines.append((w, kendall_tau(base_r, [r["R"] for r in rows]), len(top(rows) & base_top),
                      len(set(a["target"] + "/" + a["rule_id"] for a in alerts[:5]) & set(base_alert_top))))
    taus = [t for _, t, _, _ in lines]
    L = ["# Sensitivity of the contextual score to the weights α, β, γ", "",
         f"Generated {date.today().isoformat()} by `python -m score_kg sensitivity`. Reference: α = β = γ = 1.", "",
         f"Each of α (EPSS), β (blast radius), γ (alert evidence) takes 0, 0.5, 1 or 2: {len(grid)} settings. "
         f"Ranking of {len(base)} asset × CVE pairs compared with the reference by Kendall τ-b "
         f"(min {min(taus):.3f}, median {sorted(taus)[len(taus) // 2]:.3f}).", "",
         "| α | β | γ | Kendall τ (asset×CVE) | Same top-10 asset×CVE | Same top-5 alert groups |",
         "|---:|---:|---:|---:|---:|---:|"]
    for w, tau, t10, t5 in sorted(lines, key=lambda x: x[1]):
        L.append(f"| {w[0]:g} | {w[1]:g} | {w[2]:g} | {tau:.3f} | {t10}/10 | {t5}/{len(base_alert_top)} |")
    config.REPORTS.mkdir(parents=True, exist_ok=True)
    config.SENSITIVITY_REPORT.write_text("\n".join(L) + "\n", encoding="utf-8")
    print(f"sensitivity: {len(grid)} weight settings, Kendall tau min {min(taus):.3f} -> {config.SENSITIVITY_REPORT}")
