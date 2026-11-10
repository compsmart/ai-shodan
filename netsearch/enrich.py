"""Enrichment: bring one host up to date, and remember when and how well that went.

Steps, in order (any subset):
  sources  look the address up in third-party sources (reverse DNS, InternetDB, GeoIP, configured keyed sources)
  probe    deep probe of the known services: protocol probes, headless browser, nmap -sV (in scan scope only)
  ai       the model names and describes each service, tags the host, writes a summary and findings; it may
           ask for a few more probes from the menu

The outcome is stored on the host (enriched_at, enrich_status, enrich_detail) so a later run can skip hosts
that were completed recently and carry on where an interrupted run stopped.
"""
import json
import time
from datetime import datetime, timedelta, timezone

from . import ai, probe, query, scanner, sources
from . import db as store
from .db import db

STEPS = ("sources", "probe", "ai")


def parse_steps(value):
    if not value:
        return list(STEPS)
    items = [s.strip().lower() for s in (value.split(",") if isinstance(value, str) else value) if str(s).strip()]
    bad = [s for s in items if s not in STEPS]
    if bad:
        raise ValueError(f"unknown step '{bad[0]}' (choose from {', '.join(STEPS)})")
    return [s for s in STEPS if s in items]


def is_fresh(host_row, steps, max_age_hours):
    """True when this host already completed every requested step within the last max_age_hours."""
    if not host_row["enriched_at"] or max_age_hours <= 0:
        return False
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=float(max_age_hours))).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        done = (json.loads(host_row["enrich_detail"] or "{}").get("steps")) or {}
    except ValueError:
        return False
    return all(done.get(s, {}).get("status") in ("ok", "skipped") and done[s].get("at", "") >= cutoff for s in steps)


def plan(conn, ips, steps, max_age_hours, force=False):
    """Split ips into (todo, fresh). Unknown addresses are dropped."""
    todo, fresh = [], []
    for ip in ips:
        row = conn.execute("SELECT enriched_at, enrich_detail FROM hosts WHERE ip=?", (ip,)).fetchone()
        if row is None:
            continue
        (fresh if not force and is_fresh(row, steps, max_age_hours) else todo).append(ip)
    return todo, fresh


def _step_sources(ip, names):
    with db() as conn:
        results = sources.enrich(conn, ip, names)
    errors = [k for k, v in results.items() if v.startswith("error")]
    status = "error" if errors and len(errors) == len(results) else "ok"
    return {"status": status, "note": "; ".join(f"{k}: {v}" for k, v in results.items()), "results": results}


def _step_probe(ip):
    with db() as conn:
        host = store.host_detail(conn, ip)
        settings = store.get_settings(conn)
    if not host["services"]:
        return {"status": "skipped", "note": "no known services to probe; scan the host first"}
    try:
        result = probe.deep_probe(ip, host["services"], settings)
    except scanner.ScopeError as e:
        public = "internet-routable" in str(e)
        return {"status": "skipped", "note": "public address and public scanning is off (Settings > Scanning)" if public else str(e)[:200]}
    with db() as conn:
        if result["services"]:
            store.ingest(conn, {"ip": ip, "services": result["services"]}, "probe")
        for rec in result["nmap"]:
            store.ingest(conn, rec, "nmap")
        store.log(conn, "probe", f"{ip}: {len(result['services'])} service(s), {result['web']} page(s) rendered")
    note = f"{len(result['services'])} service(s) probed, {result['web']} page(s) rendered"
    if result["closed"]:
        note += f"; no longer answering: {', '.join(str(p) for p in result['closed'][:10])}"
    return {"status": "ok", "note": "; ".join([note, *result["notes"]]), "probed": len(result["services"]),
            "web": result["web"], "closed": result["closed"]}


def _step_ai(ip, allow_probes):
    r = ai.run(ip, allow_probes=allow_probes)
    if r["mode"] != "ai":
        return {"status": "error", "note": r["note"], "model": "heuristic"}
    extra = sum(len(a) for a in r["probes"].values())
    return {"status": "ok", "model": r["model"], "risk": r["risk"],
            "note": f"{r['model']}: {r['risk']} risk, {len(r['services'])} service(s) described, {len(r['findings'])} finding(s)"
                    + (f", {extra} extra probe(s)" if extra else "")}


def run_host(ip, steps=None, source_names=None, cancelled=None):
    """Run the steps for one host and record the outcome. Returns {ip, status, steps, seconds}."""
    steps = parse_steps(steps)
    with db() as conn:
        if not conn.execute("SELECT 1 FROM hosts WHERE ip=?", (ip,)).fetchone():
            raise KeyError(ip)
        prev = conn.execute("SELECT enrich_detail FROM hosts WHERE ip=?", (ip,)).fetchone()[0]
    try:
        done = (json.loads(prev or "{}").get("steps")) or {}
    except ValueError:
        done = {}
    started, t0 = store.now(), time.monotonic()
    for step in steps:
        if cancelled and cancelled():
            break
        try:
            if step == "sources":
                out = _step_sources(ip, source_names)
            elif step == "probe":
                out = _step_probe(ip)
            else:
                out = _step_ai(ip, allow_probes="probe" in steps)
        except Exception as e:  # one bad host must not stop a batch
            out = {"status": "error", "note": f"{e.__class__.__name__}: {e}"[:300]}
        done[step] = {**out, "at": store.now()}
    ran = [done[s]["status"] for s in steps if s in done]
    status = "error" if ran and all(s == "error" for s in ran) else "partial" if "error" in ran or len(ran) < len(steps) else "ok"
    detail = {"steps": done, "started": started, "seconds": round(time.monotonic() - t0, 1), "last_steps": steps}
    with db() as conn:
        store.set_enrichment(conn, ip, status, detail)
        store.log(conn, "enrich", f"{ip}: {status} (" + ", ".join(f"{s}={done[s]['status']}" for s in steps if s in done) + ")")
    return {"ip": ip, "status": status, "steps": {s: done[s] for s in steps if s in done}, "seconds": detail["seconds"]}


def resolve(conn, ips=None, q=None, limit=5000):
    """Target list for a batch: explicit addresses, or every host matching a query."""
    if ips:
        return [store.norm_ip(i) for i in ips][:limit]
    return query.match_ips(conn, q or "", limit)
