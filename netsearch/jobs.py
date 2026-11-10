"""Scan and enrichment jobs: validated at creation, run either inside the API server or inline from the CLI."""
import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import time

from . import scanner, sources
from .db import db, get_settings, ingest, log, now

ENGINES = ("native", "nmap")


def nmap_path():
    return shutil.which("nmap")


def create_job(conn, targets, ports=None, engine="native", options=None):
    """Validate targets/ports/scope and insert a queued job. Raises ValueError/ScopeError on bad input."""
    settings = get_settings(conn)
    options = options or {}
    if engine not in ENGINES:
        raise ValueError(f"engine must be one of {ENGINES}")
    if engine == "nmap" and not nmap_path():
        raise ValueError("nmap is not installed or not on PATH")
    ports_spec = (ports or settings["scan_default_ports"]).strip()
    port_list = scanner.parse_ports(ports_spec)
    ips = scanner.parse_targets(targets, settings["scan_max_hosts"])
    public = scanner.check_scope(ips, settings)
    opts = {
        "concurrency": max(1, min(int(options.get("concurrency") or settings["scan_concurrency"]), 2000)),
        "rate": max(0, float(options.get("rate") if options.get("rate") is not None else settings["scan_rate"])),
        "timeout": max(0.2, min(float(options.get("timeout") or settings["scan_timeout"]), 30)),
        "rdns": bool(options.get("rdns", settings["scan_rdns"])),
        "ips": ips, "hosts": len(ips), "public_hosts": public,
    }
    total = len(ips) * len(port_list) if engine == "native" else len(ips)
    cur = conn.execute(
        "INSERT INTO scan_jobs(targets, ports, engine, options, status, total, created) VALUES(?,?,?,?,?,?,?)",
        (targets.strip(), ports_spec, engine, json.dumps(opts), "queued", total, now()))
    log(conn, "scan-created", f"#{cur.lastrowid} {targets.strip()[:120]} ports={ports_spec} engine={engine}")
    return cur.lastrowid


def create_enrich_job(conn, ips=None, q=None, steps=None, max_age_hours=None, force=False, limit=5000):
    """Queue an enrichment run over explicit addresses or every host matching a query.

    Hosts that completed the same steps within max_age_hours are left out (unless force), which is what
    makes a cancelled or interrupted run resumable: start it again and it carries on with the rest.
    """
    from . import enrich
    settings = get_settings(conn)
    steps = enrich.parse_steps(steps)
    max_age = float(settings["enrich_max_age_hours"] if max_age_hours is None else max_age_hours)
    targets = enrich.resolve(conn, ips, q, limit)
    todo, fresh = enrich.plan(conn, targets, steps, max_age, force)
    if not targets:
        raise ValueError("no hosts match")
    label = ", ".join(targets[:3]) + (f" +{len(targets) - 3} more" if len(targets) > 3 else "") if ips else (q or "(all hosts)")
    opts = {"ips": todo, "hosts": len(todo), "skipped": len(fresh), "matched": len(targets), "max_age_hours": max_age,
            "force": bool(force), "query": q or "", "by_query": not ips, "ok": 0, "partial": 0, "error": 0, "current": ""}
    cur = conn.execute(
        "INSERT INTO scan_jobs(kind, targets, ports, engine, options, status, total, created) VALUES('enrich',?,?,?,?,?,?,?)",
        (label, ",".join(steps), settings["ai_provider"] if "ai" in steps else "-", json.dumps(opts), "queued", len(todo), now()))
    log(conn, "enrich-created", f"#{cur.lastrowid} {label[:120]}: {len(todo)} host(s), {len(fresh)} recently done")
    return cur.lastrowid


def _run_enrich(job_id, row, progress=None):
    """Blocking enrichment worker: hosts one after another, progress written after each."""
    from . import enrich
    opts = json.loads(row["options"])
    steps, ips = row["ports"].split(","), opts["ips"]
    counts = {"ok": 0, "partial": 0, "error": 0}
    cancelled = lambda: _status(job_id) == "cancelling"
    done = 0
    for ip in ips:
        if cancelled():
            break
        with db() as conn:
            conn.execute("UPDATE scan_jobs SET options=json_set(options, '$.current', ?) WHERE id=?", (ip, job_id))
        try:
            result = enrich.run_host(ip, steps, cancelled=cancelled)
            counts[result["status"]] += 1
        except KeyError:
            counts["error"] += 1   # host was deleted while the job was queued
        done += 1
        with db() as conn:
            conn.execute("UPDATE scan_jobs SET done=?, found=?, options=json_set(options, '$.ok', ?, '$.partial', ?, '$.error', ?) WHERE id=?",
                         (done, counts["ok"] + counts["partial"], counts["ok"], counts["partial"], counts["error"], job_id))
        if progress:
            progress(done, len(ips), counts["ok"] + counts["partial"])
    with db() as conn:
        conn.execute("UPDATE scan_jobs SET options=json_set(options, '$.current', '') WHERE id=?", (job_id,))
    return counts, done < len(ips)


def job_dict(row):
    d = dict(row)
    opts = json.loads(d.pop("options") or "{}")
    opts.pop("ips", None)
    d["options"] = opts
    return d


def list_jobs(conn, limit=50):
    return [job_dict(r) for r in conn.execute("SELECT * FROM scan_jobs ORDER BY id DESC LIMIT ?", (limit,))]


def get_job(conn, job_id):
    row = conn.execute("SELECT * FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
    return job_dict(row) if row else None


def cancel_job(conn, job_id):
    """Request cancellation; the running process (server or CLI) notices on its next progress tick."""
    cur = conn.execute("UPDATE scan_jobs SET status='cancelling' WHERE id=? AND status='running'", (job_id,))
    if not cur.rowcount:
        cur = conn.execute("UPDATE scan_jobs SET status='cancelled', finished=? WHERE id=? AND status='queued'", (now(), job_id))
    return bool(cur.rowcount)


def mark_interrupted(conn):
    """Called at server start: jobs left 'running' by a dead process can never finish."""
    conn.execute("UPDATE scan_jobs SET status='interrupted', finished=? WHERE status IN ('running','cancelling','queued')", (now(),))


def _status(job_id):
    with db() as conn:
        row = conn.execute("SELECT status FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
        return row[0] if row else "cancelling"


def _compress_ports(ports):
    out, start, prev = [], None, None
    for p in ports + [None]:
        if start is None:
            start = prev = p
        elif p is not None and p == prev + 1:
            prev = p
        else:
            out.append(str(start) if start == prev else f"{start}-{prev}")
            start = prev = p
    return ",".join(out)


def _run_nmap(job_id, ips, ports, opts):
    """Blocking nmap -sV run. Returns (records, cancelled)."""
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(ips))
    cmd = [nmap_path(), "-sV", "-Pn", "-T4", "--open", "-oX", "-", "-p", _compress_ports(ports), "-iL", f.name]
    if opts.get("rate"):
        cmd += ["--max-rate", str(int(opts["rate"]))]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    cancelled = False
    try:
        while True:
            try:
                out, err = proc.communicate(timeout=1.5)
                break
            except subprocess.TimeoutExpired:
                if _status(job_id) == "cancelling":
                    proc.kill()
                    out, err = proc.communicate()
                    cancelled = True
                    break
    finally:
        os.unlink(f.name)
    if cancelled:
        return [], True
    if proc.returncode != 0:
        raise RuntimeError(f"nmap exited {proc.returncode}: {err.strip()[:300]}")
    return sources.parse_nmap_xml(out), False


async def run_job(job_id, progress=None):
    """Execute a queued job to completion. progress(done, total, found) is an optional sync callback."""
    with db() as conn:
        row = conn.execute("SELECT * FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
        if row is None or row["status"] != "queued":
            return None
        conn.execute("UPDATE scan_jobs SET status='running', started=? WHERE id=?", (now(), job_id))
    opts = json.loads(row["options"])
    cancel = asyncio.Event()
    status, error, found = "done", "", 0
    try:
        if row["kind"] == "enrich":
            counts, stopped = await asyncio.to_thread(_run_enrich, job_id, row, progress)
            found = counts["ok"] + counts["partial"]
            if stopped:
                cancel.set()
            elif counts["error"] and not found:
                error = f"all {counts['error']} host(s) failed; open one to see why"
        elif row["engine"] == "nmap":
            ips, ports = opts["ips"], scanner.parse_ports(row["ports"])
            records, cancelled = await asyncio.to_thread(_run_nmap, job_id, ips, ports, opts)
            with db() as conn:
                for rec in records:
                    ingest(conn, rec, "nmap")
                found = sum(len(r["services"]) for r in records)
                conn.execute("UPDATE scan_jobs SET done=total, found=? WHERE id=?", (found, job_id))
            if cancelled:
                cancel.set()
        else:
            ips, ports = opts["ips"], scanner.parse_ports(row["ports"])
            seen, last = set(), [0.0]

            def on_service(ip, svc):
                with db() as conn:
                    ingest(conn, {"ip": ip, "services": [svc]}, "scan")
                seen.add(ip)

            def on_progress(done, total, n):
                t = time.monotonic()
                if t - last[0] < 0.7 and done != total:
                    return
                last[0] = t
                with db() as conn:
                    conn.execute("UPDATE scan_jobs SET done=?, found=? WHERE id=?", (done, n, job_id))
                    if conn.execute("SELECT status FROM scan_jobs WHERE id=?", (job_id,)).fetchone()[0] == "cancelling":
                        cancel.set()
                if progress:
                    progress(done, total, n)

            state = await scanner.scan(ips, ports, concurrency=opts["concurrency"], rate=opts["rate"],
                                       timeout=opts["timeout"], on_service=on_service, on_progress=on_progress, cancel=cancel)
            found = state["found"]
            if opts.get("rdns") and seen and not cancel.is_set():
                names = await scanner.reverse_dns(seen)
                with db() as conn:
                    for ip, name in names.items():
                        ingest(conn, {"ip": ip, "hostnames": [name]}, "rdns")
        if cancel.is_set():
            status = "cancelled"
    except Exception as e:  # a failed job must still be recorded as finished
        status, error = "failed", f"{e.__class__.__name__}: {e}"[:500]
    with db() as conn:
        conn.execute("UPDATE scan_jobs SET status=?, error=?, found=?, finished=? WHERE id=?", (status, error, found, now(), job_id))
        what = "host(s) enriched" if row["kind"] == "enrich" else "open service(s)"
        log(conn, f"{row['kind']}-{status}", f"#{job_id}: {found} {what}" + (f" - {error}" if error else ""))
        return get_job(conn, job_id)
