"""HTTP API + static web UI. Local, single-user: bind to loopback (the default) unless you add your own auth in front."""
import asyncio
import os
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, ai, config, enrich as enrichment, jobs, probe, query, scanner, sources, tagging
from . import db as store
from .db import db

_tasks = set()


@asynccontextmanager
async def lifespan(app):
    with db() as conn:
        jobs.mark_interrupted(conn)
    yield


app = FastAPI(title="NetSearch", version=__version__, lifespan=lifespan)


@app.middleware("http")
async def local_only_guard(request: Request, call_next):
    """Block cross-site and DNS-rebinding requests: this API can launch scans and holds API keys."""
    allowed = os.environ.get("NETSEARCH_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]").split(",")
    host = request.headers.get("host", "")
    hostname = host.rsplit(":", 1)[0] if not host.endswith("]") else host
    if "*" not in allowed and hostname not in allowed:
        return JSONResponse({"detail": "host not allowed"}, status_code=403)
    origin = request.headers.get("origin")
    if origin and request.method not in ("GET", "HEAD", "OPTIONS") and urlparse(origin).netloc != host:
        return JSONResponse({"detail": "cross-origin request refused"}, status_code=403)
    return await call_next(request)


def bad(e, code=400):
    raise HTTPException(code, str(e))


def _ip(ip):
    try:
        return store.norm_ip(ip)
    except ValueError:
        bad(f"not an IP address: {ip}")


# ---------------------------------------------------------------- search / hosts

@app.get("/api/stats")
def stats():
    with db() as conn:
        return store.stats(conn)


@app.get("/api/search")
def search(q: str = "", page: int = 1, size: int = 25, sort: str = "recent", facets: bool = True):
    with db() as conn:
        try:
            result = query.search(conn, q, page, size, sort)
            if facets:
                result["facets"] = query.facets(conn, q)
        except query.QueryError as e:
            bad(e)
        return result


@app.get("/api/hosts/{ip}")
def host(ip: str):
    with db() as conn:
        return store.host_detail(conn, _ip(ip)) or bad("host not found", 404)


@app.delete("/api/hosts/{ip}")
def delete_host(ip: str):
    with db() as conn:
        n = conn.execute("DELETE FROM hosts WHERE ip=?", (_ip(ip),)).rowcount
        store.log(conn, "delete-host", ip)
        return {"deleted": n}


@app.put("/api/hosts/{ip}/notes")
def set_notes(ip: str, body: dict = Body(...)):
    with db() as conn:
        conn.execute("UPDATE hosts SET notes=? WHERE ip=?", (str(body.get("notes", ""))[:10000], _ip(ip)))
        return {"ok": True}


@app.post("/api/hosts/{ip}/tags")
def add_tag(ip: str, body: dict = Body(...)):
    with db() as conn:
        ip = _ip(ip)
        if not conn.execute("SELECT 1 FROM hosts WHERE ip=?", (ip,)).fetchone():
            bad("host not found", 404)
        try:
            tag = store.add_tag(conn, ip, body.get("tag", ""), body.get("port", 0), "manual", str(body.get("reason", "")), body.get("severity"))
        except ValueError as e:
            bad(e)
        return {"tag": tag}


@app.delete("/api/hosts/{ip}/tags")
def remove_tag(ip: str, tag: str, port: int = 0):
    with db() as conn:
        n = conn.execute("DELETE FROM tags WHERE ip=? AND tag=? AND port=?", (_ip(ip), tag, port)).rowcount
        return {"deleted": n}


@app.post("/api/hosts/{ip}/enrich")
def enrich(ip: str, body: dict = Body(default={})):
    with db() as conn:
        return {"results": sources.enrich(conn, _ip(ip), body.get("sources") or None)}


@app.post("/api/hosts/{ip}/analyze")
def analyze(ip: str):
    try:
        return ai.run(_ip(ip))
    except KeyError:
        bad("host not found", 404)


@app.get("/api/shots/{name}")
def screenshot(name: str):
    """Screenshot taken by the browser probe. The name is rebuilt from validated parts, never used as given."""
    ip, _, port = name.removesuffix(".jpg").rpartition("_")
    try:
        path = config.SHOTS_DIR / probe.shot_name(store.norm_ip(ip.replace("_", ":") if ip.count("_") > 1 else ip), int(port))
    except ValueError:
        bad("not found", 404)
    if not path.is_file():
        bad("not found", 404)
    return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "no-cache"})


# ---------------------------------------------------------------- enrichment

def _enrich_args(body):
    ips = [_ip(i) for i in (body.get("ips") or [])]
    try:
        steps = enrichment.parse_steps(body.get("steps"))
        age = body.get("max_age_hours")
        age = None if age in (None, "") else max(0.0, float(age))
    except (ValueError, TypeError) as e:
        bad(e)
    return ips, str(body.get("q") or ""), steps, age, bool(body.get("force"))


@app.post("/api/enrich/preview")
def enrich_preview(body: dict = Body(default={})):
    """How many hosts a run would touch, and how many it would skip as recently done."""
    ips, q, steps, age, force = _enrich_args(body)
    with db() as conn:
        settings = store.get_settings(conn)
        try:
            targets = enrichment.resolve(conn, ips, q)
        except query.QueryError as e:
            bad(e)
        todo, fresh = enrichment.plan(conn, targets, steps, settings["enrich_max_age_hours"] if age is None else age, force)
        public = sum(1 for ip in todo if not store.ipaddress.ip_address(ip).is_private)
        return {"matched": len(targets), "todo": len(todo), "fresh": len(fresh), "public": public, "steps": steps,
                "max_age_hours": settings["enrich_max_age_hours"] if age is None else age,
                "scan_allow_public": settings["scan_allow_public"], "ai_enabled": settings["ai_enabled"],
                "ai_provider": settings["ai_provider"], "ai_provider_label": ai.PROVIDERS.get(settings["ai_provider"], "")}


@app.post("/api/enrich")
async def enrich_start(body: dict = Body(default={})):
    ips, q, steps, age, force = _enrich_args(body)
    with db() as conn:
        try:
            job_id = jobs.create_enrich_job(conn, ips or None, q, steps, age, force)
        except (ValueError, query.QueryError) as e:
            bad(e)
    task = asyncio.create_task(jobs.run_job(job_id))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    with db() as conn:
        return jobs.get_job(conn, job_id)


@app.post("/api/ai/test")
def ai_test():
    with db() as conn:
        settings = store.get_settings(conn)
    try:
        return ai.test(settings)
    except ai.AIError as e:
        return {"ok": False, "provider": settings["ai_provider"], "error": str(e)}


@app.delete("/api/findings/{finding_id}")
def delete_finding(finding_id: int):
    with db() as conn:
        return {"deleted": conn.execute("DELETE FROM findings WHERE id=?", (finding_id,)).rowcount}


@app.get("/api/findings")
def findings(severity: str = "", limit: int = 200):
    with db() as conn:
        sql = "SELECT id, ip, port, severity, title, detail, origin, created FROM findings"
        params = []
        if severity:
            sql += " WHERE severity=?"
            params.append(severity)
        order = " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id DESC LIMIT ?"
        return [dict(r) for r in conn.execute(sql + order, (*params, limit))]


@app.get("/api/tags")
def tags():
    with db() as conn:
        return tagging.catalog_with_counts(conn)


@app.get("/api/gaps")
def gaps(kind: str = "", limit: int = 25):
    with db() as conn:
        return store.gaps(conn, kind or None, limit)


# ---------------------------------------------------------------- scans

@app.get("/api/scans")
def list_scans():
    with db() as conn:
        return {"jobs": jobs.list_jobs(conn), "nmap": bool(jobs.nmap_path()), "presets": {k: len(v) for k, v in scanner.PRESETS.items()}}


@app.post("/api/scans")
async def create_scan(body: dict = Body(...)):
    with db() as conn:
        try:
            job_id = jobs.create_job(conn, str(body.get("targets", "")), body.get("ports") or None,
                                     body.get("engine") or "native", body.get("options") or {})
        except (ValueError, scanner.ScopeError) as e:
            bad(e)
    task = asyncio.create_task(jobs.run_job(job_id))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    with db() as conn:
        return jobs.get_job(conn, job_id)


@app.get("/api/scans/{job_id}")
def get_scan(job_id: int):
    with db() as conn:
        return jobs.get_job(conn, job_id) or bad("job not found", 404)


@app.post("/api/scans/{job_id}/cancel")
def cancel_scan(job_id: int):
    with db() as conn:
        return {"cancelled": jobs.cancel_job(conn, job_id)}


# ---------------------------------------------------------------- sources / import

@app.get("/api/sources")
def list_sources():
    with db() as conn:
        settings = store.get_settings(conn)
        counts = {r[0]: r[1] for r in conn.execute("SELECT j.value, COUNT(*) FROM hosts, json_each(hosts.sources) j GROUP BY j.value")}
        return [s.info(settings) | {"hosts": counts.get(s.name, 0)} for s in sources.SOURCES.values()]


@app.post("/api/sources/{name}/search")
def source_search(name: str, body: dict = Body(...)):
    with db() as conn:
        try:
            ips = sources.remote_search(conn, name, str(body.get("query", "")), max(1, min(int(body.get("limit") or 50), 500)))
        except sources.SourceError as e:
            bad(e)
        return {"imported": len(ips), "ips": ips}


@app.post("/api/import")
async def import_file(request: Request, format: str = "auto", source: str = "import"):
    data = await request.body()
    if not data:
        bad("empty upload")

    def work():
        with db() as conn:
            return sources.import_bytes(conn, data, format, store.slug(source) or "import")
    try:
        return await asyncio.to_thread(work)
    except Exception as e:  # malformed files surface as a 400 with the parser's message
        bad(f"could not parse file: {e}")


# ---------------------------------------------------------------- settings

@app.get("/api/settings")
def get_settings():
    with db() as conn:
        s = store.get_settings(conn)
    out = {}
    for k, v in s.items():
        if k in config.SECRETS:
            out[k] = ""
            out[k + "_set"] = bool(v)
        else:
            out[k] = v
    import shutil
    out["_meta"] = {"version": __version__, "db_path": str(config.DB_PATH), "nmap": jobs.nmap_path() or "",
                    "secret_env": config.SECRETS, "ai_providers": ai.PROVIDERS,
                    "agents": {name: shutil.which(name) or "" for name in ("claude", "codex", "opencode")}}
    return out


@app.put("/api/settings")
def put_settings(body: dict = Body(...)):
    with db() as conn:
        for k, v in body.items():
            if k not in config.DEFAULTS:
                continue
            if k in config.SECRETS and v == "":
                continue  # blank = keep the stored secret; send null to clear
            try:
                store.set_setting(conn, k, "" if v is None else v)
            except (ValueError, TypeError) as e:
                bad(f"{k}: {e}")
        store.log(conn, "settings", ", ".join(k for k in body if k in config.DEFAULTS))
    return get_settings()


app.mount("/", StaticFiles(directory=str(config.WEB_DIR), html=True), name="web")
