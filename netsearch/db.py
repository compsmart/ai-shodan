"""SQLite storage: schema, settings, and the single ingest path every data source goes through."""
import ipaddress
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts(
  ip TEXT PRIMARY KEY, ip_int INTEGER NOT NULL DEFAULT 0, is_public INTEGER NOT NULL DEFAULT 0,
  hostnames TEXT DEFAULT '[]', org TEXT DEFAULT '', asn TEXT DEFAULT '', isp TEXT DEFAULT '',
  country TEXT DEFAULT '', city TEXT DEFAULT '', os TEXT DEFAULT '',
  vulns TEXT DEFAULT '[]', sources TEXT DEFAULT '[]', first_seen TEXT, last_seen TEXT,
  ai_summary TEXT DEFAULT '', ai_risk TEXT DEFAULT '', ai_model TEXT DEFAULT '', ai_updated TEXT DEFAULT '',
  notes TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS services(
  id INTEGER PRIMARY KEY, ip TEXT NOT NULL REFERENCES hosts(ip) ON DELETE CASCADE,
  port INTEGER NOT NULL, transport TEXT NOT NULL DEFAULT 'tcp',
  service TEXT DEFAULT '', product TEXT DEFAULT '', version TEXT DEFAULT '', cpe TEXT DEFAULT '',
  banner TEXT DEFAULT '', extra TEXT DEFAULT '{}', sources TEXT DEFAULT '[]',
  first_seen TEXT, last_seen TEXT, UNIQUE(ip, port, transport));
CREATE TABLE IF NOT EXISTS tags(
  id INTEGER PRIMARY KEY, ip TEXT NOT NULL REFERENCES hosts(ip) ON DELETE CASCADE,
  port INTEGER NOT NULL DEFAULT 0, tag TEXT NOT NULL, severity TEXT DEFAULT 'info',
  origin TEXT DEFAULT 'manual', reason TEXT DEFAULT '', created TEXT, UNIQUE(ip, port, tag));
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY, ip TEXT NOT NULL REFERENCES hosts(ip) ON DELETE CASCADE,
  port INTEGER NOT NULL DEFAULT 0, severity TEXT DEFAULT 'info', title TEXT, detail TEXT DEFAULT '',
  origin TEXT DEFAULT 'manual', created TEXT);
CREATE TABLE IF NOT EXISTS scan_jobs(
  id INTEGER PRIMARY KEY, targets TEXT, ports TEXT, engine TEXT, options TEXT DEFAULT '{}',
  status TEXT DEFAULT 'queued', total INTEGER DEFAULT 0, done INTEGER DEFAULT 0, found INTEGER DEFAULT 0,
  error TEXT DEFAULT '', created TEXT, started TEXT, finished TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS activity(id INTEGER PRIMARY KEY, ts TEXT, actor TEXT, action TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_services_ip ON services(ip);
CREATE INDEX IF NOT EXISTS ix_services_port ON services(port);
CREATE INDEX IF NOT EXISTS ix_services_product ON services(product);
CREATE INDEX IF NOT EXISTS ix_tags_ip ON tags(ip);
CREATE INDEX IF NOT EXISTS ix_tags_tag ON tags(tag);
CREATE INDEX IF NOT EXISTS ix_findings_ip ON findings(ip);
CREATE INDEX IF NOT EXISTS ix_hosts_ipint ON hosts(ip_int);
"""

# Columns added after the first release: (table, column, declaration). Applied by _migrate().
MIGRATIONS = [
    ("hosts", "enriched_at", "TEXT DEFAULT ''"),       # when the last enrichment run finished
    ("hosts", "enrich_status", "TEXT DEFAULT ''"),     # ok | partial | error
    ("hosts", "enrich_detail", "TEXT DEFAULT '{}'"),   # {steps: {sources|probe|ai: {status, note, ...}}, started, seconds}
    ("services", "name", "TEXT DEFAULT ''"),           # friendly name of what is running ("Grafana dashboard")
    ("services", "summary", "TEXT DEFAULT ''"),        # one or two sentences about this service
    ("services", "probed_at", "TEXT DEFAULT ''"),      # last deep probe
    ("scan_jobs", "kind", "TEXT DEFAULT 'scan'"),      # scan | enrich
]

SEVERITIES = ["info", "low", "medium", "high", "critical"]
_initialised = set()


def _migrate(conn):
    for table, column, decl in MIGRATIONS:
        if column not in {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect():
    config.HOME.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(config.DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    if str(config.DB_PATH) not in _initialised:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.commit()
        _initialised.add(str(config.DB_PATH))
    return conn


@contextmanager
def db():
    conn = connect()
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def actor():
    return os.environ.get("NETSEARCH_ACTOR") or "user"


def log(conn, action, detail=""):
    conn.execute("INSERT INTO activity(ts, actor, action, detail) VALUES(?,?,?,?)",
                 (now(), actor(), action, str(detail)[:500]))


# ---------------------------------------------------------------- settings

def get_settings(conn):
    s = dict(config.DEFAULTS)
    for row in conn.execute("SELECT key, value FROM settings"):
        if row["key"] in s:
            s[row["key"]] = json.loads(row["value"])
    for key, env in config.SECRETS.items():
        if not s[key] and os.environ.get(env):
            s[key] = os.environ[env]
    return s


def set_setting(conn, key, value):
    if key not in config.DEFAULTS:
        raise ValueError(f"unknown setting: {key}")
    default = config.DEFAULTS[key]
    if isinstance(default, bool):
        if isinstance(value, str):
            value = value.strip().lower() in ("1", "true", "yes", "on")
        value = bool(value)
    elif isinstance(default, int):
        value = int(value)
    elif isinstance(default, float):
        value = float(value)
    else:
        value = str(value).strip()
    if key == "ai_provider" and value not in config.AI_PROVIDERS:
        raise ValueError(f"must be one of {', '.join(config.AI_PROVIDERS)}")
    conn.execute("INSERT INTO settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                 (key, json.dumps(value)))
    return value


# ---------------------------------------------------------------- ingest

def _loads(text, default):
    try:
        return json.loads(text) if text else default
    except ValueError:
        return default


def _union(old, new):
    out = list(old)
    for item in new or []:
        if item and item not in out:
            out.append(item)
    return out


def norm_ip(value):
    return str(ipaddress.ip_address(str(value).strip()))


def ingest(conn, rec, source):
    """Merge a normalised host record into the database.

    rec = {ip, hostnames?, org?, asn?, isp?, country?, city?, os?, vulns?, tags?,
           services?: [{port, transport?, service?, product?, version?, cpe?, banner?, name?, summary?,
                        extra?, weak?, probed?}]}
    Non-empty incoming values overwrite; lists are unioned. Rule tags are recomputed afterwards.
    """
    from . import fingerprint, tagging

    ip = norm_ip(rec["ip"])
    addr = ipaddress.ip_address(ip)
    ts = now()
    row = conn.execute("SELECT * FROM hosts WHERE ip=?", (ip,)).fetchone()
    if row is None:
        conn.execute("INSERT INTO hosts(ip, ip_int, is_public, first_seen, last_seen) VALUES(?,?,?,?,?)",
                     (ip, int(addr) if addr.version == 4 else 0, int(addr.is_global), ts, ts))
        row = conn.execute("SELECT * FROM hosts WHERE ip=?", (ip,)).fetchone()
    updates = {
        "last_seen": ts,
        "hostnames": json.dumps(_union(_loads(row["hostnames"], []), [h.lower().rstrip(".") for h in rec.get("hostnames") or [] if h])),
        "vulns": json.dumps(_union(_loads(row["vulns"], []), rec.get("vulns"))),
        "sources": json.dumps(_union(_loads(row["sources"], []), [source])),
    }
    for field in ("org", "asn", "isp", "country", "city", "os"):
        if rec.get(field):
            updates[field] = str(rec[field])
    conn.execute(f"UPDATE hosts SET {', '.join(k + '=?' for k in updates)} WHERE ip=?", (*updates.values(), ip))

    for svc in rec.get("services") or []:
        port = int(svc["port"])
        transport = (svc.get("transport") or "tcp").lower()
        new = {k: str(svc.get(k) or "") for k in ("service", "product", "version", "cpe", "banner", "name", "summary")}
        new["banner"], new["name"], new["summary"] = new["banner"][:8000], new["name"][:120], new["summary"][:1000]
        probed = ts if svc.get("probed") else ""
        extra = dict(svc.get("extra") or {})
        guessed = set()   # fields that are only a port-number guess: they fill blanks, never replace
        if not new["product"] or not new["service"]:
            ident = fingerprint.identify(port, new["banner"], extra)
            for k, v in ident.items():
                if v and not new.get(k):
                    new[k] = v
                    if not ident["product"] and not new["banner"]:
                        guessed.add(k)
        old = conn.execute("SELECT * FROM services WHERE ip=? AND port=? AND transport=?", (ip, port, transport)).fetchone()
        if old is None:
            conn.execute(
                "INSERT INTO services(ip, port, transport, service, product, version, cpe, banner, name, summary, probed_at,"
                " extra, sources, first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ip, port, transport, new["service"], new["product"], new["version"], new["cpe"], new["banner"],
                 new["name"], new["summary"], probed, json.dumps(extra), json.dumps([source]), ts, ts))
        else:
            # weak = a guess (e.g. nmap's port-table name): only fills blanks, never replaces observed values
            weak = bool(svc.get("weak"))
            merged = {k: ((old[k] or v) if (weak or k in guessed) else (v or old[k])) for k, v in new.items()}
            if not weak and new["product"] and not new["version"] and new["product"] != old["product"]:
                merged["version"] = ""  # a different product invalidates the stored version
            conn.execute(
                "UPDATE services SET service=?, product=?, version=?, cpe=?, banner=?, name=?, summary=?, probed_at=?,"
                " extra=?, sources=?, last_seen=? WHERE id=?",
                (merged["service"], merged["product"], merged["version"], merged["cpe"], merged["banner"],
                 merged["name"], merged["summary"], probed or old["probed_at"],
                 json.dumps({**_loads(old["extra"], {}), **extra}),
                 json.dumps(_union(_loads(old["sources"], []), [source])), ts, old["id"]))

    for tag in rec.get("tags") or []:
        add_tag(conn, ip, tag, origin=source)
    if not rec.get("os") and not row["os"]:   # no source told us the OS: infer it from banners when they say so
        texts = [r[0] + "\n" + (r[1] or "") for r in conn.execute(
            "SELECT banner, json_extract(extra, '$.http.server') FROM services WHERE ip=?", (ip,))]
        guess = fingerprint.guess_os(texts)
        if guess:
            conn.execute("UPDATE hosts SET os=? WHERE ip=?", (guess, ip))
    tagging.apply(conn, ip)
    return ip


def set_enrichment(conn, ip, status, detail):
    conn.execute("UPDATE hosts SET enriched_at=?, enrich_status=?, enrich_detail=? WHERE ip=?",
                 (now(), status, json.dumps(detail), ip))


def slug(tag):
    import re
    return re.sub(r"[^a-z0-9]+", "-", str(tag).lower()).strip("-")[:48]


def add_tag(conn, ip, tag, port=0, origin="manual", reason="", severity=None):
    from .tagging import CATALOG
    tag = slug(tag)
    if not tag:
        raise ValueError("empty tag")
    if severity not in SEVERITIES:
        severity = CATALOG.get(tag, ("info", ""))[0]
    conn.execute("INSERT OR IGNORE INTO tags(ip, port, tag, severity, origin, reason, created) VALUES(?,?,?,?,?,?,?)",
                 (ip, int(port or 0), tag, severity, origin, reason[:500], now()))
    return tag


def add_finding(conn, ip, title, detail="", severity="info", port=0, origin="manual"):
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}")
    if not conn.execute("SELECT 1 FROM hosts WHERE ip=?", (ip,)).fetchone():
        raise KeyError(ip)
    cur = conn.execute("INSERT INTO findings(ip, port, severity, title, detail, origin, created) VALUES(?,?,?,?,?,?,?)",
                       (ip, int(port or 0), severity, title[:200], detail[:4000], origin, now()))
    return cur.lastrowid


# ---------------------------------------------------------------- reads

def service_dict(row):
    d = dict(row)
    d["extra"] = _loads(d.get("extra"), {})
    d["sources"] = _loads(d.get("sources"), [])
    return d


def host_dict(row):
    d = dict(row)
    for k in ("hostnames", "vulns", "sources"):
        d[k] = _loads(d.get(k), [])
    d["is_public"] = bool(d.get("is_public"))
    d["enrich_detail"] = _loads(d.get("enrich_detail"), {})
    d.pop("ip_int", None)
    return d


def host_detail(conn, ip):
    row = conn.execute("SELECT * FROM hosts WHERE ip=?", (ip,)).fetchone()
    if row is None:
        return None
    host = host_dict(row)
    host["services"] = [service_dict(r) for r in conn.execute("SELECT * FROM services WHERE ip=? ORDER BY port", (ip,))]
    host["tags"] = [dict(r) for r in conn.execute(
        "SELECT port, tag, severity, origin, reason FROM tags WHERE ip=? ORDER BY port, tag", (ip,))]
    host["findings"] = [dict(r) for r in conn.execute(
        "SELECT id, port, severity, title, detail, origin, created FROM findings WHERE ip=? ORDER BY id DESC", (ip,))]
    return host


def stats(conn):
    one = lambda sql: conn.execute(sql).fetchone()[0]
    top = lambda sql: [{"value": r[0], "count": r[1]} for r in conn.execute(sql)]
    return {
        "hosts": one("SELECT COUNT(*) FROM hosts"),
        "services": one("SELECT COUNT(*) FROM services"),
        "public_hosts": one("SELECT COUNT(*) FROM hosts WHERE is_public=1"),
        "analyzed": one("SELECT COUNT(*) FROM hosts WHERE ai_updated!=''"),
        "enriched": one("SELECT COUNT(*) FROM hosts WHERE enriched_at!=''"),
        "findings": {r[0]: r[1] for r in conn.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity")},
        "risk": {r[0]: r[1] for r in conn.execute("SELECT ai_risk, COUNT(*) FROM hosts WHERE ai_risk!='' GROUP BY ai_risk")},
        "top_ports": top("SELECT port, COUNT(*) c FROM services GROUP BY port ORDER BY c DESC LIMIT 10"),
        "top_products": top("SELECT product, COUNT(*) c FROM services WHERE product!='' GROUP BY product ORDER BY c DESC LIMIT 10"),
        "top_tags": top("SELECT tag, COUNT(DISTINCT ip) c FROM tags GROUP BY tag ORDER BY c DESC LIMIT 12"),
        "top_sources": top("SELECT j.value, COUNT(*) c FROM hosts, json_each(hosts.sources) j GROUP BY j.value ORDER BY c DESC"),
        "activity": [dict(r) for r in conn.execute("SELECT ts, actor, action, detail FROM activity ORDER BY id DESC LIMIT 15")],
    }


GAP_KINDS = {
    "no-services": ("Hosts with no known services", "SELECT ip FROM hosts h WHERE NOT EXISTS (SELECT 1 FROM services s WHERE s.ip=h.ip)"),
    "unidentified": ("Hosts with a service whose product is unknown", "SELECT DISTINCT ip FROM services WHERE product=''"),
    "no-banner": ("Hosts with a service that has no banner (port known only from a third party)", "SELECT DISTINCT ip FROM services WHERE banner=''"),
    "no-geo": ("Public hosts missing country/org", "SELECT ip FROM hosts WHERE is_public=1 AND (country='' OR org='')"),
    "no-hostnames": ("Hosts with no hostnames", "SELECT ip FROM hosts WHERE hostnames='[]'"),
    "unanalyzed": ("Hosts with services but no AI/agent analysis", "SELECT ip FROM hosts h WHERE ai_updated='' AND EXISTS (SELECT 1 FROM services s WHERE s.ip=h.ip)"),
    "unenriched": ("Hosts that have never been through enrichment", "SELECT ip FROM hosts WHERE enriched_at=''"),
    "stale": ("Hosts not seen for 30+ days", "SELECT ip FROM hosts WHERE last_seen < strftime('%Y-%m-%dT%H:%M:%SZ','now','-30 days')"),
}


def gaps(conn, kind=None, limit=50):
    out = {}
    for name, (label, sql) in GAP_KINDS.items():
        if kind and kind != name:
            continue
        count = conn.execute(f"SELECT COUNT(*) FROM ({sql})").fetchone()[0]
        out[name] = {"label": label, "count": count,
                     "ips": [r[0] for r in conn.execute(f"{sql} LIMIT ?", (limit,))]}
    return out
