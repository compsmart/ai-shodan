"""Search query language -> SQL.   Example:  port:22 product:openssh -tag:outdated-software net:10.0.0.0/8 "free text"

Service filters in one query must match the same service; a negated service filter means
"the host has no such service". See docs/query-language.md.
"""
import ipaddress
import json
import re

from .db import SEVERITIES, host_dict


class QueryError(ValueError):
    pass


TOKEN = re.compile(r'(-?)(?:([a-z_]+):)?("([^"]*)"|\S+)', re.I)
LIKE = lambda v: "%" + v.replace("*", "%") + "%"

# service-level fields: name -> (sql with {s} alias, value transform)
SERVICE_FIELDS = {
    "service": ("{s}.service = ? COLLATE NOCASE", str),
    "product": ("{s}.product LIKE ?", LIKE),
    "version": ("{s}.version LIKE ?", lambda v: v.replace("*", "%") + "%"),
    "banner": ("{s}.banner LIKE ?", LIKE),
    "cpe": ("{s}.cpe LIKE ?", LIKE),
    "transport": ("{s}.transport = ? COLLATE NOCASE", str),
    "title": ("json_extract({s}.extra, '$.http.title') LIKE ?", LIKE),
    "server": ("json_extract({s}.extra, '$.http.server') LIKE ?", LIKE),
    "cert": ("({s}.extra LIKE ? AND json_extract({s}.extra, '$.tls') IS NOT NULL)", LIKE),
}
HOST_FIELDS = {
    "ip": ("h.ip LIKE ?", lambda v: v.replace("*", "%")),
    "country": ("h.country = ? COLLATE NOCASE", str),
    "city": ("h.city LIKE ?", LIKE),
    "org": ("(h.org LIKE ? OR h.isp LIKE ?)", lambda v: [LIKE(v), LIKE(v)]),
    "asn": ("h.asn = ? COLLATE NOCASE", lambda v: v if v.upper().startswith("AS") else "AS" + v),
    "os": ("h.os LIKE ?", LIKE),
    "hostname": ("h.hostnames LIKE ?", LIKE),
    "source": ("h.sources LIKE ?", lambda v: f'%"{v}"%'),
    "cve": ("h.vulns LIKE ?", LIKE),
    "risk": ("h.ai_risk = ? COLLATE NOCASE", str),
    "tag": ("EXISTS (SELECT 1 FROM tags t WHERE t.ip=h.ip AND t.tag = ?)", str),
    "severity": ("EXISTS (SELECT 1 FROM findings f WHERE f.ip=h.ip AND f.severity = ?)", str),
    "after": ("h.last_seen >= ?", str),
    "enriched": ("h.enrich_status = ? COLLATE NOCASE", str),
    "name": ("EXISTS (SELECT 1 FROM services x WHERE x.ip=h.ip AND x.name LIKE ?)", LIKE),
    "before": ("h.last_seen < ?", str),
}
HAS = {
    "cve": "h.vulns != '[]'", "vuln": "h.vulns != '[]'", "ai": "h.ai_updated != ''", "enriched": "h.enriched_at != ''", "screenshot": "EXISTS (SELECT 1 FROM services x WHERE x.ip=h.ip AND json_extract(x.extra, '$.probe.screenshot') IS NOT NULL)", "hostname": "h.hostnames != '[]'",
    "notes": "h.notes != ''", "finding": "EXISTS (SELECT 1 FROM findings f WHERE f.ip=h.ip)",
    "tls": "EXISTS (SELECT 1 FROM services x WHERE x.ip=h.ip AND json_extract(x.extra, '$.tls') IS NOT NULL)",
    "service": "EXISTS (SELECT 1 FROM services x WHERE x.ip=h.ip)",
}
ALIASES = {"vuln": "cve", "net": "net", "cidr": "net", "http.title": "title", "app": "product", "is": "is"}
FIELDS = sorted(set(SERVICE_FIELDS) | set(HOST_FIELDS) | {"port", "net", "has", "is"})


def _port_cond(value):
    parts, params = [], []
    for item in value.split(","):
        if "-" in item:
            lo, hi = item.split("-", 1)
            parts.append("{s}.port BETWEEN ? AND ?")
            params += [int(lo), int(hi)]
        else:
            parts.append("{s}.port = ?")
            params.append(int(item))
    return "(" + " OR ".join(parts) + ")", params


def compile_query(q):
    """Return (where_sql, params). Positive service conditions reference alias s."""
    where, params = [], []
    for neg, field, raw, quoted in TOKEN.findall(q or ""):
        value = quoted if raw.startswith('"') else raw
        field = (field or "").lower()
        field = ALIASES.get(field, field)
        if not value:
            continue
        try:
            if not field:
                like = LIKE(value)
                sql = ("(h.ip LIKE ? OR h.hostnames LIKE ? OR h.org LIKE ? OR h.ai_summary LIKE ? OR EXISTS (SELECT 1 FROM services x "
                       "WHERE x.ip=h.ip AND (x.banner LIKE ? OR x.product LIKE ? OR x.service LIKE ? OR x.extra LIKE ? OR x.name LIKE ? OR x.summary LIKE ?)))")
                p = [like] * 10
            elif field == "port" or field in SERVICE_FIELDS:
                if field == "port":
                    tmpl, p = _port_cond(value)
                else:
                    tmpl, conv = SERVICE_FIELDS[field]
                    p = [conv(value)]
                if neg:
                    sql, neg = f"NOT EXISTS (SELECT 1 FROM services s2 WHERE s2.ip=h.ip AND {tmpl.format(s='s2')})", ""
                else:
                    sql = tmpl.format(s="s")
            elif field == "net":
                net = ipaddress.ip_network(value, strict=False)
                sql, p = "h.ip_int BETWEEN ? AND ?", [int(net.network_address), int(net.broadcast_address)]
            elif field == "has":
                if value.lower() not in HAS:
                    raise QueryError(f"has: accepts {', '.join(sorted(HAS))}")
                sql, p = HAS[value.lower()], []
            elif field == "is":
                if value.lower() not in ("public", "private"):
                    raise QueryError("is: accepts public or private")
                sql, p = f"h.is_public = {int(value.lower() == 'public')}", []
            elif field in HOST_FIELDS:
                sql, conv = HOST_FIELDS[field]
                p = conv(value)
                p = p if isinstance(p, list) else [p]
            else:
                raise QueryError(f"unknown filter '{field}:' - available: {', '.join(FIELDS)}")
        except QueryError:
            raise
        except ValueError as e:
            raise QueryError(f"bad value for {field}: {value} ({e})")
        where.append(f"NOT ({sql})" if neg else sql)
        params += p
    return " AND ".join(where) or "1=1", params


SORTS = {
    "recent": "h.last_seen DESC, h.ip_int",
    "ip": "h.ip_int, h.ip",
    "enriched": "h.enriched_at DESC, h.ip_int",
    "ports": "(SELECT COUNT(*) FROM services x WHERE x.ip=h.ip) DESC, h.ip_int",
    "risk": "CASE h.ai_risk WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 "
            "WHEN 'info' THEN 4 ELSE 5 END, h.last_seen DESC",
}
BASE = "FROM hosts h LEFT JOIN services s ON s.ip=h.ip WHERE "


def search(conn, q="", page=1, size=25, sort="recent"):
    where, params = compile_query(q)
    size = max(1, min(int(size), 500))
    page = max(1, int(page))
    total = conn.execute(f"SELECT COUNT(DISTINCT h.ip) {BASE}{where}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT h.* {BASE}{where} GROUP BY h.ip ORDER BY {SORTS.get(sort, SORTS['recent'])} LIMIT ? OFFSET ?",
        (*params, size, (page - 1) * size)).fetchall()
    hosts = []
    for row in rows:
        h = host_dict(row)
        h.pop("notes", None)
        h.pop("enrich_detail", None)
        h["services"] = [dict(r) | {"title": r["title"] or ""} for r in conn.execute(
            "SELECT port, transport, service, product, version, name, json_extract(extra, '$.http.title') AS title "
            "FROM services WHERE ip=? ORDER BY port", (h["ip"],))]
        h["tags"] = [dict(r) for r in conn.execute(
            "SELECT tag, MAX(severity) AS severity, MIN(origin) AS origin, COUNT(*) AS n FROM tags WHERE ip=? GROUP BY tag ORDER BY tag",
            (h["ip"],))]
        for t in h["tags"]:  # MAX() on text is alphabetical; fix up to the real highest severity
            sevs = [r[0] for r in conn.execute("SELECT severity FROM tags WHERE ip=? AND tag=?", (h["ip"], t["tag"]))]
            t["severity"] = max(sevs, key=lambda s: SEVERITIES.index(s) if s in SEVERITIES else 0)
        hosts.append(h)
    return {"query": q, "total": total, "page": page, "size": size, "hosts": hosts}


def match_ips(conn, q="", limit=5000):
    """Every host matching a query (not one page), in address order."""
    where, params = compile_query(q)
    return [r[0] for r in conn.execute(f"SELECT DISTINCT h.ip, h.ip_int {BASE}{where} ORDER BY h.ip_int, h.ip LIMIT ?", (*params, int(limit)))]


def facets(conn, q="", limit=8):
    where, params = compile_query(q)

    def top(expr, extra_join="", cond="1=1"):
        return [{"value": r[0], "count": r[1]} for r in conn.execute(
            f"SELECT {expr} AS v, COUNT(DISTINCT h.ip) AS c FROM hosts h LEFT JOIN services s ON s.ip=h.ip {extra_join} "
            f"WHERE ({where}) AND {cond} GROUP BY v ORDER BY c DESC LIMIT ?", (*params, limit))]

    return {
        "port": top("s.port", cond="s.port IS NOT NULL"),
        "service": top("s.service", cond="s.service != ''"),
        "product": top("s.product", cond="s.product != ''"),
        "tag": top("t.tag", "JOIN tags t ON t.ip=h.ip"),
        "country": top("h.country", cond="h.country != ''"),
        "org": top("h.org", cond="h.org != ''"),
    }


def export_rows(conn, q=""):
    """Yield one flat dict per (host, service) for export."""
    where, params = compile_query(q)
    cur = conn.execute(
        f"SELECT h.ip, h.hostnames, h.org, h.asn, h.country, h.ai_risk, s.port, s.transport, s.service, s.product, "
        f"s.version, s.cpe, s.banner {BASE}{where} ORDER BY h.ip_int, s.port", params)
    for r in cur:
        d = dict(r)
        d["hostnames"] = ",".join(json.loads(d["hostnames"] or "[]"))
        yield d
