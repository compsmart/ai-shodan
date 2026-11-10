"""Deterministic tagging rules. Rule tags (origin='rule') are recomputed on every ingest;
tags from AI, agents, humans and third-party sources are left alone.

CATALOG maps tag -> (severity, description). Tags outside the catalog are allowed (severity info
unless the writer supplies one).
"""
import json
import re
from datetime import datetime, timezone

CATALOG = {
    # exposure
    "exposed-database": ("high", "Database service reachable on a public address"),
    "no-auth": ("high", "Service answered a data/admin request without authentication"),
    "has-cve": ("high", "A source reports known CVEs for this host"),
    "ics": ("high", "Industrial control protocol exposed"),
    "cleartext": ("medium", "Unencrypted protocol that carries credentials"),
    "admin-panel": ("medium", "Administrative or management web interface"),
    "dir-listing": ("medium", "Web server directory listing enabled"),
    "outdated-software": ("medium", "Version is older than a conservative support threshold"),
    "expired-cert": ("medium", "TLS certificate has expired"),
    "weak-tls": ("medium", "Negotiated TLS 1.0/1.1 or SSLv3"),
    "container-api": ("medium", "Container / orchestration API exposed"),
    "self-signed-cert": ("low", "TLS certificate is self-signed"),
    "default-page": ("low", "Web server default / placeholder page"),
    "dev-server": ("low", "Development server not meant for exposure"),
    "many-ports": ("low", "Unusually many open ports (possible honeypot, tarpit or misconfigured firewall)"),
    "nonstandard-port": ("info", "Well-known service on an unusual port"),
    # classification
    "database": ("info", "Database service"),
    "remote-access": ("info", "Remote administration service"),
    "web": ("info", "HTTP(S) service"),
    "mail": ("info", "Mail service"),
    "iot": ("info", "IoT / embedded device"),
    "proxy": ("info", "Proxy service"),
    "login-page": ("info", "Web login form"),
    "file-sharing": ("info", "File sharing service"),
    # commonly written by AI / agents
    "suspicious": ("high", "Flagged as suspicious by analysis"),
    "unusual": ("medium", "Flagged as unusual by analysis"),
    "interesting": ("low", "Flagged as worth a look"),
    "honeypot": ("low", "Likely a honeypot"),
}

DB_SERVICES = {"mysql", "postgresql", "redis", "mongodb", "memcached", "elasticsearch", "mssql", "oracle",
               "cassandra", "couchdb", "zookeeper"}
DB_PRODUCTS = {"Elasticsearch", "CouchDB", "MySQL", "MariaDB", "Redis", "MongoDB", "Memcached"}
REMOTE = {"ssh", "rdp", "vnc", "telnet", "winrm"}
MAIL = {"smtp", "smtps", "pop3", "pop3s", "imap", "imaps"}
ICS_PORTS = {502, 102, 47808, 44818, 20000, 1911}
IOT = {"rtsp", "mqtt"}
FILES = {"ftp", "smb", "nfs", "afp", "rsync", "netbios-ssn"}
ADMIN_APPS = {"Grafana", "Kibana", "phpMyAdmin", "Jenkins", "Portainer", "Prometheus", "RabbitMQ Management",
              "pfSense", "MikroTik RouterOS", "Synology DSM", "Proxmox VE", "Webmin", "Adminer", "Traefik",
              "Jupyter", "Apache Tomcat", "Pi-hole", "MinIO"}
CONTAINER = {"Docker API", "Kubernetes API"}
DEV = {"Werkzeug", "Python SimpleHTTPServer", "Python http.server", "Uvicorn"}
CANON_PORTS = {"ssh": {22}, "telnet": {23}, "ftp": {21}, "rdp": {3389}, "mysql": {3306}, "redis": {6379},
               "smtp": {25, 587, 465}, "vnc": {5900, 5901, 5902}, "memcached": {11211}}
# Conservative "clearly old" floors; a heuristic for triage, not a vulnerability verdict.
OUTDATED = {"OpenSSH": (8, 0), "nginx": (1, 20), "Apache httpd": (2, 4, 50), "Microsoft IIS": (10,),
            "PHP": (8, 1), "MySQL": (8, 0), "MariaDB": (10, 5), "Redis": (6, 2), "Elasticsearch": (7, 17),
            "vsftpd": (3, 0), "ProFTPD": (1, 3, 6), "Exim": (4, 96), "lighttpd": (1, 4, 60),
            "Apache Tomcat": (9,), "Memcached": (1, 6)}
DEFAULT_TITLES = re.compile(r"Welcome to nginx|Apache2 \w+ Default Page|IIS Windows|Test Page for|It works|Welcome to CentOS", re.I)
LOGIN_TITLES = re.compile(r"\b(log ?in|sign ?in|authentication required)\b", re.I)


def vtuple(version):
    m = re.match(r"(\d+(?:\.\d+)*)", version or "")
    return tuple(int(x) for x in m.group(1).split(".")) if m else ()


def compute(host, services):
    """Return a list of (port, tag, reason). port 0 = host-level."""
    out = []
    add = lambda port, tag, reason="": out.append((port, tag, reason))
    public = bool(host.get("is_public"))
    if host.get("vulns"):
        add(0, "has-cve", f"{len(host['vulns'])} CVE(s) reported: {', '.join(host['vulns'][:5])}")
    if len(services) >= 20:
        add(0, "many-ports", f"{len(services)} open ports")

    for s in services:
        port, svc, product, version = s["port"], s["service"], s["product"], s["version"]
        extra, banner = s.get("extra") or {}, s.get("banner") or ""
        http, tls = extra.get("http") or {}, extra.get("tls") or {}
        apps = {a["name"]: a.get("version", "") for a in http.get("apps") or []}
        label = f"{product or svc} on {port}"

        if svc in DB_SERVICES or product in DB_PRODUCTS:
            add(port, "database")
            if public:
                add(port, "exposed-database", f"{label} is reachable from the internet")
        if svc in REMOTE:
            add(port, "remote-access")
        if svc in MAIL:
            add(port, "mail")
        if svc in FILES:
            add(port, "file-sharing")
        if svc in ("http", "https"):
            add(port, "web")
        if svc in ("socks", "http-proxy") or product == "Squid":
            add(port, "proxy")
        if svc in IOT or product in ("Hikvision web", "GoAhead", "RomPager", "Home Assistant", "OctoPrint"):
            add(port, "iot")
        if port in ICS_PORTS:
            add(port, "ics", f"industrial protocol port {port} ({svc or 'unknown'}) is open")
        if svc in ("telnet", "ftp") or (svc == "vnc" and not tls) or \
                (svc == "http" and "basic" in (http.get("headers") or {}).get("www-authenticate", "").lower()):
            add(port, "cleartext", f"{svc} sends credentials unencrypted")

        if "redis_version" in banner:
            add(port, "no-auth", "Redis answered INFO without authentication")
        elif svc == "memcached" and banner.startswith("VERSION"):
            add(port, "no-auth", "Memcached answered without authentication")
        elif product in ("Elasticsearch", "CouchDB") and http.get("status") == 200:
            add(port, "no-auth", f"{product} root endpoint is readable without authentication")
        elif product == "Docker API" and svc == "http":
            add(port, "no-auth", "Docker API reachable over plain HTTP")
        if product in CONTAINER or set(apps) & CONTAINER or svc in ("kubelet",):
            add(port, "container-api")

        hit = (set(apps) | {product}) & ADMIN_APPS
        if hit:
            add(port, "admin-panel", f"{sorted(hit)[0]} interface")
        title = http.get("title") or ""
        if title.startswith("Index of /") or title.startswith("Directory listing for"):
            add(port, "dir-listing", f"title: {title[:80]}")
        if DEFAULT_TITLES.search(title):
            add(port, "default-page", f"title: {title[:80]}")
        if LOGIN_TITLES.search(title) or http.get("status") == 401:
            add(port, "login-page")
        if product in DEV or set(apps) & DEV:
            add(port, "dev-server", f"{product} is a development server")

        if tls:
            if tls.get("self_signed"):
                add(port, "self-signed-cert")
            exp = tls.get("not_after") or ""
            if tls.get("expired") or (exp and exp < datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")):
                add(port, "expired-cert", f"certificate expired {exp}".strip())
            if tls.get("version") in ("TLSv1", "TLSv1.1", "SSLv3"):
                add(port, "weak-tls", f"negotiated {tls['version']}")

        for name, ver in [(product, version), *apps.items()]:
            floor = OUTDATED.get(name)
            if floor and vtuple(ver) and vtuple(ver) < floor:
                add(port, "outdated-software", f"{name} {ver} is older than {'.'.join(map(str, floor))}")
        if svc in CANON_PORTS and port not in CANON_PORTS[svc]:
            add(port, "nonstandard-port", f"{svc} on port {port}")
    return out


def apply(conn, ip):
    """Recompute rule tags for one host."""
    from .db import host_dict, now, service_dict
    row = conn.execute("SELECT * FROM hosts WHERE ip=?", (ip,)).fetchone()
    if row is None:
        return []
    services = [service_dict(r) for r in conn.execute("SELECT * FROM services WHERE ip=?", (ip,))]
    tags = compute(host_dict(row), services)
    conn.execute("DELETE FROM tags WHERE ip=? AND origin='rule'", (ip,))
    ts = now()
    seen = set()
    for port, tag, reason in tags:
        if (port, tag) in seen:
            continue
        seen.add((port, tag))
        conn.execute("INSERT OR IGNORE INTO tags(ip, port, tag, severity, origin, reason, created) VALUES(?,?,?,?,?,?,?)",
                     (ip, port, tag, CATALOG[tag][0], "rule", reason, ts))
    return tags


def catalog_with_counts(conn):
    counts = {r[0]: (r[1], r[2]) for r in conn.execute(
        "SELECT tag, COUNT(DISTINCT ip), MAX(severity) FROM tags GROUP BY tag")}
    sev = {r[0]: r[1] for r in conn.execute("SELECT tag, severity FROM tags GROUP BY tag")}
    out = []
    for tag in sorted(set(CATALOG) | set(counts)):
        severity, desc = CATALOG.get(tag, (sev.get(tag, "info"), "Custom tag"))
        out.append({"tag": tag, "severity": severity, "description": desc, "hosts": counts.get(tag, (0,))[0]})
    return out
