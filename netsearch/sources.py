"""Third-party sources and file importers. Everything returns normalised host records for db.ingest().

A source is a class with lookup(ip, settings) -> record | None and optionally
search(query, limit, settings) -> [record]. Register new ones in SOURCES.
"""
import base64
import ipaddress
import json
import socket
import xml.etree.ElementTree as ET

import httpx

from .config import USER_AGENT


class SourceError(RuntimeError):
    pass


def _client():
    return httpx.Client(timeout=20, headers={"User-Agent": USER_AGENT}, follow_redirects=True)


def _get(url, **kw):
    try:
        with _client() as c:
            r = c.get(url, **kw)
    except httpx.HTTPError as e:
        raise SourceError(f"request failed: {e.__class__.__name__}")
    return _check(r)


def _check(r):
    if r.status_code == 404:
        return None
    if r.status_code in (401, 403):
        raise SourceError(f"HTTP {r.status_code}: key missing, invalid, or not entitled to this endpoint")
    if r.status_code == 429:
        raise SourceError("HTTP 429: rate limit or quota exhausted")
    if r.status_code >= 400:
        raise SourceError(f"HTTP {r.status_code}: {r.text[:200]}")
    try:
        return r.json()
    except ValueError:
        raise SourceError("response was not JSON")


class Source:
    name = label = description = ""
    key_setting = None      # settings key holding the credential, if one is needed
    signup = ""
    can_search = False
    verified = True         # False = written from public API docs, not exercised against the live API
    public_only = True      # do not send private addresses to third parties

    def configured(self, settings):
        return not self.key_setting or bool(settings.get(self.key_setting))

    def _key(self, settings):
        key = settings.get(self.key_setting)
        if not key:
            raise SourceError(f"{self.label} needs an API key (setting: {self.key_setting})")
        return key

    def info(self, settings):
        return {"name": self.name, "label": self.label, "description": self.description,
                "key_setting": self.key_setting, "configured": self.configured(settings), "signup": self.signup,
                "can_search": self.can_search, "verified": self.verified}


# ---------------------------------------------------------------- Shodan family

def shodan_banner_to_service(b):
    extra = {}
    http = b.get("http") or {}
    if http:
        extra["http"] = {"status": http.get("status") or 0, "title": (http.get("title") or "")[:200],
                         "server": http.get("server") or "", "headers": {}, "body_preview": ""}
    cert = ((b.get("ssl") or {}).get("cert")) or {}
    if cert:
        subj, iss = cert.get("subject") or {}, cert.get("issuer") or {}
        extra["tls"] = {"cn": subj.get("CN", ""), "subject": json.dumps(subj), "issuer": json.dumps(iss),
                        "self_signed": subj == iss, "expired": bool(cert.get("expired"))}
    cpes = b.get("cpe23") or b.get("cpe") or []
    return {"port": b.get("port"), "transport": b.get("transport") or "tcp", "service": (b.get("_shodan") or {}).get("module", "").split("-")[0],
            "product": b.get("product") or "", "version": b.get("version") or "", "cpe": cpes[0] if cpes else "",
            "banner": b.get("data") or "", "extra": extra}


def shodan_host_fields(d):
    vulns = d.get("vulns") or []
    return {"hostnames": d.get("hostnames") or [], "org": d.get("org") or "", "asn": d.get("asn") or "",
            "isp": d.get("isp") or "", "os": d.get("os") or "", "city": d.get("city") or "",
            "country": d.get("country_code") or (d.get("location") or {}).get("country_code") or "",
            "vulns": list(vulns), "tags": d.get("tags") or []}


def _group_shodan_matches(matches):
    hosts = {}
    for b in matches:
        ip = b.get("ip_str")
        if not ip or b.get("port") is None:
            continue
        rec = hosts.setdefault(ip, {"ip": ip, "services": [], **shodan_host_fields(b)})
        rec["services"].append(shodan_banner_to_service(b))
    return list(hosts.values())


class InternetDB(Source):
    name, label = "internetdb", "Shodan InternetDB"
    description = "Free, keyless per-IP summary from Shodan: open ports, hostnames, CPEs, tags and known CVEs (no banners)."
    signup = "https://internetdb.shodan.io/"

    def lookup(self, ip, settings):
        d = _get(f"https://internetdb.shodan.io/{ip}")
        if not d or "ports" not in d:
            return None
        return {"ip": ip, "hostnames": d.get("hostnames") or [], "vulns": d.get("vulns") or [], "tags": d.get("tags") or [],
                "services": [{"port": p} for p in d.get("ports") or []]}


class Shodan(Source):
    name, label, key_setting, can_search = "shodan", "Shodan", "shodan_api_key", True
    description = "Host lookups and search. Free keys are rate-limited; search filters and paging need a paid plan."
    signup = "https://account.shodan.io/"

    def lookup(self, ip, settings):
        d = _get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": self._key(settings)})
        if not d:
            return None
        return {"ip": ip, **shodan_host_fields(d), "services": [shodan_banner_to_service(b) for b in d.get("data") or []]}

    def search(self, query, limit, settings):
        d = _get("https://api.shodan.io/shodan/host/search", params={"key": self._key(settings), "query": query})
        return _group_shodan_matches((d or {}).get("matches") or [])[:limit]


# ---------------------------------------------------------------- Censys / ZoomEye (unverified)

class Censys(Source):
    name, label, key_setting, verified = "censys", "Censys", "censys_api_token", False
    description = "Host lookups through the Censys Platform API using a personal access token."
    signup = "https://accounts.censys.io/"

    def lookup(self, ip, settings):
        d = _get(f"https://api.platform.censys.io/v3/global/asset/host/{ip}",
                 headers={"Authorization": f"Bearer {self._key(settings)}", "Accept": "application/json"})
        res = ((d or {}).get("result") or {}).get("resource") or (d or {}).get("result") or {}
        if not res:
            return None
        services = []
        for s in res.get("services") or []:
            sw = (s.get("software") or [{}])[0]
            services.append({"port": s.get("port"), "transport": (s.get("transport_protocol") or "tcp").lower(),
                             "service": (s.get("protocol") or s.get("service_name") or "").lower(),
                             "product": sw.get("product") or "", "version": sw.get("version") or "",
                             "banner": s.get("banner") or ""})
        asn = res.get("autonomous_system") or {}
        loc = res.get("location") or {}
        return {"ip": ip, "services": [s for s in services if s["port"]],
                "hostnames": (res.get("dns") or {}).get("names") or [],
                "org": asn.get("name") or "", "asn": f"AS{asn['asn']}" if asn.get("asn") else "",
                "country": loc.get("country_code") or "", "city": loc.get("city") or ""}


class ZoomEye(Source):
    name, label, key_setting, can_search, verified = "zoomeye", "ZoomEye", "zoomeye_api_key", True, False
    description = "Search and host lookups through the ZoomEye v2 API (daily quota on free accounts)."
    signup = "https://www.zoomeye.ai/"

    def search(self, query, limit, settings):
        try:
            with _client() as c:
                r = c.post("https://api.zoomeye.ai/v2/search", headers={"API-KEY": self._key(settings)},
                           json={"qbase64": base64.b64encode(query.encode()).decode(), "page": 1, "pagesize": min(limit, 100)})
        except httpx.HTTPError as e:
            raise SourceError(f"request failed: {e.__class__.__name__}")
        hosts = {}
        for m in (_check(r) or {}).get("data") or []:
            ip, port = m.get("ip"), m.get("port")
            if not ip or not port:
                continue
            rec = hosts.setdefault(ip, {"ip": ip, "services": [], "hostnames": [], "org": m.get("organization.name") or m.get("isp.name") or "",
                                        "country": m.get("country.code") or "", "city": m.get("city.name") or "",
                                        "asn": f"AS{m['asn']}" if m.get("asn") else "", "os": m.get("os") or ""})
            if m.get("domain"):
                rec["hostnames"].append(m["domain"])
            extra = {"http": {"status": 0, "title": str(m.get("title") or "")[:200], "server": "", "headers": {}, "body_preview": ""}} if m.get("title") else {}
            rec["services"].append({"port": port, "service": m.get("service") or "", "product": m.get("product") or "",
                                    "version": m.get("version") or "", "banner": m.get("banner") or m.get("header") or "", "extra": extra})
        return list(hosts.values())[:limit]

    def lookup(self, ip, settings):
        found = self.search(f'ip="{ip}"', 50, settings)
        return found[0] if found else None


# ---------------------------------------------------------------- free enrichment

class ReverseDNS(Source):
    name, label, public_only = "rdns", "Reverse DNS", False
    description = "PTR lookup using this machine's resolver."

    def lookup(self, ip, settings):
        try:
            if ipaddress.ip_address(ip).is_loopback:
                return None   # a hosts-file alias for loopback says nothing about the machine
            name = socket.gethostbyaddr(ip)[0]
        except OSError:
            return None
        return {"ip": ip, "hostnames": [name]} if name and name != ip else None


class GeoIP(Source):
    name, label = "geoip", "ip-api.com (geo / ASN)"
    description = "Country, city, ISP, org and ASN from ip-api.com's free endpoint (plain HTTP, non-commercial use, ~45 requests/minute)."
    signup = "https://ip-api.com/docs"

    def lookup(self, ip, settings):
        d = _get(f"http://ip-api.com/json/{ip}", params={"fields": "status,countryCode,city,isp,org,as,reverse"})
        if not d or d.get("status") != "success":
            return None
        return {"ip": ip, "country": d.get("countryCode") or "", "city": d.get("city") or "", "isp": d.get("isp") or "",
                "org": d.get("org") or d.get("isp") or "", "asn": (d.get("as") or "").split(" ")[0],
                "hostnames": [d["reverse"]] if d.get("reverse") else []}


SOURCES = {s.name: s for s in (InternetDB(), Shodan(), Censys(), ZoomEye(), ReverseDNS(), GeoIP())}
DEFAULT_ENRICH = ["rdns", "internetdb", "geoip"]


def enrich(conn, ip, names=None, settings=None):
    """Look an IP up in the given sources (default: free ones plus any configured keyed source) and ingest."""
    from . import db
    settings = settings or db.get_settings(conn)
    if names is None:
        names = DEFAULT_ENRICH + [n for n, s in SOURCES.items() if s.key_setting and s.configured(settings)]
    public = ipaddress.ip_address(ip).is_global
    results = {}
    for name in names:
        src = SOURCES.get(name)
        if src is None:
            results[name] = "error: unknown source"
            continue
        if src.public_only and not public:
            results[name] = "skipped: private address"
            continue
        try:
            rec = src.lookup(ip, settings)
        except SourceError as e:
            results[name] = f"error: {e}"
            continue
        if rec:
            db.ingest(conn, rec, name)
            results[name] = f"ok: {len(rec.get('services') or [])} service(s)"
        else:
            results[name] = "no data"
    db.log(conn, "enrich", f"{ip}: " + ", ".join(f"{k}={v.split(':')[0]}" for k, v in results.items()))
    return results


def remote_search(conn, name, query, limit=50):
    from . import db
    src = SOURCES.get(name)
    if src is None or not src.can_search:
        raise SourceError(f"source '{name}' does not support search")
    records = src.search(query, limit, db.get_settings(conn))
    for rec in records:
        db.ingest(conn, rec, name)
    db.log(conn, "source-search", f"{name}: '{query}' -> {len(records)} host(s)")
    return [r["ip"] for r in records]


# ---------------------------------------------------------------- file importers

def parse_nmap_xml(text):
    records = []
    for host in ET.fromstring(text).iter("host"):
        addr = next((a.get("addr") for a in host.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not addr:
            continue
        rec = {"ip": addr, "services": [],
               "hostnames": [h.get("name") for h in host.iter("hostname") if h.get("name")]}
        osmatch = host.find("os/osmatch")
        if osmatch is not None:
            rec["os"] = osmatch.get("name", "")
        for p in host.iter("port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            s = p.find("service")
            s = s.attrib if s is not None else {}
            cpe = p.find("service/cpe")
            scripts = {x.get("id"): (x.get("output") or "")[:1000] for x in p.findall("script")}
            rec["services"].append({
                "port": int(p.get("portid")), "transport": p.get("protocol") or "tcp",
                "service": ("https" if s.get("tunnel") == "ssl" and s.get("name") == "http" else s.get("name", "")),
                "product": s.get("product", ""), "version": s.get("version", "").removeprefix("for_Windows_"),
                "cpe": cpe.text if cpe is not None else "",
                "banner": " ".join(x for x in (s.get("product"), s.get("version"), s.get("extrainfo")) if x),
                "extra": {"nmap": {"extrainfo": s.get("extrainfo", ""), "scripts": scripts}} if (scripts or s.get("extrainfo")) else {},
                **({"weak": True} if s.get("method") == "table" else {})})
        if rec["services"] or rec["hostnames"]:
            records.append(rec)
    return records


def _generic_line(d):
    """Normalise one JSON object from a Shodan export, masscan, Rapid7 Sonar or a generic dump."""
    if "ip_str" in d and "port" in d:                                   # Shodan export
        return {"ip": d["ip_str"], **shodan_host_fields(d), "services": [shodan_banner_to_service(d)]}
    if "ports" in d and "ip" in d:                                      # masscan -oJ
        return {"ip": d["ip"], "services": [
            {"port": p["port"], "transport": p.get("proto", "tcp"), "service": (p.get("service") or {}).get("name", ""),
             "banner": (p.get("service") or {}).get("banner", "")} for p in d["ports"] if p.get("port")]}
    if d.get("type") in ("ptr", "a") and "name" in d and "value" in d:  # Sonar rDNS / FDNS
        ip, name = (d["name"], d["value"]) if d["type"] == "ptr" else (d["value"], d["name"])
        return {"ip": ip, "hostnames": [name]}
    ip = d.get("ip") or d.get("saddr") or d.get("host") or d.get("address")
    if not ip:
        return None
    rec = {"ip": ip, "hostnames": [h for h in ([d.get("hostname"), d.get("domain")] + list(d.get("hostnames") or [])) if h],
           "org": d.get("org") or "", "country": d.get("country") or d.get("country_code") or "", "asn": d.get("asn") or "",
           "services": [s for s in (d.get("services") or []) if isinstance(s, dict) and s.get("port")]}  # NetSearch's own shape
    port = d.get("port") or d.get("sport") or d.get("dport")
    if port:
        rec["services"].append({"port": int(port), "transport": d.get("transport") or d.get("proto") or "tcp",
                                "service": d.get("service") or "", "product": d.get("product") or "",
                                "version": d.get("version") or "", "banner": str(d.get("banner") or d.get("data") or "")})
    return rec


def parse_bytes(data, fmt="auto"):
    """Parse an uploaded/imported file. Formats: nmap-xml, jsonl (Shodan export, Sonar, generic), json (masscan/array)."""
    text = data.decode("utf-8", "replace").lstrip("﻿").strip()
    if fmt == "auto":
        fmt = "nmap-xml" if text.startswith("<") else "json" if text.startswith("[") else "jsonl"
    if fmt == "nmap-xml":
        return parse_nmap_xml(text)
    if fmt == "json":
        text = text.rstrip().rstrip(",")
        if not text.endswith("]"):
            text += "]"   # masscan leaves the array open when interrupted
        items = json.loads(text)
    elif fmt == "jsonl":
        items = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{"):
                try:
                    items.append(json.loads(line))
                except ValueError:
                    continue
    else:
        raise ValueError(f"unknown format: {fmt}")
    records = []
    for d in items:
        rec = _generic_line(d) if isinstance(d, dict) else None
        if rec:
            try:
                ipaddress.ip_address(str(rec["ip"]).strip())
                records.append(rec)
            except ValueError:
                continue
    return records


def import_bytes(conn, data, fmt="auto", source="import"):
    from . import db
    records = parse_bytes(data, fmt)
    for rec in records:
        db.ingest(conn, rec, source)
    db.log(conn, "import", f"{len(records)} record(s) via {source}")
    return {"records": len(records), "hosts": len({r["ip"] for r in records})}
