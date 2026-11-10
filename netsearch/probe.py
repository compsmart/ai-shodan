"""Deep probe: look closely at the services already known on one host.

Three layers, all read-only (nothing here authenticates, guesses credentials or sends exploit payloads):

1. every known TCP port is re-probed (banner, TLS, HTTP) and asked a protocol-specific question from MENU,
2. web services are rendered in a headless browser (Playwright) to capture what a person would see:
   final URL, title, visible text, generator, JavaScript libraries, login forms and a screenshot,
3. services that are still unidentified go to `nmap -sV` when nmap is installed.

The AI step may ask for more probes, but only by name from MENU / WEB_PATHS and only on ports already
known for the host (see extra_probes). Callers must pass scanner.check_scope() first; deep_probe() does it too.
"""
import asyncio
import hashlib
import re
import shutil
import struct
import subprocess
from urllib.parse import urlparse

from . import config, fingerprint, scanner
from .db import now

MAX_SERVICES = 40      # ports probed per host
MAX_WEB = 12           # pages rendered per host
_printable = scanner._printable


class ProbeError(RuntimeError):
    pass


# ---------------------------------------------------------------- protocol probes

def _dns_version_query():
    q = b"\x07version\x04bind\x00\x00\x10\x00\x03"                       # version.bind TXT CH
    msg = b"\x4e\x53\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + q
    return struct.pack(">H", len(msg)) + msg


def _mongo_hello():
    doc = b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
    body = struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, -1) + doc
    return struct.pack("<iiii", 16 + len(body), 1, 0, 2004) + body


def _smb2_negotiate():
    dialects = (0x0202, 0x0210, 0x0300, 0x0302)
    header = b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) + b"\x00" * 16
    body = struct.pack("<HHHHI", 36, len(dialects), 1, 0, 0) + b"\x00" * 16 + b"\x00" * 8 + struct.pack("<4H", *dialects)
    msg = header + body
    return b"\x00" + struct.pack(">I", len(msg))[1:] + msg


# name -> (payload, read the server greeting first?, what it is for)
MENU = {
    "banner": (None, True, "wait for whatever the server says first"),
    "crlf": (b"\r\n\r\n", False, "blank lines; many text protocols answer with an error that names them"),
    "help": (b"HELP\r\n", False, "HELP command for text protocols"),
    "smtp-ehlo": (b"EHLO netsearch.invalid\r\nQUIT\r\n", True, "SMTP capabilities"),
    "imap-capability": (b"a1 CAPABILITY\r\na2 LOGOUT\r\n", True, "IMAP capabilities"),
    "pop3-capa": (b"CAPA\r\nQUIT\r\n", True, "POP3 capabilities"),
    "ftp-feat": (b"FEAT\r\nSYST\r\nQUIT\r\n", True, "FTP feature list and system type"),
    "ssh-kex": (b"SSH-2.0-NetSearch_0.1\r\n", True, "SSH key-exchange, cipher and MAC algorithms offered"),
    "redis-info": (b"INFO\r\n", False, "Redis INFO (answers only when no password is set)"),
    "memcached-version": (b"version\r\n", False, "Memcached version"),
    "zookeeper-srvr": (b"srvr", False, "ZooKeeper server details"),
    "rtsp-options": (b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", False, "RTSP methods and Server header (cameras, media servers)"),
    "amqp-header": (b"AMQP\x00\x00\x09\x01", False, "AMQP 0-9-1 handshake; RabbitMQ replies with product and version"),
    "postgres-ssl": (b"\x00\x00\x00\x08\x04\xd2\x16\x2f", False, "PostgreSQL SSLRequest; only PostgreSQL answers S or N"),
    "mongodb-hello": (_mongo_hello(), False, "MongoDB isMaster; reveals the wire version"),
    "dns-version": (_dns_version_query(), False, "DNS version.bind over TCP"),
    "smb-negotiate": (_smb2_negotiate(), False, "SMB2 negotiate; reveals the dialect and whether signing is required"),
    "rdp-negotiate": (scanner.PROBES[3389], False, "RDP negotiation; reveals the security protocol selected"),
    "tls": (None, False, "TLS handshake and certificate"),
    "http-get": (None, False, "plain HTTP GET /"),
}
# Read-only paths the model may ask for on a web service, as probe name "http:/path".
WEB_PATHS = ["/robots.txt", "/favicon.ico", "/version", "/api/version", "/api/v1/version", "/api/status", "/status",
             "/health", "/healthz", "/login", "/manifest.json", "/metrics", "/actuator/info", "/server-status",
             "/.well-known/security.txt", "/api", "/swagger.json", "/openapi.json", "/v2/", "/api/health",
             "/api/v4/version", "/api/server/version", "/system/info", "/sitemap.xml"]
# Probes sent automatically, by the service name the first pass came up with.
BY_SERVICE = {
    "ssh": ["ssh-kex"], "smtp": ["smtp-ehlo"], "smtps": [], "imap": ["imap-capability"], "pop3": ["pop3-capa"],
    "ftp": ["ftp-feat"], "postgresql": ["postgres-ssl"], "mongodb": ["mongodb-hello"], "amqp": ["amqp-header"],
    "dns": ["dns-version"], "smb": ["smb-negotiate"], "netbios-ssn": ["smb-negotiate"], "rtsp": ["rtsp-options"],
    "zookeeper": ["zookeeper-srvr"],
}
MONGO_WIRE = {0: "2.4", 2: "2.6", 3: "3.0", 4: "3.2", 5: "3.4", 6: "3.6", 7: "4.0", 8: "4.2", 9: "4.4", 13: "5.0",
              17: "6.0", 21: "7.0", 25: "8.0"}
SMB_DIALECTS = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1"}


def _decode(name, raw):
    """Turn a probe's raw answer into text the fingerprint rules and the model can read."""
    if name == "postgres-ssl":
        return f"postgres-ssl:{raw[:1].decode('latin-1')}" if raw[:1] in (b"S", b"N") and len(raw) == 1 else _printable(raw.decode("latin-1"), 300)
    if name == "mongodb-hello":
        i = raw.find(b"maxWireVersion\x00")
        if i > 0 and len(raw) >= i + 19:
            wire = struct.unpack("<i", raw[i + 15:i + 19])[0]
            newest = max((w for w in MONGO_WIRE if w <= wire), default=None)
            exact = MONGO_WIRE.get(wire) or (MONGO_WIRE[newest] + "+" if newest is not None else "")
            return f"mongodb-wire:{wire} version:{exact}"
    if name == "dns-version" and len(raw) > 14:
        txt = raw[2 + 12 + 18:]                      # skip length, header and the echoed question
        i = txt.find(b"\x00\x10\x00\x03")            # TXT CH in the answer
        if i >= 0 and len(txt) > i + 11:
            n = txt[i + 10]
            return "dns-version:" + _printable(txt[i + 11:i + 11 + n].decode("latin-1"), 120)
        return "dns-version:(hidden)"
    if name == "smb-negotiate" and raw[4:8] == b"\xfeSMB" and len(raw) >= 74:
        mode, dialect = struct.unpack("<HH", raw[70:74])
        return f"smb2 dialect={SMB_DIALECTS.get(dialect, hex(dialect))} signing={'required' if mode & 2 else 'not required'}"
    if name == "ssh-kex":
        text = raw.decode("latin-1")
        banner, _, rest = text.partition("\n")
        lists = [x for x in re.findall(r"[a-z0-9@.\-_,]{12,}", rest) if "," in x or "-" in x][:6]
        labels = ("kex", "host-key", "cipher", "cipher-s2c", "mac", "mac-s2c")
        return banner.strip() + "".join(f"\n{labels[i]}: {v[:300]}" for i, v in enumerate(lists))
    return _printable(raw.decode("latin-1"), 1200)


async def _exchange(ip, port, payload, greet, timeout):
    """Connect, optionally read the greeting, send payload, return what came back (None = could not connect)."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except Exception:
        return None
    try:
        data = await scanner._read(reader, min(timeout, 2.0) if payload else timeout, 16384) if greet else b""
        if payload:
            writer.write(payload)
            await writer.drain()
            data += (b"\n" if data else b"") + await scanner._read(reader, timeout, 16384)
        return data
    except OSError:
        return b""
    finally:
        await scanner._close(writer)


async def run_probe(ip, port, name, timeout=4.0):
    """Run one MENU probe. Returns text ('' = no answer, None = connection refused)."""
    if name == "tls":
        r = await scanner._tls_probe(ip, port, timeout)
        if r is None:
            return None
        t = r["tls"]
        return "; ".join(f"{k}={t[k]}" for k in ("version", "cipher", "cn", "issuer", "self_signed", "not_after", "san") if t.get(k) not in (None, "", []))[:900]
    if name == "http-get":
        raw = await _exchange(ip, port, scanner._http_request(ip), False, timeout)
        return None if raw is None else _printable(raw.decode("latin-1"), 1200)
    payload, greet, _ = MENU[name]
    raw = await _exchange(ip, port, payload, greet, timeout)
    return None if raw is None else _decode(name, raw)


async def _refresh(ip, services, timeout):
    """First pass over every known port: fresh banner/TLS/HTTP plus the protocol's own question."""
    sem = asyncio.Semaphore(6)

    async def one(old):
        port = old["port"]
        async with sem:
            svc = await scanner.probe_port(ip, port, timeout)
            if svc is None:
                return port, None
            service = svc.get("service") or old.get("service") or ""
            names = list(BY_SERVICE.get(service, []))
            if not names and not svc["extra"].get("http") and not svc.get("product"):
                names = ["help"] if svc.get("banner") else ["crlf", "help"]
            responses = {}
            for name in names:
                text = await run_probe(ip, port, name, timeout)
                if text:
                    responses[name] = text
            svc["extra"]["probe"] = {"at": now(), "responses": responses}
            return port, svc

    return dict(await asyncio.gather(*(one(s) for s in services)))


# ---------------------------------------------------------------- browser

_PAGE_JS = """() => {
  const t = (s, n) => (s == null ? '' : String(s)).replace(/\\s+/g, ' ').trim().slice(0, n);
  const meta = n => { const m = document.querySelector('meta[name="' + n + '" i]'); return m ? t(m.content, 200) : ''; };
  const libs = {};
  const lib = (name, fn) => { try { const v = fn(); if (v) libs[name] = v === true ? '' : t(v, 30); } catch (e) {} };
  lib('jQuery', () => window.jQuery && (window.jQuery.fn && window.jQuery.fn.jquery || true));
  lib('React', () => window.React ? (window.React.version || true) : !!document.querySelector('[data-reactroot], #__next, #root[data-reactroot]'));
  lib('Vue.js', () => window.Vue ? (window.Vue.version || true) : !!document.querySelector('[data-v-app], #__nuxt'));
  lib('AngularJS', () => window.angular && window.angular.version && window.angular.version.full);
  lib('Angular', () => { const e = document.querySelector('[ng-version]'); return e && e.getAttribute('ng-version'); });
  lib('Next.js', () => !!window.__NEXT_DATA__);
  lib('Nuxt', () => !!window.__NUXT__);
  lib('Bootstrap', () => window.bootstrap ? (window.bootstrap.Tooltip && window.bootstrap.Tooltip.VERSION || true) : false);
  lib('Svelte', () => !!document.querySelector('[class*="svelte-"]'));
  lib('Ember', () => window.Ember && window.Ember.VERSION);
  lib('Backbone', () => window.Backbone && window.Backbone.VERSION);
  lib('Alpine.js', () => window.Alpine && (window.Alpine.version || true));
  lib('htmx', () => window.htmx && (window.htmx.version || true));
  const icon = document.querySelector('link[rel~="icon" i]');
  return {
    title: t(document.title, 200), generator: meta('generator'), description: meta('description'),
    app_name: meta('application-name'), text: t(document.body ? document.body.innerText : '', 1800),
    scripts: Array.from(document.scripts).map(s => s.src).filter(Boolean).slice(0, 15).map(s => t(s, 160)),
    forms: document.forms.length, password_fields: document.querySelectorAll('input[type=password]').length,
    inputs: Array.from(document.querySelectorAll('input[name], input[id]')).slice(0, 12).map(i => t(i.name || i.id, 40)),
    headings: Array.from(document.querySelectorAll('h1, h2')).slice(0, 6).map(h => t(h.innerText, 100)).filter(Boolean),
    favicon: icon ? t(icon.href, 300) : '', libs: libs,
  };
}"""


def _launch(p, settings, ip):
    # No DNS at all: the page under test may only talk to the IP we were asked to look at.
    args = [f"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE {ip}", "--disable-extensions", "--mute-audio", "--no-first-run"]
    wanted = (settings.get("probe_browser_channel") or "").strip()
    last = None
    for channel in ([wanted] if wanted else [None, "msedge", "chrome"]):
        try:
            return p.chromium.launch(headless=True, args=args, **({"channel": channel} if channel else {}))
        except Exception as e:
            last = e
    raise ProbeError(f"no browser could be started ({str(last).splitlines()[0][:120]}); run: playwright install chromium")


def shot_name(ip, port):
    return f"{ip.replace(':', '_')}_{int(port)}.jpg"


def _render(browser, ip, port, scheme):
    """Open one web service in a fresh browser context and describe what is there."""
    url = f"{scheme}://{ip}:{port}/"
    blocked, out = set(), {"url": url}
    ctx = browser.new_context(ignore_https_errors=True, accept_downloads=False, service_workers="block",
                              viewport={"width": 1280, "height": 800})
    try:
        def guard(route):
            host = (urlparse(route.request.url).hostname or "").strip("[]")
            if host == ip:
                route.continue_()
            else:
                blocked.add(host[:80])
                route.abort()

        ctx.route("**/*", guard)
        if hasattr(ctx, "route_web_socket"):
            ctx.route_web_socket("**/*", lambda ws: ws.connect_to_server() if (urlparse(ws.url).hostname or "").strip("[]") == ip else ws.close())
        ctx.set_default_timeout(8000)
        page = ctx.new_page()
        try:
            resp = page.goto(url, wait_until="domcontentloaded", timeout=12000)
        except Exception as e:
            out["error"] = str(e).splitlines()[0][:200]
            resp = None
        if resp is not None:
            try:
                page.wait_for_load_state("networkidle", timeout=4000)
            except Exception:
                pass
            out["status"] = resp.status
            try:
                out["headers"] = {k.lower()[:40]: _printable(v, 300) for k, v in list(resp.all_headers().items())[:40]}
            except Exception:
                out["headers"] = {}
        if resp is not None or page.url not in ("about:blank", ""):
            out["final_url"] = page.url[:300]
            try:
                info = page.evaluate(_PAGE_JS)
                if isinstance(info, dict):
                    for k, v in info.items():
                        out[k] = v
            except Exception as e:
                out.setdefault("error", "page script: " + str(e).splitlines()[0][:160])
            try:
                out["_html"] = page.content()[:60000]
            except Exception:
                pass
            try:
                out["cookies"] = sorted({c["name"][:40] for c in ctx.cookies()})[:15]
            except Exception:
                pass
            try:
                config.SHOTS_DIR.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(config.SHOTS_DIR / shot_name(ip, port)), type="jpeg", quality=60)
                out["screenshot"] = shot_name(ip, port)
            except Exception:
                pass
            for path, key, limit in (("/favicon.ico", "favicon_md5", 0), ("/robots.txt", "robots", 400)):
                try:
                    r = ctx.request.get(f"{scheme}://{ip}:{port}{path}", timeout=5000, max_redirects=0)
                    if r.status == 200:
                        body = r.body()[:500000]
                        if key == "favicon_md5":
                            out[key] = hashlib.md5(body).hexdigest()
                        elif b"<html" not in body[:300].lower():
                            out[key] = _printable(body.decode("utf-8", "replace"), limit)
                except Exception:
                    pass
        if blocked:
            out["blocked_hosts"] = sorted(blocked)[:12]
    finally:
        try:
            ctx.close()
        except Exception:
            pass
    return out


def web_probe(ip, targets, settings):
    """Render [(port, scheme)] in a headless browser. Returns {port: page description}."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise ProbeError("Playwright is not installed; run: pip install playwright")
    results = {}
    with sync_playwright() as p:
        browser = _launch(p, settings, ip)
        try:
            for port, scheme in targets[:MAX_WEB]:
                try:
                    results[port] = _render(browser, ip, port, scheme)
                except Exception as e:  # one hostile page must not end the run
                    results[port] = {"url": f"{scheme}://{ip}:{port}/", "error": str(e).splitlines()[0][:200]}
        finally:
            try:
                browser.close()
            except Exception:
                pass
    return results


# ---------------------------------------------------------------- nmap fallback

def nmap_versions(ip, ports, timeout=240):
    """nmap -sV on specific ports. Returns normalised host records ([] when nmap is missing or fails)."""
    from . import sources
    exe = shutil.which("nmap")
    if not exe or not ports:
        return []
    cmd = [exe, "-sV", "-Pn", "-T4", "--version-intensity", "7", "--open", "-oX", "-", "-p", ",".join(str(p) for p in ports), ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return []
    return sources.parse_nmap_xml(proc.stdout) if proc.returncode == 0 else []


# ---------------------------------------------------------------- orchestration

def deep_probe(ip, services, settings):
    """Probe the known TCP services of one host. Blocking; call it from a worker thread.

    Returns {"services": [records for db.ingest], "nmap": [host records], "closed": [ports], "notes": [...], "web": n}.
    Raises scanner.ScopeError when the address may not be probed under the current settings.
    """
    scanner.check_scope([ip], settings)
    timeout = max(1.0, min(float(settings.get("probe_timeout") or 4.0), 15))
    known = [s for s in services if s.get("transport", "tcp") == "tcp"][:MAX_SERVICES]
    notes = []
    if len(services) > len(known):
        notes.append(f"{len(services) - len(known)} service(s) not probed (UDP or over the {MAX_SERVICES}-port limit)")
    fresh = asyncio.run(_refresh(ip, known, timeout))
    closed = sorted(p for p, svc in fresh.items() if svc is None)
    live = {p: svc for p, svc in fresh.items() if svc}

    pages = {}
    targets = [(p, "https" if svc["extra"].get("tls") else "http") for p, svc in sorted(live.items()) if svc["extra"].get("http")]
    if targets and settings.get("probe_browser"):
        try:
            pages = web_probe(ip, targets, settings)
        except ProbeError as e:
            notes.append(f"browser: {e}")
        except Exception as e:
            notes.append(f"browser failed: {str(e).splitlines()[0][:160]}")
    if len(targets) > MAX_WEB:
        notes.append(f"{len(targets) - MAX_WEB} web service(s) not rendered (limit {MAX_WEB} per host)")

    records = []
    for port, svc in sorted(live.items()):
        extra, page = svc["extra"], pages.get(port)
        if page:
            http = dict(extra.get("http") or {"status": page.get("status", 0), "server": (page.get("headers") or {}).get("server", ""), "headers": {}})
            html = page.pop("_html", "")
            if page.get("title"):
                http["title"] = page["title"]
            headers = {**(page.get("headers") or {}), **(http.get("headers") or {})}
            match = {**http, "headers": headers, "html": html, "generator": page.get("generator", ""), "libs": page.get("libs") or {}}
            product, version, cpe, apps = fingerprint.identify_http(match)
            if apps:
                http["apps"] = apps
            if page.get("generator"):
                http["generator"] = page["generator"]
            extra["http"] = http
            extra["probe"]["web"] = page
            svc.update(service="https" if extra.get("tls") else "http", product=product or svc.get("product", ""),
                       version=version if product else svc.get("version", ""), cpe=cpe if product else svc.get("cpe", ""))
        elif not svc.get("product"):
            svc.update({k: v for k, v in fingerprint.identify(port, svc.get("banner", ""), extra).items() if v})
        svc["probed"] = True
        records.append(svc)

    nmap_records = []
    unknown = [r["port"] for r in records if not r.get("product") and not r["extra"].get("http")]
    if unknown and settings.get("probe_nmap"):
        nmap_records = nmap_versions(ip, unknown)
        if nmap_records:
            notes.append(f"nmap -sV on {len(unknown)} unidentified port(s)")
    return {"services": records, "nmap": nmap_records, "closed": closed, "notes": notes, "web": len(pages)}


def menu_for_model():
    return {"protocol_probes": {k: v[2] for k, v in MENU.items()}, "web_paths": [f"http:{p}" for p in WEB_PATHS]}


def _http_path(ip, port, scheme, path, timeout):
    import httpx
    try:
        with httpx.Client(verify=False, follow_redirects=False, timeout=timeout, headers={"User-Agent": config.USER_AGENT}) as c:
            r = c.get(f"{scheme}://{ip}:{port}{path}")
    except httpx.HTTPError as e:
        return f"request failed ({type(e).__name__})"
    head = f"HTTP {r.status_code}" + "".join(f"\n{k}: {r.headers[k][:200]}" for k in ("server", "content-type", "location", "www-authenticate") if k in r.headers)
    return head + "\n\n" + _printable(r.content[:4000].decode("utf-8", "replace"), 900)


def extra_probes(ip, requests, services, settings):
    """Run probes a model asked for. Anything not on the menu, or on a port we do not know, is dropped.

    requests = [{"port": int, "probe": str}]. Returns ({port: {probe: text}}, [rejected descriptions]).
    """
    scanner.check_scope([ip], settings)
    limit = max(0, int(settings.get("enrich_ai_probes") or 0))
    timeout = max(1.0, min(float(settings.get("probe_timeout") or 4.0), 15))
    by_port = {s["port"]: s for s in services if s.get("transport", "tcp") == "tcp"}
    accepted, rejected, seen = [], [], set()
    for req in requests or []:
        port, name = req.get("port"), str(req.get("probe") or "").strip()
        key = (port, name)
        valid = name in MENU or (name.startswith("http:") and name[5:] in WEB_PATHS)
        if port not in by_port or not valid or key in seen:
            rejected.append(f"{port}/{name[:40]}")
        elif len(accepted) < limit:
            seen.add(key)
            accepted.append(key)
    results = {}

    async def protocol():
        for port, name in accepted:
            if not name.startswith("http:"):
                text = await run_probe(ip, port, name, timeout)
                results.setdefault(port, {})[name] = "(connection refused)" if text is None else (text or "(no answer)")

    asyncio.run(protocol())
    for port, name in accepted:
        if name.startswith("http:"):
            scheme = "https" if (by_port[port].get("extra") or {}).get("tls") else "http"
            results.setdefault(port, {})[name] = _http_path(ip, port, scheme, name[5:], timeout + 4)
    return results, rejected
