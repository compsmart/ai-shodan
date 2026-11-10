"""Native asyncio scanner: TCP connect, banner grab, a few read-only protocol probes, TLS + HTTP.

It never authenticates, brute-forces or sends exploit payloads. Scope is enforced by check_scope():
reserved/multicast/link-local space is always refused, the exclude list is honoured, and
internet-routable targets require the scan_allow_public setting.
"""
import asyncio
import hashlib
import ipaddress
import random
import re
import socket
import ssl

from . import fingerprint
from .config import USER_AGENT

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 102, 110, 111, 135, 139, 143, 179, 389, 443, 445, 465, 502, 515, 548, 554, 587,
    631, 636, 873, 993, 995, 1080, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2181, 2222, 2375, 2376,
    3000, 3128, 3306, 3389, 4443, 5000, 5001, 5060, 5432, 5601, 5672, 5900, 5901, 5984, 5985, 6379, 6443, 6667,
    7001, 7443, 7547, 8000, 8008, 8009, 8010, 8080, 8081, 8082, 8083, 8086, 8088, 8090, 8123, 8181, 8443, 8500, 8834,
    8880, 8888, 9000, 9001, 9042, 9090, 9092, 9100, 9200, 9300, 9418, 9443, 9999, 10000, 10250, 11211, 15672,
    27017, 27018, 50000,
]
PRESETS = {
    "top100": TOP_PORTS,
    "top20": [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443],
    "web": [80, 81, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443],
    "databases": [1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 11211, 27017],
    "remote": [22, 23, 2222, 3389, 5900, 5901, 5985],
}
TLS_PORTS = {443, 465, 636, 993, 995, 2083, 2087, 2376, 4443, 6443, 7443, 8443, 8834, 9443, 10250}
HTTP_PORTS = {80, 81, 2082, 2086, 2375, 3000, 3128, 5000, 5001, 5601, 5984, 5985, 7001, 7547, 8000, 8008, 8010, 8080,
              8081, 8083, 8086, 8088, 8090, 8123, 8181, 8500, 8880, 8888, 9000, 9001, 9090, 9200, 10000, 15672}
# Read-only protocol probes sent when the server does not speak first.
PROBES = {
    6379: b"INFO\r\n",
    11211: b"version\r\n",
    2181: b"srvr",
    3389: bytes.fromhex("030000130ee000000000000100080003000000"),
}
# Ports where sending an HTTP request is pointless (binary protocols that stay silent).
NO_HTTP = {135, 139, 445, 1433, 1521, 5432, 27017, 27018, 9042, 9092, 502, 102, 5672, 1883}


class ScopeError(ValueError):
    pass


# ---------------------------------------------------------------- targets / ports

def parse_ports(spec):
    spec = (spec or "top100").strip().lower()
    ports = set()
    for item in re.split(r"[,\s]+", spec):
        if not item:
            continue
        if item in PRESETS:
            ports.update(PRESETS[item])
        elif "-" in item:
            lo, hi = (int(x) for x in item.split("-", 1))
            if not 0 < lo <= hi <= 65535:
                raise ValueError(f"bad port range: {item}")
            ports.update(range(lo, hi + 1))
        elif item.isdigit() and 0 < int(item) <= 65535:
            ports.add(int(item))
        else:
            raise ValueError(f"bad port spec: {item} (use numbers, ranges, or {', '.join(PRESETS)})")
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


def parse_targets(spec, max_hosts=4096):
    """Expand 'a.b.c.d', CIDR, 'a.b.c.d-e.f.g.h', 'a.b.c.d-N' and hostnames into a list of IPv4 strings."""
    ips, seen = [], set()

    def push(addr):
        s = str(addr)
        if s not in seen:
            seen.add(s)
            ips.append(s)
            if len(ips) > max_hosts:
                raise ScopeError(f"target list exceeds scan_max_hosts ({max_hosts}); split the job or raise the limit")

    for item in re.split(r"[,\s]+", (spec or "").strip()):
        if not item:
            continue
        try:
            if "/" in item:
                net = ipaddress.ip_network(item, strict=False)
                if net.version != 4:
                    raise ScopeError("only IPv4 ranges can be scanned")
                if net.num_addresses > max_hosts * 2:
                    raise ScopeError(f"{item} has {net.num_addresses} addresses; limit is scan_max_hosts ({max_hosts})")
                for addr in (net.hosts() if net.prefixlen < 31 else net):
                    push(addr)
            elif re.fullmatch(r"[\d.]+-[\d.]+", item):
                a, b = item.split("-", 1)
                start = ipaddress.IPv4Address(a)
                end = ipaddress.IPv4Address(b if "." in b else a.rsplit(".", 1)[0] + "." + b)
                if int(end) < int(start) or int(end) - int(start) > max_hosts:
                    raise ScopeError(f"bad or oversized range: {item}")
                for n in range(int(start), int(end) + 1):
                    push(ipaddress.IPv4Address(n))
            elif re.fullmatch(r"[\d.]+", item):
                push(ipaddress.IPv4Address(item))
            else:
                infos = socket.getaddrinfo(item, None, socket.AF_INET, socket.SOCK_STREAM)
                push(ipaddress.IPv4Address(infos[0][4][0]))
        except ScopeError:
            raise
        except (ValueError, OSError) as e:
            raise ScopeError(f"cannot parse target '{item}': {e}")
    if not ips:
        raise ScopeError("no targets given")
    return ips


def check_scope(ips, settings):
    """Raise ScopeError unless every address may be scanned under the current settings."""
    exclude = []
    for item in re.split(r"[,\s]+", settings.get("scan_exclude") or ""):
        if item:
            try:
                exclude.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                raise ScopeError(f"bad entry in scan_exclude: {item}")
    public = []
    for ip in ips:
        a = ipaddress.ip_address(ip)
        if a.is_multicast or a.is_unspecified or a.is_link_local or a.is_reserved:
            raise ScopeError(f"{ip} is in reserved/multicast/link-local space and is never scanned")
        if any(a in net for net in exclude):
            raise ScopeError(f"{ip} is on the exclude list (scan_exclude)")
        if not a.is_private:
            public.append(ip)
    if public and not settings.get("scan_allow_public"):
        raise ScopeError(
            f"{len(public)} target(s) such as {public[0]} are internet-routable. Scanning public addresses is off by default: "
            "only scan networks you own or are authorised to test, then enable 'scan_allow_public' in Settings "
            "(or: netsearch config set scan_allow_public true).")
    return len(public)


# ---------------------------------------------------------------- probing

def _printable(text, limit=4000):
    return re.sub(r"[^\x09\x0a\x0d\x20-\x7e]", ".", text)[:limit]


async def _read(reader, first_timeout, limit=65536):
    buf, timeout = b"", first_timeout
    try:
        while len(buf) < limit:
            chunk = await asyncio.wait_for(reader.read(8192), timeout)
            if not chunk:
                break
            buf += chunk
            timeout = 0.4
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        pass
    return buf


async def _close(writer):
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 1)
    except Exception:
        pass


def _tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:  # we observe, not trust: accept legacy protocol versions and ciphers so they can be reported
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ssl.SSLError, ValueError):
        pass
    return ctx


def _http_request(host):
    return (f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\n"
            "Connection: close\r\n\r\n").encode()


def parse_cert(der):
    info = {"sha256": hashlib.sha256(der).hexdigest()}
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        cert = x509.load_der_x509_certificate(der)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        info.update(
            subject=cert.subject.rfc4514_string(), issuer=cert.issuer.rfc4514_string(),
            cn=str(cn[0].value) if cn else "", self_signed=cert.subject == cert.issuer,
            not_before=cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            not_after=cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"))
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            info["san"] = san.get_values_for_type(x509.DNSName)[:50]
        except x509.ExtensionNotFound:
            info["san"] = []
    except Exception as e:  # malformed certificates are data, not errors
        info["parse_error"] = str(e)[:200]
    return info


async def _tls_probe(ip, port, timeout):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=_tls_context(), ssl_handshake_timeout=timeout + 2), timeout + 3)
    except Exception:
        return None
    try:
        obj = writer.get_extra_info("ssl_object")
        tls = {"version": obj.version(), "cipher": (obj.cipher() or [""])[0]}
        der = obj.getpeercert(binary_form=True)
        if der:
            tls.update(parse_cert(der))
        raw = await _read(reader, 0.3)
        if not raw:
            writer.write(_http_request(ip))
            await writer.drain()
            raw = await _read(reader, timeout)
        return {"tls": tls, "raw": raw}
    except Exception:
        return {"tls": {}, "raw": b""}
    finally:
        await _close(writer)


def parse_http(raw):
    """Parse a raw HTTP response into the dict stored at extra['http'] (None if it is not HTTP)."""
    if not raw.startswith(b"HTTP/"):
        return None
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    m = re.match(r"HTTP/[\d.]+ (\d{3})", lines[0])
    headers = {}
    for line in lines[1:]:
        k, sep, v = line.partition(":")
        if sep:
            headers[k.strip().lower()] = _printable(v.strip(), 300)
    text = body[:200000].decode("utf-8", "replace")
    title = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    keep = ("server", "x-powered-by", "www-authenticate", "location", "content-type", "x-jenkins", "via",
            "x-generator", "x-frame-options", "strict-transport-security", "set-cookie", "kbn-version", "kbn-name",
            "x-influxdb-version", "x-plex-protocol", "docker-distribution-api-version", "x-gitea-version",
            "x-nextcloud-version", "x-aspnet-version", "x-runtime", "x-drupal-cache")
    return {
        "status": int(m.group(1)) if m else 0,
        "server": headers.get("server", ""),
        "title": re.sub(r"\s+", " ", title.group(1)).strip()[:200] if title else "",
        "headers": {k: (v.split("=")[0] if k == "set-cookie" else v) for k, v in headers.items() if k in keep},
        "body_preview": re.sub(r"\s+", " ", text)[:1500],
        "head": _printable(head.decode("latin-1"), 3000),
    }


async def probe_port(ip, port, timeout=2.0):
    """Return a service dict if the port is open, else None."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except Exception:
        return None
    raw, tried_http, extra = b"", False, {}
    try:
        if port not in TLS_PORTS:
            raw = await _read(reader, 0.4 if port in HTTP_PORTS else 1.5)
            if not raw:
                probe = PROBES.get(port)
                if probe is None and port not in NO_HTTP:
                    probe, tried_http = _http_request(ip), True
                if probe:
                    writer.write(probe)
                    await writer.drain()
                    raw = await _read(reader, timeout)
    except OSError:
        pass
    finally:
        await _close(writer)

    wants_tls = port in TLS_PORTS or (tried_http and not raw) or b"HTTPS port" in raw or b"SSL-enabled" in raw
    if wants_tls:
        result = await _tls_probe(ip, port, timeout)
        if result and result["tls"]:
            extra["tls"], raw = result["tls"], result["raw"]
        elif port in TLS_PORTS and not raw:  # not TLS after all: fall back to plain HTTP
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
                writer.write(_http_request(ip))
                await writer.drain()
                raw = await _read(reader, timeout)
                await _close(writer)
            except Exception:
                pass

    http = parse_http(raw)
    if http:
        banner = http.pop("head")
        extra["http"] = http
        match_text = banner
    else:
        match_text = raw[:4000].decode("latin-1")
        banner = _printable(match_text)
    svc = {"port": port, "transport": "tcp", "banner": banner, "extra": extra}
    svc.update(fingerprint.identify(port, match_text, extra))
    return svc


class RateLimiter:
    def __init__(self, rate):
        self.interval = 1.0 / rate if rate and rate > 0 else 0
        self.next = 0.0

    async def wait(self):
        if not self.interval:
            return
        now = asyncio.get_running_loop().time()
        self.next = max(self.next, now)
        delay = self.next - now
        self.next += self.interval
        if delay > 0:
            await asyncio.sleep(delay)


async def scan(ips, ports, *, concurrency=200, rate=300, timeout=2.0, on_service=None, on_progress=None, cancel=None):
    """Probe every (ip, port). on_service(ip, svc) and on_progress(done, total, found) are sync callbacks."""
    ips = list(ips)
    random.shuffle(ips)
    total, state = len(ips) * len(ports), {"done": 0, "found": 0}
    queue = asyncio.Queue(maxsize=max(1, concurrency) * 2)
    limiter = RateLimiter(rate)

    async def worker():
        while True:
            item = await queue.get()
            if item is None:
                return
            if not (cancel and cancel.is_set()):
                await limiter.wait()
                try:
                    svc = await probe_port(item[0], item[1], timeout)
                except Exception:
                    svc = None
                if svc:
                    state["found"] += 1
                    if on_service:
                        on_service(item[0], svc)
            state["done"] += 1
            if on_progress:
                on_progress(state["done"], total, state["found"])

    workers = [asyncio.create_task(worker()) for _ in range(max(1, min(concurrency, total)))]
    for port in ports:
        for ip in ips:
            if cancel and cancel.is_set():
                break
            await queue.put((ip, port))
    for _ in workers:
        await queue.put(None)
    await asyncio.gather(*workers)
    return state


async def reverse_dns(ips, timeout=4.0):
    """Best-effort PTR lookups. Returns {ip: hostname}."""
    sem, out = asyncio.Semaphore(20), {}

    async def one(ip):
        async with sem:
            try:
                name = (await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, ip), timeout))[0]
                if name and name != ip:
                    out[ip] = name
            except Exception:
                pass

    await asyncio.gather(*(one(ip) for ip in ips if not ip.startswith("127.")))
    return out
