import asyncio

import pytest

from netsearch import ai, enrich, fingerprint, jobs, probe, query, scanner, sources, tagging
from netsearch import db as store
from netsearch.db import db


def test_fingerprint_banners():
    f = fingerprint.identify
    assert f(22, "SSH-2.0-OpenSSH_7.4\r\n") == {"service": "ssh", "product": "OpenSSH", "version": "7.4", "cpe": "cpe:2.3:a:openbsd:openssh:7.4"}
    assert f(2222, "SSH-2.0-dropbear_2019.78")["product"] == "Dropbear sshd"
    assert f(21, "220 (vsFTPd 3.0.3)")["version"] == "3.0.3"
    assert f(25, "220 mail.example.com ESMTP Postfix (Ubuntu)")["product"] == "Postfix"
    assert f(3306, "J\x00\x00\x00\n8.0.36\x00abc")["product"] == "MySQL"
    assert f(3306, "n\x00\x00\x00\n5.5.5-10.6.12-MariaDB-0ubuntu0.22.04.1\x00")["version"] == "10.6.12"
    assert f(6379, "$3000\r\n# Server\r\nredis_version:5.0.7\r\n")["version"] == "5.0.7"
    assert f(11211, "VERSION 1.5.22\r\n")["service"] == "memcached"
    assert f(5432, "")["service"] == "postgresql"   # port-based guess when nothing was read


def test_fingerprint_http():
    raw = (b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nX-Powered-By: PHP/7.4.3\r\n\r\n"
           b"<html><head><title>phpMyAdmin</title></head></html>")
    http = scanner.parse_http(raw)
    assert http["status"] == 200 and http["title"] == "phpMyAdmin"
    extra = {"http": http}
    fp = fingerprint.identify(80, "", extra)
    assert fp["service"] == "http" and fp["product"] == "phpMyAdmin"
    assert {a["name"] for a in http["apps"]} == {"phpMyAdmin", "PHP"}
    es = scanner.parse_http(b'HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{"cluster_name":"x","version":{"number" : "6.8.0"}}')
    assert fingerprint.identify(9200, "", {"http": es})["version"] == "6.8.0"


def test_targets_and_scope():
    assert scanner.parse_targets("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    assert scanner.parse_targets("10.0.0.1-3, 10.0.0.9") == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.9"]
    assert scanner.parse_ports("22,80-82,top20")[:2] == [21, 22]
    with pytest.raises(scanner.ScopeError):
        scanner.parse_targets("10.0.0.0/8", max_hosts=4096)
    settings = {"scan_allow_public": False, "scan_exclude": "10.9.0.0/16"}
    assert scanner.check_scope(["10.0.0.1", "127.0.0.1"], settings) == 0
    for bad in (["8.8.8.8"], ["10.9.1.1"], ["224.0.0.1"], ["169.254.169.254"]):
        with pytest.raises(scanner.ScopeError):
            scanner.check_scope(bad, settings)
    assert scanner.check_scope(["8.8.8.8"], {"scan_allow_public": True}) == 1


def seed():
    with db() as conn:
        store.ingest(conn, {"ip": "8.8.4.4", "hostnames": ["db.example.net"], "org": "Example", "country": "US", "vulns": ["CVE-2020-0001"],
                            "services": [{"port": 6379, "banner": "# Server\r\nredis_version:5.0.7\r\n"},
                                         {"port": 22, "banner": "SSH-2.0-OpenSSH_7.4"}]}, "test")
        store.ingest(conn, {"ip": "10.1.2.3", "services": [{"port": 2222, "banner": "SSH-2.0-OpenSSH_9.6"},
                                                           {"port": 23, "banner": "\xff\xfb\x01login: "}]}, "test")
        store.ingest(conn, {"ip": "198.51.100.7", "services": [{"port": 443}]}, "internetdb")


def test_ingest_tagging_query():
    seed()
    with db() as conn:
        h = store.host_detail(conn, "8.8.4.4")
        tags = {(t["port"], t["tag"]) for t in h["tags"]}
        assert h["is_public"] and h["services"][1]["product"] == "Redis" and h["services"][1]["version"] == "5.0.7"
        assert {(6379, "no-auth"), (6379, "exposed-database"), (6379, "outdated-software"), (22, "outdated-software"), (0, "has-cve")} <= tags
        assert (2222, "nonstandard-port") in {(t["port"], t["tag"]) for t in store.host_detail(conn, "10.1.2.3")["tags"]}

        ips = lambda q: sorted(h["ip"] for h in query.search(conn, q)["hosts"])
        assert ips("port:6379") == ["8.8.4.4"]
        assert ips("product:openssh") == ["10.1.2.3", "8.8.4.4"]
        assert ips("product:openssh version:7") == ["8.8.4.4"]
        assert ips("service:ssh -tag:outdated-software") == ["10.1.2.3"]
        assert ips("-port:22") == ["10.1.2.3", "198.51.100.7"]
        assert ips("net:10.0.0.0/8") == ["10.1.2.3"]
        assert ips("has:cve country:us is:public") == ["8.8.4.4"]
        assert ips("redis_version") == ["8.8.4.4"]
        assert ips("hostname:example.net tag:no-auth") == ["8.8.4.4"]
        with pytest.raises(query.QueryError):
            query.search(conn, "bogus:1")
        assert query.facets(conn, "")["port"][0]["count"] == 1

        # merging keeps richer data and re-ingest does not duplicate
        store.ingest(conn, {"ip": "8.8.4.4", "services": [{"port": 22}]}, "internetdb")
        h = store.host_detail(conn, "8.8.4.4")
        assert len(h["services"]) == 2 and h["services"][0]["product"] == "OpenSSH" and h["sources"] == ["test", "internetdb"]
        assert store.gaps(conn, "no-banner")["no-banner"]["ips"] == ["198.51.100.7"]
        # a weak guess fills blanks but never replaces an observed value
        store.ingest(conn, {"ip": "8.8.4.4", "services": [{"port": 22, "service": "guess", "weak": True}]}, "nmap")
        assert store.host_detail(conn, "8.8.4.4")["services"][0]["service"] == "ssh"


def test_heuristic_and_ai_store():
    with db() as conn:
        h = store.host_detail(conn, "8.8.4.4")
        assert ai.heuristic(h)["risk"] == "high"
        assert ai.host_payload(h)["services"][0]["port"] == 22
        ai.store(conn, "8.8.4.4", {"summary": "s", "risk": "high",
                                   "tags": [{"tag": "Suspicious Thing", "port": 9999, "severity": "high", "reason": "r"}],
                                   "findings": [{"severity": "high", "title": "t", "detail": "d", "port": 6379}]}, "model-x")
        h = store.host_detail(conn, "8.8.4.4")
        assert h["ai_risk"] == "high" and h["findings"][0]["port"] == 6379
        assert any(t["tag"] == "suspicious-thing" and t["port"] == 0 and t["origin"] == "ai" for t in h["tags"])
        tagging.apply(conn, "8.8.4.4")   # rule retag leaves AI tags alone
        assert any(t["origin"] == "ai" for t in store.host_detail(conn, "8.8.4.4")["tags"])



def test_model_output_is_coerced():
    out = ai.clean(ai.parse_json('<think>hm</think>```json\n{"summary": " ok ", "risk": "severe", "tags": [{"tag": "x", "port": "22"}, "junk"],'
                                 ' "findings": [{"title": "t", "severity": "high", "port": 22}, {"detail": "no title"}]}\n```'))
    assert out == {"summary": "ok", "risk": "info", "services": [], "more_probes": [],
                   "tags": [{"tag": "x", "port": 0, "severity": "info", "reason": ""}],
                   "findings": [{"severity": "high", "title": "t", "detail": "", "port": 22}]}


def test_ai_service_identification_is_stored_carefully():
    result = ai.clean({"summary": "s", "risk": "low", "services": [
        {"port": 22, "name": "OpenSSH server", "service": "ssh", "product": "Totally Different", "version": "9.9", "summary": "Remote shell.", "confidence": "medium"},
        {"port": 6379, "name": "Redis cache", "service": "redis", "product": "Redis", "version": "Redis/5 (weird)", "summary": "Cache.", "confidence": "high"},
        {"port": 4444, "name": "not a known port", "service": "x", "product": "x", "version": "1", "summary": "", "confidence": "high"}]})
    with db() as conn:
        ai.store(conn, "8.8.4.4", result, "model-y")
        by_port = {s["port"]: s for s in store.host_detail(conn, "8.8.4.4")["services"]}
    assert set(by_port) == {22, 6379}                                          # the model cannot invent services
    assert by_port[22]["name"] == "OpenSSH server" and by_port[22]["product"] == "OpenSSH"   # medium confidence only fills blanks
    assert by_port[6379]["summary"] == "Cache." and by_port[6379]["version"] != "Redis/5 (weird)"
    assert by_port[22]["extra"]["ai"]["confidence"] == "medium"


def test_probe_decoders_and_fingerprints():
    assert probe._decode("postgres-ssl", b"N") == "postgres-ssl:N"
    wire = b"....maxWireVersion\x00" + (17).to_bytes(4, "little") + b"...."
    assert probe._decode("mongodb-hello", wire) == "mongodb-wire:17 version:6.0"
    assert fingerprint.identify(27017, "", {"probe": {"responses": {"mongodb-hello": "mongodb-wire:17 version:6.0"}}})["version"] == "6.0"
    assert fingerprint.identify(5432, "", {"probe": {"responses": {"postgres-ssl": "postgres-ssl:S"}}})["product"] == "PostgreSQL"
    assert fingerprint.guess_os(["SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"]) == "Linux (Ubuntu)"
    product, version, _, apps = fingerprint.identify_http({"server": "nginx/1.24.0", "title": "Home", "generator": "Hugo 0.111.3", "libs": {"jQuery": "3.6.0"}})
    assert (product, version) == ("Hugo", "0.111.3") and {"name": "jQuery", "version": "3.6.0"} in apps
    assert fingerprint.identify_http({"headers": {"kbn-version": "8.11.1"}})[:2] == ("Kibana", "8.11.1")


def test_extra_probes_only_run_what_is_on_the_menu():
    settings = {"enrich_ai_probes": 2, "probe_timeout": 1, "scan_allow_public": False, "scan_exclude": ""}
    services = [{"port": 1, "transport": "tcp", "extra": {}}]
    asked = [{"port": 1, "probe": "banner"}, {"port": 1, "probe": "rm -rf /"}, {"port": 99, "probe": "banner"},
             {"port": 1, "probe": "http:/etc/passwd"}, {"port": 1, "probe": "help"}, {"port": 1, "probe": "crlf"}]
    results, rejected = probe.extra_probes("127.0.0.1", asked, services, settings)
    assert set(results[1]) == {"banner", "help"}                               # capped at enrich_ai_probes
    assert rejected == ["1/rm -rf /", "99/banner", "1/http:/etc/passwd"]
    with pytest.raises(scanner.ScopeError):
        probe.extra_probes("8.8.8.8", asked, services, settings)                # public address, public scanning off


def test_enrichment_status_skip_and_resume(monkeypatch):
    monkeypatch.setattr(ai, "complete", lambda system, user, schema, settings: (
        {"summary": "A test host.", "risk": "low", "services": [], "tags": [], "findings": [], "more_probes": []}, "fake-model"))
    with db() as conn:
        store.set_setting(conn, "probe_browser", False)
        store.set_setting(conn, "probe_nmap", False)
        store.ingest(conn, {"ip": "10.77.0.1", "services": [{"port": 1, "banner": "x"}]}, "test")
        store.ingest(conn, {"ip": "10.77.0.2"}, "test")
    r = enrich.run_host("10.77.0.1", ["probe", "ai"])
    assert r["status"] == "ok" and r["steps"]["ai"]["model"] == "fake-model" and "no longer answering: 1" in r["steps"]["probe"]["note"]
    with db() as conn:
        h = store.host_detail(conn, "10.77.0.1")
        assert h["enriched_at"] and h["enrich_status"] == "ok" and h["ai_summary"] == "A test host."
        ips = ["10.77.0.1", "10.77.0.2"]
        assert enrich.plan(conn, ips, ["probe", "ai"], 24) == (["10.77.0.2"], ["10.77.0.1"])       # done recently: skipped
        assert enrich.plan(conn, ips, ["sources", "ai"], 24)[0] == ips                              # a step it has not had
        assert enrich.plan(conn, ips, ["ai"], 24, force=True)[0] == ips
        assert query.match_ips(conn, "has:enriched net:10.77.0.0/24") == ["10.77.0.1"]
        job_id = jobs.create_enrich_job(conn, q="net:10.77.0.0/24", steps="ai")
    job = asyncio.run(jobs.run_job(job_id))
    assert job["kind"] == "enrich" and job["status"] == "done" and job["total"] == 1 and job["options"]["skipped"] == 1
    with db() as conn:
        assert enrich.plan(conn, ips, ["ai"], 24) == ([], ips)


def test_importers():
    xml = """<nmaprun><host><address addr="192.0.2.5" addrtype="ipv4"/><hostnames><hostname name="a.example"/></hostnames>
    <ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24.0"/></port>
    <port protocol="tcp" portid="81"><state state="closed"/></port></ports></host></nmaprun>"""
    recs = sources.parse_bytes(xml.encode())
    assert recs[0]["services"] == [{"port": 80, "transport": "tcp", "service": "http", "product": "nginx", "version": "1.24.0",
                                    "cpe": "", "banner": "nginx 1.24.0", "extra": {}}]
    jsonl = (b'{"ip_str":"192.0.2.6","port":22,"data":"SSH-2.0-OpenSSH_8.9","org":"X"}\n'
             b'{"ip":"192.0.2.7","ports":[{"port":443,"proto":"tcp"}]}\n'
             b'{"name":"192.0.2.8","type":"ptr","value":"h.example"}\nnot json\n')
    recs = sources.parse_bytes(jsonl)
    assert [r["ip"] for r in recs] == ["192.0.2.6", "192.0.2.7", "192.0.2.8"] and recs[2]["hostnames"] == ["h.example"]


def test_live_scan_of_local_servers():
    """Start an SSH-like banner server and an HTTP server on loopback, then run a real job against them."""
    async def main():
        async def ssh(reader, writer):
            writer.write(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
            await writer.drain()
            writer.close()

        async def http(reader, writer):
            await reader.read(1024)
            body = b"<html><title>Index of /</title></html>"
            writer.write(b"HTTP/1.0 200 OK\r\nServer: SimpleHTTP/0.6 Python/3.11.1\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
            await writer.drain()
            writer.close()

        s1 = await asyncio.start_server(ssh, "127.0.0.1", 0)
        s2 = await asyncio.start_server(http, "127.0.0.1", 0)
        p1, p2 = s1.sockets[0].getsockname()[1], s2.sockets[0].getsockname()[1]
        with db() as conn:
            job_id = jobs.create_job(conn, "127.0.0.1", f"{p1},{p2}", "native", {"rdns": False})
        job = await jobs.run_job(job_id)
        s1.close(), s2.close()
        return job, p1, p2

    job, p1, p2 = asyncio.run(main())
    assert job["status"] == "done" and job["found"] == 2, job
    with db() as conn:
        h = store.host_detail(conn, "127.0.0.1")
    by_port = {s["port"]: s for s in h["services"]}
    assert by_port[p1]["product"] == "OpenSSH" and by_port[p1]["version"] == "8.2p1"
    assert by_port[p2]["service"] == "http" and by_port[p2]["product"] == "Python SimpleHTTPServer"
    tags = {(t["port"], t["tag"]) for t in h["tags"]}
    assert {(p2, "dir-listing"), (p2, "dev-server"), (p1, "nonstandard-port")} <= tags
