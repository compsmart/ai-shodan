"""netsearch command line. Every command accepts --json for machine-readable output (agents should always use it)."""
import argparse
import asyncio
import csv
import json
import os
import sys

from . import __version__, ai, config, enrich, jobs, query, scanner, sources, tagging
from . import db as store
from .db import db


def out(args, data, human=None):
    if args.json or human is None:
        print(json.dumps(data, indent=2, default=str))
    else:
        human(data)


def die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def table(rows, cols):
    if not rows:
        print("(none)")
        return
    widths = [max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols]
    widths = [min(w, 60) for w in widths]
    print("  ".join(c.upper().ljust(w) for c, w in zip(cols, widths)))
    for r in rows:
        print("  ".join(str(r.get(c, ""))[:w].ljust(w) for c, w in zip(cols, widths)))


def svc_label(s):
    return f"{s['port']}/{s['service'] or '?'}" + (f" {s['product']} {s['version']}".rstrip() if s["product"] else "")


def print_host(h):
    print(f"{h['ip']}  {' '.join(h['hostnames'][:3])}")
    meta = [x for x in (h["org"], h["asn"], h["country"], h["os"]) if x]
    if meta:
        print("  " + " | ".join(meta))
    print(f"  sources: {', '.join(h['sources'])}   first seen {h['first_seen']}   last seen {h['last_seen']}")
    if h["ai_summary"]:
        print(f"  risk: {h['ai_risk'] or '-'} ({h['ai_model']})  {h['ai_summary']}")
    if h["enriched_at"]:
        steps = h["enrich_detail"].get("steps") or {}
        print(f"  enriched: {h['enriched_at']} ({h['enrich_status']})  " + ", ".join(f"{k}={v.get('status')}" for k, v in steps.items()))
    if h["vulns"]:
        print(f"  vulns: {', '.join(h['vulns'][:15])}")
    print("  services:")
    for s in h["services"]:
        title = (s["extra"].get("http") or {}).get("title", "")
        print(f"    {svc_label(s)}" + (f"  [{s['name']}]" if s["name"] else "") + (f'  "{title}"' if title else ""))
        if s["summary"]:
            print(f"      {s['summary']}")
    if h["tags"]:
        print("  tags: " + ", ".join(sorted({t["tag"] + (f":{t['port']}" if t["port"] else "") for t in h["tags"]})))
    for f in h["findings"]:
        print(f"  [{f['severity']}] {f['title']}" + (f" (port {f['port']})" if f["port"] else ""))


# ---------------------------------------------------------------- commands

def cmd_serve(args):
    import uvicorn
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("warning: binding to a non-loopback address exposes an unauthenticated API that can launch scans.", file=sys.stderr)
        os.environ.setdefault("NETSEARCH_ALLOWED_HOSTS", "*")
    print(f"NetSearch {__version__}  ->  http://{args.host}:{args.port}   (db: {config.DB_PATH})")
    uvicorn.run("netsearch.api:app", host=args.host, port=args.port, log_level="warning")


def cmd_scan(args):
    opts = {k: getattr(args, k) for k in ("concurrency", "rate", "timeout") if getattr(args, k) is not None}
    if args.no_rdns:
        opts["rdns"] = False
    with db() as conn:
        try:
            job_id = jobs.create_job(conn, " ".join(args.targets), args.ports, args.engine, opts)
        except (ValueError, scanner.ScopeError) as e:
            die(e, 2)

    def progress(done, total, found):
        if not args.json:
            print(f"\r  {done}/{total} probes, {found} open", end="", file=sys.stderr, flush=True)

    job = asyncio.run(jobs.run_job(job_id, progress))
    if not args.json:
        print(file=sys.stderr)
    with db() as conn:
        rows = conn.execute("SELECT DISTINCT ip FROM services WHERE last_seen >= ? ORDER BY ip", (job["started"],)).fetchall()
        hosts = [store.host_detail(conn, r[0]) for r in rows]
    job["hosts"] = [{"ip": h["ip"], "services": [svc_label(s) for s in h["services"]],
                     "tags": sorted({t["tag"] for t in h["tags"]})} for h in hosts]

    def human(j):
        print(f"scan #{j['id']} {j['status']}: {j['found']} open service(s) on {len(j['hosts'])} host(s)" + (f"  error: {j['error']}" if j["error"] else ""))
        for h in j["hosts"]:
            print(f"  {h['ip']:<16} {', '.join(h['services'])}")
            if h["tags"]:
                print(f"  {'':<16} tags: {', '.join(h['tags'])}")
    out(args, job, human)
    if job["status"] == "failed":
        sys.exit(1)


def cmd_scans(args):
    with db() as conn:
        if args.cancel:
            return out(args, {"cancelled": jobs.cancel_job(conn, args.cancel)})
        out(args, jobs.list_jobs(conn, args.limit), lambda rows: table(rows, ["id", "kind", "status", "engine", "targets", "ports", "done", "total", "found", "created"]))


def cmd_search(args):
    with db() as conn:
        try:
            res = query.search(conn, " ".join(args.query), args.page, args.limit, args.sort)
            if args.facets:
                res["facets"] = query.facets(conn, " ".join(args.query))
        except query.QueryError as e:
            die(e, 2)

    def human(r):
        print(f"{r['total']} host(s)" + (f", showing {len(r['hosts'])}" if r["total"] > len(r["hosts"]) else ""))
        for h in r["hosts"]:
            print(f"{h['ip']:<16} {(h['hostnames'] or [''])[0][:34]:<34} {h['ai_risk'] or '-':<8} {', '.join(svc_label(s) for s in h['services'][:8])}")
            if h["tags"]:
                print(f"{'':<16} tags: {', '.join(t['tag'] for t in h['tags'])}")
    out(args, res, human)


def cmd_host(args):
    with db() as conn:
        h = store.host_detail(conn, store.norm_ip(args.ip))
    if not h:
        die("host not found", 3)
    out(args, h, print_host)


def _targets(conn, args, gap_kind):
    """Resolve the hosts a batch command applies to: explicit IPs, --query, or a gap kind."""
    if getattr(args, "ips", None):
        return [store.norm_ip(i) for i in args.ips]
    if getattr(args, "query", None):
        return [h["ip"] for h in query.search(conn, args.query, 1, args.limit)["hosts"]]
    if getattr(args, "missing", None):
        kind = args.missing if isinstance(args.missing, str) else gap_kind
        return store.gaps(conn, kind, args.limit)[kind]["ips"]
    die("give one or more IPs, --query, or the gap flag", 2)


def cmd_enrich(args):
    names = args.sources.split(",") if args.sources else None
    steps = enrich.parse_steps("sources,probe,ai" if args.full else args.steps)
    explicit = bool(args.ips)
    with db() as conn:
        if args.all:
            targets = query.match_ips(conn, "", args.limit)
        else:
            targets = _targets(conn, args, "no-geo")
        settings = store.get_settings(conn)
        age = settings["enrich_max_age_hours"] if args.max_age is None else args.max_age
        # Addresses named on the command line are always done; batches skip what was completed recently.
        todo, fresh = enrich.plan(conn, targets, steps, age, force=args.force or explicit)
    unknown = [ip for ip in targets if ip not in todo and ip not in fresh]
    if unknown:
        die(f"host not found: {unknown[0]} (scan or import it first)", 3)
    results = {ip: {"status": "skipped", "note": f"completed within the last {age:g}h (use --force to redo)"} for ip in fresh}
    if fresh and not args.json:
        print(f"skipping {len(fresh)} host(s) completed within the last {age:g}h (--force to redo)", file=sys.stderr)
    for ip in todo:
        try:
            r = enrich.run_host(ip, steps, names)
        except KeyError:
            die(f"host not found: {ip} (scan or import it first)", 3)
        results[ip] = {"status": r["status"], "seconds": r["seconds"], "steps": r["steps"]}
        if not args.json:
            print(f"{ip}: {r['status']} ({r['seconds']}s)")
            for step, d in r["steps"].items():
                print(f"  {step:<8} {d['status']:<8} {d.get('note', '')}")
    if args.json:
        out(args, results)


def cmd_analyze(args):
    results = []
    with db() as conn:
        targets = _targets(conn, args, "unanalyzed")
    for ip in targets:
        try:
            r = ai.run(ip)
        except KeyError:
            die(f"host not found: {ip}", 3)
        results.append({"ip": ip, **r})
        if not args.json:
            print(f"{ip}  [{r['risk']}] ({r['mode']}, {r['model']}) {r['summary']}" + (f"\n  note: {r['note']}" if r["note"] else ""))
            for s in r["services"]:
                print(f"  {s['port']:<6} {s['name']}" + (f" - {s['product']} {s['version']}".rstrip() if s["product"] else ""))
            for f in r["findings"]:
                print(f"  [{f['severity']}] {f['title']}")
    if args.json:
        out(args, results)


def cmd_ai(args):
    with db() as conn:
        settings = store.get_settings(conn)
    try:
        r = ai.test(settings)
    except ai.AIError as e:
        die(f"{settings['ai_provider']}: {e}")
    out(args, r, lambda d: print(f"{d['provider']} ok: model {d['model']} answered in {d['seconds']}s"))


def cmd_source(args):
    with db() as conn:
        if args.action == "list":
            settings = store.get_settings(conn)
            return out(args, [s.info(settings) for s in sources.SOURCES.values()],
                       lambda rows: table(rows, ["name", "label", "configured", "can_search", "verified", "key_setting"]))
        if not args.name or not args.query:
            die("usage: netsearch source search NAME QUERY", 2)
        try:
            ips = sources.remote_search(conn, args.name, " ".join(args.query), args.limit)
        except sources.SourceError as e:
            die(e)
        out(args, {"imported": len(ips), "ips": ips}, lambda d: print(f"imported {d['imported']} host(s): {', '.join(d['ips'][:20])}"))


def cmd_import(args):
    with open(args.file, "rb") as f:
        data = f.read()
    with db() as conn:
        try:
            res = sources.import_bytes(conn, data, args.format, args.source)
        except Exception as e:
            die(f"could not parse {args.file}: {e}")
    out(args, res, lambda d: print(f"imported {d['records']} record(s) covering {d['hosts']} host(s)"))


def cmd_tag(args):
    with db() as conn:
        if args.action == "list":
            return out(args, tagging.catalog_with_counts(conn), lambda rows: table(rows, ["tag", "severity", "hosts", "description"]))
        if args.action == "retag":
            ips = [r[0] for r in conn.execute("SELECT ip FROM hosts")]
            for ip in ips:
                tagging.apply(conn, ip)
            return out(args, {"retagged": len(ips)})
        if not args.ip or not args.tag:
            die("usage: netsearch tag add|rm IP TAG [--port N] [--reason TEXT]", 2)
        ip = store.norm_ip(args.ip)
        if not conn.execute("SELECT 1 FROM hosts WHERE ip=?", (ip,)).fetchone():
            die("host not found", 3)
        if args.action == "add":
            tag = store.add_tag(conn, ip, args.tag, args.port, f"agent:{store.actor()}" if store.actor() != "user" else "manual",
                                args.reason, args.severity)
            store.log(conn, "tag", f"{ip} +{tag}")
            out(args, {"ip": ip, "tag": tag, "port": args.port})
        else:
            n = conn.execute("DELETE FROM tags WHERE ip=? AND tag=? AND port=?", (ip, store.slug(args.tag), args.port)).rowcount
            out(args, {"deleted": n})


def cmd_finding(args):
    with db() as conn:
        if args.action == "list":
            sql, params = "SELECT id, ip, port, severity, title, origin, created FROM findings", []
            if args.severity:
                sql, params = sql + " WHERE severity=?", [args.severity]
            rows = [dict(r) for r in conn.execute(sql + " ORDER BY id DESC LIMIT ?", (*params, args.limit))]
            return out(args, rows, lambda rs: table(rs, ["id", "severity", "ip", "port", "title", "origin"]))
        if not args.ip or not args.title:
            die("usage: netsearch finding add IP --title TEXT [--detail TEXT] [--severity S] [--port N]", 2)
        try:
            fid = store.add_finding(conn, store.norm_ip(args.ip), args.title, args.detail, args.severity or "info", args.port,
                                    f"agent:{store.actor()}" if store.actor() != "user" else "manual")
        except KeyError:
            die("host not found", 3)
        except ValueError as e:
            die(e, 2)
        store.log(conn, "finding", f"{args.ip}: [{args.severity or 'info'}] {args.title}")
        out(args, {"id": fid})


def cmd_annotate(args):
    with db() as conn:
        try:
            ai.annotate(conn, store.norm_ip(args.ip), args.summary, args.risk)
        except KeyError:
            die("host not found", 3)
        except ValueError as e:
            die(e, 2)
    out(args, {"ok": True})


def cmd_gaps(args):
    with db() as conn:
        g = store.gaps(conn, args.kind, args.limit)

    def human(d):
        for name, v in d.items():
            print(f"{name:<14} {v['count']:>6}  {v['label']}")
            if args.kind:
                print("\n".join("  " + ip for ip in v["ips"]))
    out(args, g, human)


def cmd_stats(args):
    with db() as conn:
        s = store.stats(conn)

    def human(d):
        print(f"hosts {d['hosts']} ({d['public_hosts']} public)   services {d['services']}   analysed {d['analyzed']}   findings {sum(d['findings'].values())}")
        for key in ("top_ports", "top_products", "top_tags"):
            print(f"{key[4:]:<9} " + ", ".join(f"{x['value']} ({x['count']})" for x in d[key]))
    out(args, s, human)


def cmd_config(args):
    with db() as conn:
        if args.action == "set":
            if not args.key or args.value is None:
                die("usage: netsearch config set KEY VALUE", 2)
            try:
                store.set_setting(conn, args.key, args.value)
            except ValueError as e:
                die(e, 2)
            store.log(conn, "settings", args.key)
        s = store.get_settings(conn)
    masked = {k: ("(set)" if v else "") if k in config.SECRETS else v for k, v in s.items()}
    if args.action == "get" and args.key:
        masked = {args.key: masked.get(args.key)}
    out(args, masked, lambda d: [print(f"{k} = {v}") for k, v in d.items()])


def cmd_export(args):
    with db() as conn:
        try:
            rows = list(query.export_rows(conn, " ".join(args.query)))
        except query.QueryError as e:
            die(e, 2)
    fh = open(args.output, "w", newline="", encoding="utf-8") if args.output else sys.stdout
    if args.format == "csv":
        w = csv.DictWriter(fh, fieldnames=list(rows[0]) if rows else ["ip"])
        w.writeheader()
        w.writerows(rows)
    else:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    if args.output:
        fh.close()
        print(f"wrote {len(rows)} row(s) to {args.output}", file=sys.stderr)


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="machine-readable output")
    p = argparse.ArgumentParser(prog="netsearch", description="Unified network search: scan, import, enrich, analyse, query.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help):
        sp = sub.add_parser(name, help=help, parents=[common])
        sp.set_defaults(fn=fn)
        return sp

    s = add("serve", cmd_serve, "run the web UI and API")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8470)

    s = add("scan", cmd_scan, "scan targets now and store the results")
    s.add_argument("targets", nargs="+", help="IPs, CIDRs, ranges (10.0.0.1-50) or hostnames")
    s.add_argument("-p", "--ports", help=f"ports/ranges/presets ({', '.join(scanner.PRESETS)}); default from settings")
    s.add_argument("--engine", choices=jobs.ENGINES, default="native")
    s.add_argument("--concurrency", type=int)
    s.add_argument("--rate", type=float, help="new connections per second")
    s.add_argument("--timeout", type=float)
    s.add_argument("--no-rdns", action="store_true")

    s = add("scans", cmd_scans, "list scan jobs")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--cancel", type=int, metavar="ID")

    s = add("search", cmd_search, "search the database")
    s.add_argument("query", nargs="*")
    s.add_argument("--limit", type=int, default=25)
    s.add_argument("--page", type=int, default=1)
    s.add_argument("--sort", choices=list(query.SORTS), default="recent")
    s.add_argument("--facets", action="store_true")

    s = add("host", cmd_host, "show everything known about one host")
    s.add_argument("ip")

    s = add("enrich", cmd_enrich, "enrich hosts: source lookups, deep probe, AI identification")
    s.add_argument("ips", nargs="*")
    s.add_argument("--query", help="enrich hosts matching a search query")
    s.add_argument("--missing", nargs="?", const=True, metavar="GAP", help="enrich hosts from a gap list (default no-geo)")
    s.add_argument("--all", action="store_true", help="every host in the database (up to --limit)")
    s.add_argument("--steps", default="sources", help=f"comma list from: {', '.join(enrich.STEPS)} (default: sources)")
    s.add_argument("--full", action="store_true", help="all steps: sources, probe, ai")
    s.add_argument("--sources", help=f"for the sources step, a comma list from: {', '.join(sources.SOURCES)}")
    s.add_argument("--max-age", type=float, metavar="HOURS", help="skip hosts completed more recently than this (default from settings)")
    s.add_argument("--force", action="store_true", help="redo hosts even if they were completed recently")
    s.add_argument("--limit", type=int, default=25)

    s = add("ai", cmd_ai, "check that the configured AI provider answers")
    s.add_argument("action", choices=["test"])

    s = add("analyze", cmd_analyze, "AI analysis: summary, risk, tags, findings")
    s.add_argument("ips", nargs="*")
    s.add_argument("--query")
    s.add_argument("--unanalyzed", dest="missing", action="store_true", help="hosts with no analysis yet")
    s.add_argument("--limit", type=int, default=10)

    s = add("source", cmd_source, "list sources or pull results from a remote search")
    s.add_argument("action", choices=["list", "search"])
    s.add_argument("name", nargs="?")
    s.add_argument("query", nargs="*")
    s.add_argument("--limit", type=int, default=50)

    s = add("import", cmd_import, "import nmap XML, masscan JSON, Shodan/Sonar/generic JSONL")
    s.add_argument("file")
    s.add_argument("--format", choices=["auto", "nmap-xml", "json", "jsonl"], default="auto")
    s.add_argument("--source", default="import", help="label recorded as the data source")

    s = add("tag", cmd_tag, "manage tags")
    s.add_argument("action", choices=["add", "rm", "list", "retag"])
    s.add_argument("ip", nargs="?")
    s.add_argument("tag", nargs="?")
    s.add_argument("--port", type=int, default=0)
    s.add_argument("--reason", default="")
    s.add_argument("--severity", choices=store.SEVERITIES)

    s = add("finding", cmd_finding, "record or list findings")
    s.add_argument("action", choices=["add", "list"])
    s.add_argument("ip", nargs="?")
    s.add_argument("--title")
    s.add_argument("--detail", default="")
    s.add_argument("--severity", choices=store.SEVERITIES)
    s.add_argument("--port", type=int, default=0)
    s.add_argument("--limit", type=int, default=50)

    s = add("annotate", cmd_annotate, "store an analysis summary + risk for a host (for agents)")
    s.add_argument("ip")
    s.add_argument("--summary", required=True)
    s.add_argument("--risk", required=True, choices=store.SEVERITIES)

    s = add("gaps", cmd_gaps, "what is missing from the database (work queue for agents)")
    s.add_argument("kind", nargs="?", choices=list(store.GAP_KINDS))
    s.add_argument("--limit", type=int, default=25)

    add("stats", cmd_stats, "database overview")

    s = add("config", cmd_config, "view or change settings")
    s.add_argument("action", choices=["list", "get", "set"])
    s.add_argument("key", nargs="?")
    s.add_argument("value", nargs="?")

    s = add("export", cmd_export, "export matching services as JSONL or CSV")
    s.add_argument("query", nargs="*")
    s.add_argument("--format", choices=["jsonl", "csv"], default="jsonl")
    s.add_argument("-o", "--output")
    return p


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        args.fn(args)
    except ValueError as e:
        die(e, 2)
    except KeyboardInterrupt:
        die("interrupted", 130)


if __name__ == "__main__":
    main()
