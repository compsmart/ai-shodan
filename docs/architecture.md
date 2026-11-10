# Architecture

```
            scans (native / nmap)   third-party lookups & searches   file imports
                      \                        |                        /
                       +------------  normalised host record ----------+
                                               |
                                        db.ingest()  -> fingerprint.identify() for bare banners
                                               |      -> tagging.apply()  (rule tags)
                                               v
                                   SQLite  data/netsearch.db
                                    /          |          \
                          query.py search   ai.analyze()   gaps()
                                    \          |          /
                              api.py (FastAPI + web UI)    cli.py
```

One process model: the API server runs scan jobs as asyncio tasks; the CLI runs them inline. Both write to the same SQLite file (WAL mode), so the UI, the CLI and several agents can work at once.

## Modules

| File | Responsibility |
|---|---|
| `config.py` | Paths, setting defaults, secret → environment variable map |
| `db.py` | Schema, connections, settings, `ingest()`, tag/finding writers, `host_detail()`, `stats()`, `gaps()` |
| `scanner.py` | Target and port parsing, `check_scope()`, `probe_port()`, `scan()`, reverse DNS |
| `fingerprint.py` | `BANNER_RULES`, `HTTP_SERVER_RULES`, `HTTP_APP_RULES`, port → service guesses |
| `tagging.py` | Tag catalog and deterministic rules |
| `sources.py` | Provider classes, `enrich()`, `remote_search()`, file parsers |
| `jobs.py` | Job creation (validation + scope), execution, cancellation, nmap runner |
| `probe.py` | Deep probe of known services: protocol probe menu, headless-browser rendering, nmap fallback, `extra_probes()` for model requests |
| `enrich.py` | Per-host enrichment steps (sources, probe, ai), status recording, skip/resume planning |
| `ai.py` | Prompt, output schema, local (OpenAI-compatible) and Anthropic model calls, heuristic fallback, `annotate()` |
| `query.py` | Query language compiler, search, facets, export |
| `api.py` | HTTP API, local-only guard, static UI |
| `cli.py` | Command line |
| `web/` | `index.html`, `styles.css`, `app.js` — no build step |

## Schema

- `hosts(ip PK, ip_int, is_public, hostnames[], org, asn, isp, country, city, os, vulns[], sources[], first_seen, last_seen, ai_summary, ai_risk, ai_model, ai_updated, notes)`
- `services(id, ip → hosts, port, transport, service, product, version, cpe, banner, extra{}, sources[], first_seen, last_seen)` unique on `(ip, port, transport)`
- `tags(ip, port, tag, severity, origin, reason, created)` unique on `(ip, port, tag)`; port 0 = host level
- `findings(id, ip, port, severity, title, detail, origin, created)`
- `scan_jobs(id, targets, ports, engine, options{}, status, total, done, found, error, created, started, finished)`
- `settings(key, value)` · `activity(ts, actor, action, detail)`

`[]` and `{}` columns hold JSON. `services.extra` carries `http` (`status`, `title`, `server`, `headers`, `apps`, `body_preview`), `tls` (`version`, `cipher`, `cn`, `subject`, `issuer`, `san`, `not_before`, `not_after`, `self_signed`, `sha256`) and `nmap` (`extrainfo`, `scripts`).

## How a native scan probes a port

1. TCP connect with the job timeout. Closed or filtered → nothing stored.
2. On TLS-typical ports go straight to step 5. Otherwise wait briefly for a server-first banner (SSH, FTP, SMTP, MySQL…).
3. If silent, send the read-only probe for that port (Redis, Memcached, ZooKeeper, RDP) or else an HTTP `GET /`.
4. If HTTP got no answer or a "this is an HTTPS port" reply, retry with TLS.
5. TLS: handshake without verification (legacy versions allowed so they can be reported), record protocol, cipher and certificate, then HTTP `GET /` inside the tunnel.
6. `fingerprint.identify()` turns the response into service / product / version / CPE; the record goes through `db.ingest()` immediately, so results show up while the job runs.

## Enrichment

`enrich.run_host(ip, steps)` runs the steps in order with short database connections (nothing is locked while a probe or a model is working) and writes `hosts.enriched_at`, `enrich_status` and `enrich_detail` (`{steps: {name: {status, note, at, ...}}, seconds}`). `enrich.plan()` decides which hosts are fresh: every requested step completed (`ok` or `skipped`) within `enrich_max_age_hours`. Batch runs are `scan_jobs` rows with `kind='enrich'`, executed in a worker thread one host at a time; cancelling or killing one loses nothing because freshness is per host.

The deep probe stores what it saw at `services.extra.probe` (`responses` per probe name, `web` for the browser view) and the screenshot under `data/shots/`. The AI's reading goes to `services.name`, `services.summary` and `extra.ai`; it replaces an observed product or version only at high confidence, fills blanks at medium, and can never add a port.

The model never opens a connection itself. It can return `more_probes: [{port, probe}]`; `probe.extra_probes()` runs only names found in `probe.MENU` or `probe.WEB_PATHS`, only on ports already recorded for that host, only inside scan scope, and at most `enrich_ai_probes` of them.

## AI analysis

`ai.analyze()` builds a compact JSON view of the host (banners capped at 700 characters, at most 80 services), and asks the configured model (`ai_provider`: a local OpenAI-compatible server by default, or the Claude API) for `{summary, risk, tags[], findings[]}` using a JSON-schema-constrained response. The system prompt marks all host data as untrusted evidence. Results replace the host's previous `ai` tags and findings. Model and effort are settings (`ai_model`, default `claude-opus-5-5`; `ai_effort`, default `medium`). On newer SDK versions the request opts into server-side refusal fallbacks, since scan data can trip safety classifiers.

## Security model

- Single user, local. The API has no login; it binds to loopback, checks the `Host` header against an allow-list (`NETSEARCH_ALLOWED_HOSTS`) and refuses cross-origin writes, which blocks drive-by requests from web pages.
- Everything captured from remote hosts is hostile input. The UI escapes every value; the AI prompt fences it; nothing from a banner is executed.
- Scope enforcement is in `scanner.check_scope()` and runs at job creation for the UI, API and CLI alike.

## Extending

- New fingerprint: add a tuple to the relevant rule list in `fingerprint.py` and a case to `tests/test_core.py`.
- New protocol probe: add bytes to `scanner.PROBES` keyed by port (read-only requests only).
- New tag rule: see [tagging.md](tagging.md). New provider or file format: see [sources.md](sources.md).
- New search filter: add to `SERVICE_FIELDS` or `HOST_FIELDS` in `query.py`.
