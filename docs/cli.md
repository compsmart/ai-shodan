# CLI reference

`netsearch <command> [options]` — or `python -m netsearch …`. Add `--json` to any command for machine-readable output. The database lives in `data/netsearch.db` next to the package; set `NETSEARCH_HOME` to use another directory.

Exit codes: `0` success · `1` operation failed · `2` bad input or scope refusal · `3` host not found.

Set `NETSEARCH_ACTOR=<name>` so the activity log, tags and findings record who did the work.

## Populate

| Command | Purpose |
|---|---|
| `scan TARGETS… [-p PORTS] [--engine native\|nmap] [--rate N] [--concurrency N] [--timeout S] [--no-rdns]` | Scan now, store results. Targets: IPs, CIDRs, `10.0.0.1-50`, hostnames. Ports: numbers, ranges, presets `top100 top20 web databases remote`. |
| `scans [--cancel ID]` | List jobs, or cancel one (also cancels jobs started in the UI). |
| `import FILE [--format auto\|nmap-xml\|json\|jsonl] [--source LABEL]` | Load nmap XML, masscan JSON, Shodan export, Sonar or generic JSONL. |
| `source list` | Providers and whether each is configured. |
| `source search NAME QUERY… [--limit N]` | Run a query at a provider (`shodan`, `zoomeye`) and import the hosts. Uses provider credits. |

`scan --json` returns the job plus the hosts it touched:

```json
{"id": 3, "status": "done", "total": 2540, "done": 2540, "found": 12, "error": "",
 "hosts": [{"ip": "192.168.1.10", "services": ["22/ssh OpenSSH 9.6", "80/http nginx 1.24.0"], "tags": ["remote-access", "web"]}]}
```

## Query

| Command | Purpose |
|---|---|
| `search [QUERY…] [--limit N] [--page N] [--sort recent\|risk\|ports\|ip] [--facets]` | Search hosts. See [query-language.md](query-language.md). |
| `host IP` | Everything known about one host: services with banners and `extra` (HTTP, TLS), tags with reasons, findings, analysis. |
| `stats` | Counts and top ports/products/tags. |
| `gaps [KIND] [--limit N]` | What is missing. Kinds: `no-services unidentified no-banner no-geo no-hostnames unanalyzed stale`. |
| `export [QUERY…] [--format jsonl\|csv] [-o FILE]` | One row per (host, service). |

`gaps --json`:

```json
{"unanalyzed": {"label": "Hosts with services but no AI/agent analysis", "count": 14, "ips": ["10.0.0.5", "10.0.0.9"]}}
```

## Enrich and analyse

| Command | Purpose |
|---|---|
| `enrich IP…` / `--query Q` / `--missing [GAP]` / `--all` `[--steps sources,probe,ai] [--full] [--sources a,b] [--max-age HOURS] [--force] [--limit N]` | Enrich hosts. Default step is `sources` only (`rdns,internetdb,geoip` plus configured keyed sources; private addresses are never sent to third parties); `--full` runs all three. Batches skip hosts that completed the same steps within `--max-age` (default `enrich_max_age_hours`); addresses named on the command line and `--force` always run. |
| `ai test` | Check that the configured AI provider answers. |
| `analyze IP…` / `--query Q` / `--unanalyzed` `[--limit N]` | Model analysis (local server by default): summary, risk, tags, findings. Falls back to a rule-based summary (`"mode": "heuristic"`) when AI is off or the model is unreachable. |
| `annotate IP --summary TEXT --risk info\|low\|medium\|high\|critical` | Store your own analysis verdict (for agents doing the analysis themselves). |
| `tag add IP TAG [--port N] [--reason TEXT] [--severity S]` · `tag rm IP TAG [--port N]` | Tag a host (port 0) or one service. |
| `tag list` · `tag retag` | Tag catalog with counts · recompute rule tags for every host. |
| `finding add IP --title T [--detail D] [--severity S] [--port N]` · `finding list [--severity S]` | Record or list findings. |

## Operate

| Command | Purpose |
|---|---|
| `serve [--host H] [--port P]` | Web UI and API (default `127.0.0.1:8470`). |
| `config list` · `config get KEY` · `config set KEY VALUE` | Settings. Secrets print as `(set)`. |

`enrich --json` returns one entry per address:

```json
{"10.0.0.5": {"status": "ok", "seconds": 41.2, "steps": {
  "sources": {"status": "ok", "note": "rdns: ok: 0 service(s); internetdb: skipped: private address", "results": {"rdns": "ok: 0 service(s)"}},
  "probe": {"status": "ok", "note": "3 service(s) probed, 1 page(s) rendered", "probed": 3, "web": 1, "closed": []},
  "ai": {"status": "ok", "model": "claude-haiku-5-5", "risk": "low", "note": "..."}}},
 "10.0.0.6": {"status": "skipped", "note": "completed within the last 24h (use --force to redo)"}}
```

Host status is `ok`, `partial` (a step failed or the run was stopped) or `error`. A step is `ok`, `skipped` (for example the probe on a public host while public scanning is off) or `error`.

Settings: `enrich_max_age_hours`, `enrich_ai_probes`, `probe_browser`, `probe_browser_channel`, `probe_nmap`, `probe_timeout`, `ai_claude_model`, `ai_codex_model`, `ai_opencode_model`, `scan_allow_public`, `scan_max_hosts`, `scan_concurrency`, `scan_rate`, `scan_timeout`, `scan_default_ports`, `scan_exclude`, `scan_rdns`, `ai_enabled`, `ai_provider` (`local`, `anthropic`, `claude`, `codex` or `opencode`), `ai_base_url`, `ai_model` (blank = automatic), `ai_timeout`, `ai_effort` (Anthropic only), `ai_api_key`, `anthropic_api_key`, `shodan_api_key`, `censys_api_token`, `zoomeye_api_key`. The secrets can instead come from `NETSEARCH_AI_API_KEY`, `ANTHROPIC_API_KEY`, `SHODAN_API_KEY`, `CENSYS_API_TOKEN`, `ZOOMEYE_API_KEY`.
