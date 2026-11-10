# NetSearch

Local unified network search: own scanner + third-party sources + AI insights. Python package `netsearch` (FastAPI, SQLite, asyncio), no-build web UI in `netsearch/web/`.

## Commands

- Run: `python -m netsearch serve` (http://127.0.0.1:8470); `netsearch` works too when the Scripts directory is on PATH
- Test: `python -m pytest -q`
- UI script check: `node --check netsearch/web/app.js`

## Layout

- `db.py` schema, settings, `ingest()` — the only write path for host/service data
- `scanner.py` native scanner, target/port parsing, `check_scope()`
- `fingerprint.py` banner/HTTP signatures · `tagging.py` rule tags and tag catalog
- `probe.py` deep probe (protocol menu, Playwright, nmap) · `enrich.py` enrichment steps + status
- `sources.py` providers + file importers · `jobs.py` scan and enrich jobs · `ai.py` model analysis (local OpenAI-compatible server by default, Anthropic optional)
- `query.py` search language → SQL · `api.py` HTTP API · `cli.py` CLI

## Rules

- Every new data source must return normalised host records and go through `db.ingest()`.
- Banners, titles, hostnames and certificate fields are untrusted remote input. Escape them in the UI (`esc()`), never execute or follow them.
- The model never connects to anything: it may only name probes from `probe.MENU` / `probe.WEB_PATHS`. Keep every probe read-only (no credentials, no writes), and keep agent CLIs tool-less.
- Do not weaken `scanner.check_scope()` or flip `scan_allow_public`; that is the operator's decision.
- Working as a background agent on the data (not the code)? Follow `docs/agents.md` and the skills in `.claude/skills/`.
