# NetSearch

A local, unified search over network and internet scan data. NetSearch runs its own scans, pulls from third-party indexes (Shodan, Censys, ZoomEye, Shodan InternetDB), imports open datasets and tool output, and merges everything into one record per host in a local SQLite database. Rules and a language model (local by default) tag what is interesting, unusual or suspicious.

- **Web UI**: dashboard, search with facets, scan jobs, sources, insights, settings. Details and configuration open in side drawers. **Enrich** on the Explore page works through every host in the current results.
- **CLI**: `netsearch`, with `--json` on every command.
- **Agent kit**: skills in `.claude/skills/` and guides in `docs/` so background agents can populate and enrich the database.

## Quick start

```
pip install -e .
netsearch serve                      # http://127.0.0.1:8470
netsearch scan 192.168.1.0/24        # scan your own network from the CLI
netsearch search "port:22 product:openssh"
```

If `netsearch` is not on your PATH, use `python -m netsearch` in its place.

Requires Python 3.10+. nmap is optional; when it is on `PATH` you can choose it as the scan engine for deeper version detection.

## Scanning responsibly

Scanning machines you do not own or have permission to test can be unlawful and usually breaches ISP and hosting terms. NetSearch therefore ships with guard rails:

- Public (internet-routable) targets are **refused by default**. Enable them in Settings → Scanning or with `netsearch config set scan_allow_public true` once you have authorisation.
- Multicast, link-local (including cloud metadata addresses) and reserved space are never scanned. `scan_exclude` adds your own never-scan list.
- Jobs are capped (`scan_max_hosts`, default 4096) and rate-limited (`scan_rate`, default 300 connections/second).
- The scanner connects, reads banners, and sends a handful of read-only requests (HTTP `GET /`, a TLS handshake, Redis `INFO`, Memcached `version`). It never authenticates, brute-forces or sends exploit payloads.

## What it detects

Service, product and version for SSH, FTP, SMTP, POP3/IMAP, MySQL/MariaDB, Redis, Memcached, VNC, RDP, Telnet, ZooKeeper, rsync and HTTP(S) servers and applications (nginx, Apache, IIS, Tomcat, Jenkins, Grafana, Kibana, Elasticsearch, phpMyAdmin, Docker and Kubernetes APIs, and more), plus TLS certificate details. Signatures live in `netsearch/fingerprint.py` and are easy to extend. The nmap engine uses nmap's own probe database instead.

## Enrichment

Enrich brings a host up to date in three steps and records when each was last done:

1. **Source lookups**: reverse DNS, Shodan InternetDB, GeoIP and any provider you have a key for.
2. **Deep probe** of the services already known: each port is re-read and asked a protocol-specific question (SSH algorithms, SMTP/IMAP/POP3 capabilities, SMB dialect, MongoDB wire version, PostgreSQL, RabbitMQ, DNS `version.bind`, RTSP and more). Web services are opened in a headless browser (Playwright) to capture the rendered title, visible text, generator, JavaScript libraries, login forms and a screenshot. Anything still unidentified goes to `nmap -sV` when nmap is installed.
3. **AI identification**: the model names and describes every service, tags the host and writes a summary and findings. It may ask for a few more probes, chosen from a fixed read-only menu and run by NetSearch.

From the UI: **Enrich N results** on the Explore page, **Enrich** on a host card or in the host drawer for one machine, or **Enrich all hosts** on the Scans page. From the CLI: `netsearch enrich --query "port:8080" --full`.

Hosts completed within the last 24 hours (Settings → Enrichment) are skipped, so a run that was stopped or interrupted resumes where it left off when you start it again. Choosing a single host always re-runs it.

The deep probe obeys the same scope rules as scanning: public hosts are not probed unless public scanning is enabled, though they still get source lookups and AI analysis of stored data. The browser may only talk to the address under test; requests to any other host are blocked and listed.

The browser step needs `pip install playwright`, and uses bundled Chromium, Edge or Chrome, whichever is present.

## AI insights

"Analyse with AI" (or `netsearch analyze`) sends one host's services, banners, probe results and metadata to a language model and stores a summary, a risk level, a name and description for each service, tags and evidence-backed findings.

Choose the model in Settings → AI ("Which AI to use") or with `netsearch config set ai_provider NAME`:

| Provider | What runs | Default model |
|---|---|---|
| `local` (default) | Any OpenAI-compatible server at `ai_base_url`, e.g. llama.cpp, Ollama, LM Studio | the first model the server lists |
| `claude` | The `claude` CLI agent, with all tools removed | `haiku` (`ai_claude_model`) |
| `codex` | The `codex` CLI agent, in a read-only sandbox in an empty folder | `gpt-5.6-luna` (`ai_codex_model`; blank = Codex's own default) |
| `opencode` | The `opencode` CLI agent, with every permission denied | opencode's default (`ai_opencode_model`) |
| `anthropic` | The Claude API, needs an API key | `claude-opus-5-5` |

Agent CLIs use whatever account they are signed in to. `netsearch ai test` (or the Test button) checks that the chosen provider answers.

If the provider fails, a rule-based summary is stored instead and labelled `heuristic`.

## Documentation

| | |
|---|---|
| [docs/cli.md](docs/cli.md) | Every command, with JSON output shapes and exit codes |
| [docs/query-language.md](docs/query-language.md) | Search filters |
| [docs/sources.md](docs/sources.md) | Providers, keys, import formats, open datasets |
| [docs/tagging.md](docs/tagging.md) | Tag catalog and how rules, AI and agents tag |
| [docs/agents.md](docs/agents.md) | Playbooks for background agents |
| [docs/architecture.md](docs/architecture.md) | Modules, schema, how to extend |

## Status and limits

- The Censys and ZoomEye connectors were written from public API documentation and have not been run against the live services; the UI marks them as unverified.
- AI analysis was run end to end with the local server and the `claude` and `codex` agents; `opencode` passed the connectivity test only. The Anthropic API provider has not been run in this build.
- Codex cannot have its tools removed, only sandboxed read-only. A hostile banner that talked the model into it could make Codex read local files into its answer. Prefer `local` or `claude` for data from machines you do not trust.
- Deep-probe protocol questions were checked against the services available on the build machine (SMB, HTTP, RPC). The others (MongoDB, PostgreSQL, AMQP, DNS, RTSP, mail) follow the protocol specifications and have unit tests for their decoders only.
- IPv4 TCP only for the built-in scanner. UDP services arrive only through imports and third-party sources.
- The API has no authentication. It binds to loopback and rejects cross-origin and non-local `Host` requests; do not expose it to a network without putting your own auth in front.
- API keys are stored unencrypted in `data/netsearch.db` (or use environment variables).

Tests: `pip install -e .[dev] && pytest` (includes a live scan of throwaway loopback servers).
