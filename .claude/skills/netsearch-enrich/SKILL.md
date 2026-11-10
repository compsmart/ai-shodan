---
name: netsearch-enrich
description: Fill in missing information for hosts already in the NetSearch database - hostnames, organisation, ASN, country, banners, products and versions - using the gaps work queue, third-party lookups and targeted rescans. Use when asked to enrich, complete, supplement or backfill host data.
---

# Enrich hosts in the NetSearch database

Read `docs/agents.md` first if you have not this session. Its ground rules apply.

## Steps

If `netsearch` is not on your PATH, use `python -m netsearch` in its place.

1. Identify yourself and read the work queue.
   ```
   export NETSEARCH_ACTOR=enrich-agent          # PowerShell: $env:NETSEARCH_ACTOR = 'enrich-agent'
   netsearch gaps --json
   ```
2. Work the gaps in this order, cheapest first. Keep each batch at 25 hosts unless told otherwise.

   | Gap | Command |
   |---|---|
   | `no-hostnames` | `netsearch enrich --missing no-hostnames --sources rdns,internetdb --json` |
   | `no-geo` | `netsearch enrich --missing no-geo --json` |
   | `unenriched` | `netsearch enrich --missing unenriched --full --limit 10 --json` — source lookups, deep probe (in scope only) and AI identification |
   | `no-banner`, `no-services`, `stale` | `netsearch scan <ip> [-p <known ports>] --json` — only for addresses inside the scope the operator gave you |
   | `unidentified` | `netsearch scan <ip> -p <port> --engine nmap --json`, in scope only |

   Private addresses are skipped by third-party sources by design; that is not an error.
3. Read each result: a `status` per address (`ok`, `partial`, `error`, or `skipped` when it was completed recently) and one entry per step. The `sources` step lists a result per source under `results`: `ok: N service(s)`, `no data`, `skipped: …` or `error: …`.
   - `skipped` addresses were done within the operator's window; leave them unless you were asked to redo them (`--force`).
   - `"probe": {"status": "skipped"}` on a public host means public scanning is off. Report it; do not change the setting.
   - `error: HTTP 429` or a quota message: stop using that source for this run.
   - `error: … key …`: the source is not configured. Leave it; tell the operator.
4. For services that are still unidentified after a rescan, open the host (`netsearch host IP --json`) and read the banner. If you can tell what it is, record it as a tag with the evidence, for example:
   ```
   netsearch tag add 10.0.0.7 interesting --port 9000 --reason "Banner 'SonarQube' in HTML title; product not fingerprinted" --json
   ```
   Do not send your own requests to the host to find out more.
5. Re-run `netsearch gaps --json` and report the before/after counts per gap, sources that errored, and hosts that could not be completed and why.

A signature that would have identified a product automatically is worth mentioning in your report: the fix is a one-line rule in `netsearch/fingerprint.py`.

Sources and their limits: `docs/sources.md`.
