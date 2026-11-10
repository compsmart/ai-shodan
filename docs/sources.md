# Sources

Every source produces normalised host records that are merged by `db.ingest()`: one row per host, one per (ip, port, transport). Non-empty incoming values overwrite, lists (hostnames, CVEs, sources) are unioned, and each host and service remembers which sources contributed.

## Providers

| Name | Key | Lookup | Search | Notes |
|---|---|---|---|---|
| `scan` / `nmap` | — | — | — | Your own scans. The only sources that capture banners first-hand. |
| `internetdb` | none | yes | no | Shodan InternetDB: ports, hostnames, tags, CVEs. No banners, updated roughly weekly. |
| `shodan` | `shodan_api_key` | yes | yes | Free keys are rate-limited; search filters and paging need a paid plan. |
| `censys` | `censys_api_token` | yes | no | Platform API, personal access token. **Unverified** against the live API. |
| `zoomeye` | `zoomeye_api_key` | yes | yes | v2 API, daily quota. **Unverified** against the live API. |
| `rdns` | none | yes | no | PTR lookup with the local resolver. |
| `geoip` | none | yes | no | ip-api.com: country, city, ISP, org, ASN. Plain HTTP, non-commercial use, about 45 requests a minute. |

Set keys in Settings → API keys, in a provider's drawer on the Sources page, with `netsearch config set shodan_api_key …`, or through environment variables.

Private and loopback addresses are never sent to a third party; `enrich` reports them as `skipped: private address`.

CVE ids come from third parties that match on version strings. Treat them as leads, not confirmed vulnerabilities.

## Importing files

`netsearch import FILE` or Sources → Import file. The format is detected from the first character unless you pass `--format`.

| Format | Produced by | Fields used |
|---|---|---|
| `nmap-xml` | `nmap -oX` | address, hostnames, open ports, service name/product/version/CPE, script output, OS match |
| `json` | `masscan -oJ` (array) | `ip`, `ports[].port/proto/service` |
| `jsonl` | `shodan download` | full banner objects: product, version, CPE, HTTP, TLS, CVEs, org, ASN |
| `jsonl` | Rapid7 Sonar rDNS / FDNS | `{"name","type":"ptr"\|"a","value"}` → hostnames |
| `jsonl` | anything else | `ip` (or `saddr`/`host`), `port`, `banner` or `data`, `service`, `product`, `version`, `hostname`, `org`, `country`, `asn` |

Imported banners that arrive without a product are run through the same fingerprints as scanned ones.

Use `--source` to label a load (for example `--source sonar-2026-10`), then filter with `source:sonar-2026-10`. Files are read into memory, so cut very large dumps into slices first, and decompress `.gz` files.

## Open datasets

Bulk datasets are too large to query live; download the slice you care about and import it.

- **Rapid7 Project Sonar** — reverse DNS, forward DNS and port studies. Access terms have changed over time; check Rapid7 Open Data for what is currently available to you.
- **Archived internet censuses and BigQuery-hosted scan data** — export rows as JSON lines with at least `ip` and `port`. This data describes the internet as it was on the collection date; give it a dated source label.
- **Your own tooling** — nmap or masscan run anywhere, then imported.

## Adding a provider

Subclass `Source` in `netsearch/sources.py`, implement `lookup(ip, settings)` (and `search(query, limit, settings)` with `can_search = True`), return records shaped like:

```python
{"ip": "203.0.113.10", "hostnames": [...], "org": "", "asn": "AS64500", "country": "DE", "city": "", "os": "",
 "vulns": ["CVE-…"], "tags": [...],
 "services": [{"port": 443, "transport": "tcp", "service": "https", "product": "nginx", "version": "1.24.0",
               "cpe": "", "banner": "…", "extra": {"http": {...}, "tls": {...}}}]}
```

Add an instance to `SOURCES`, and if it needs a key add the setting to `config.DEFAULTS` and `config.SECRETS`. It then appears in the UI, the CLI and `enrich` automatically.
