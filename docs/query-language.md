# Query language

Filters are separated by spaces and combined with AND. Prefix a filter with `-` to negate it. Quote values that contain spaces: `product:"Apache httpd"`. `*` is a wildcard in text filters. Bare words search IPs, hostnames, organisations, summaries, banners, products and service details.

| Filter | Matches |
|---|---|
| `port:22` `port:80,443` `port:8000-8100` | Open port(s) |
| `service:ssh` | Protocol name, exact |
| `product:nginx` | Product contains |
| `version:1.18` | Version starts with |
| `banner:"220 ProFTPD"` | Banner contains |
| `title:login` `server:apache` | HTTP title / `Server` header contains |
| `cert:example.com` | TLS certificate fields contain |
| `cpe:openssh` `transport:udp` | CPE contains / transport |
| `ip:10.0.0.*` `net:10.0.0.0/24` | Address pattern / CIDR |
| `hostname:example.com` `org:hetzner` `asn:AS13335` `country:DE` `city:berlin` `os:linux` | Ownership and location |
| `tag:exposed-database` | Host or any of its services has the tag |
| `risk:high` | Analysis risk level |
| `severity:critical` | Has a finding of that severity |
| `cve:CVE-2021-41773` | Reported CVE id contains |
| `has:cve` `has:ai` `has:tls` `has:finding` `has:hostname` `has:notes` `has:service` `has:enriched` `has:screenshot` | Presence checks |
| `enriched:ok` `enriched:partial` `enriched:error` | Outcome of the last enrichment run |
| `name:grafana` | The friendly name the AI gave a service |
| `is:public` `is:private` | Internet-routable or not |
| `source:scan` `source:shodan` `source:internetdb` | Data came from this source |
| `after:2026-01-01` `before:2026-06-01` | Last seen |

Service filters (`port service product version banner title server cert cpe transport`) in one query must all match **the same service**: `port:8080 product:jenkins` finds Jenkins on 8080, not a host with Jenkins somewhere and something else on 8080.

A negated service filter means the host has **no** such service: `-port:22` returns hosts without port 22 open.

Examples:

```
tag:no-auth is:public                      unauthenticated services on the internet
service:http title:"index of"              directory listings
product:openssh tag:outdated-software      old OpenSSH
port:3389 -tag:remote-access               RDP port open but not identified as RDP
has:service -has:ai                        hosts still waiting for analysis
net:192.168.0.0/16 tag:cleartext           telnet/ftp on the LAN
```
