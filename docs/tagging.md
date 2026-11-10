# Tags and findings

A **tag** is a short label on a host (port 0) or on one service, with a severity and a reason. A **finding** is a titled, evidence-backed observation with a severity. Both record their origin.

| Origin | Written by | Lifecycle |
|---|---|---|
| `rule` | `tagging.py`, on every ingest | Recomputed each time; cannot be removed by hand (fix the rule instead) |
| `ai` | `netsearch analyze` / "Analyse with AI" | Replaced on the next analysis of that host |
| `agent:<name>` | CLI with `NETSEARCH_ACTOR` set | Kept until removed |
| `manual` | UI or CLI | Kept until removed |
| a source name | Third-party tags (for example Shodan's `cloud`, `vpn`) | Kept until removed |

## Catalog

Severity drives colour and the heuristic risk level. Tags outside the catalog are allowed; they default to `info` unless a severity is supplied.

| Tag | Severity | Assigned when |
|---|---|---|
| `exposed-database` | high | A database service is on a public address |
| `no-auth` | high | Redis answered `INFO`, Memcached answered `version`, Elasticsearch/CouchDB root was readable, Docker API on plain HTTP |
| `has-cve` | high | A source reports CVE ids for the host |
| `ics` | high | An industrial protocol port is open (Modbus, S7, BACnet, EtherNet/IP, DNP3, Fox) |
| `cleartext` | medium | Telnet, FTP, unencrypted VNC, HTTP Basic auth without TLS |
| `admin-panel` | medium | Grafana, Kibana, Jenkins, phpMyAdmin, Portainer, Proxmox, router UIs and similar |
| `dir-listing` | medium | HTTP title is a directory index |
| `outdated-software` | medium | Version below a conservative floor in `tagging.OUTDATED` |
| `expired-cert` · `weak-tls` | medium | Certificate past `not_after` · TLS 1.0/1.1 or SSLv3 negotiated |
| `container-api` | medium | Docker or Kubernetes API, kubelet |
| `self-signed-cert` · `default-page` · `dev-server` · `many-ports` | low | Self-signed certificate · stock web page · Werkzeug / Python http.server / Uvicorn · 20 or more open ports |
| `nonstandard-port` | info | SSH, Telnet, FTP, RDP, MySQL, Redis, SMTP, VNC or Memcached away from its usual port |
| `database` `remote-access` `web` `mail` `iot` `proxy` `login-page` `file-sharing` | info | Classification |
| `suspicious` · `unusual` · `interesting` · `honeypot` | high · medium · low · low | Reserved for AI and agents; always give a reason |

`outdated-software` is a triage heuristic based on version numbers. It does not account for distribution backports and is not a vulnerability verdict.

## Adding a rule

Edit `compute()` in `netsearch/tagging.py`: add the tag to `CATALOG`, then `add(port, "tag-name", "reason citing the evidence")`. Run `netsearch tag retag` to apply it to existing hosts.
