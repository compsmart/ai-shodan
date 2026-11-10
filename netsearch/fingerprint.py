"""Service / product / version detection from banners and HTTP responses.

identify() is pure and is used by the scanner and by ingest (for imported banners that
arrive without a product). Add signatures to BANNER_RULES / HTTP_SERVER_RULES / HTTP_APP_RULES.
"""
import re

# (regex on banner, service, product, version group or None, cpe "vendor:product" or "")
_B = [
    (r"^SSH-[\d.]+-OpenSSH[_-](?:for_Windows_)?([\w.]+)", "ssh", "OpenSSH", 1, "openbsd:openssh"),
    (r"^SSH-[\d.]+-dropbear[_-]?([\w.]*)", "ssh", "Dropbear sshd", 1, "dropbear_ssh_project:dropbear_ssh"),
    (r"^SSH-[\d.]+-libssh[_-]?([\w.]*)", "ssh", "libssh", 1, "libssh:libssh"),
    (r"^SSH-[\d.]+-ROSSSH", "ssh", "MikroTik RouterOS sshd", None, "mikrotik:routeros"),
    (r"^SSH-[\d.]+-Cisco-([\w.]+)", "ssh", "Cisco SSH", 1, "cisco:ios"),
    (r"^SSH-([\d.]+)-(\S+)", "ssh", "", None, ""),
    (r"^220[ -].*vsFTPd ([\w.]+)", "ftp", "vsftpd", 1, "vsftpd_project:vsftpd"),
    (r"^220[ -].*ProFTPD ?([\d.]+\w*)?", "ftp", "ProFTPD", 1, "proftpd:proftpd"),
    (r"^220[ -].*Pure-FTPd", "ftp", "Pure-FTPd", None, "pureftpd:pure-ftpd"),
    (r"^220[ -].*FileZilla Server ?(?:version )?([\d.]+)?", "ftp", "FileZilla Server", 1, "filezilla-project:filezilla_server"),
    (r"^220[ -].*Microsoft FTP Service", "ftp", "Microsoft ftpd", None, "microsoft:ftp_service"),
    (r"^220[ -].*ESMTP Postfix", "smtp", "Postfix", None, "postfix:postfix"),
    (r"^220[ -].*ESMTP Exim ([\d.]+)", "smtp", "Exim", 1, "exim:exim"),
    (r"^220[ -].*Sendmail ([\d.]+)?", "smtp", "Sendmail", 1, "sendmail:sendmail"),
    (r"^220[ -].*Microsoft ESMTP MAIL Service", "smtp", "Microsoft Exchange smtpd", None, "microsoft:exchange_server"),
    (r"^220[ -].*(?:ESMTP|SMTP)", "smtp", "", None, ""),
    (r"^220[ -].*FTP", "ftp", "", None, ""),
    (r"^\+OK.*Dovecot", "pop3", "Dovecot", None, "dovecot:dovecot"),
    (r"^\+OK", "pop3", "", None, ""),
    (r"^\* OK.*Dovecot", "imap", "Dovecot", None, "dovecot:dovecot"),
    (r"^\* OK.*Courier", "imap", "Courier IMAP", None, "courier-mta:courier"),
    (r"^\* OK", "imap", "", None, ""),
    (r"^.{4}\n(?:5\.5\.5-)?(\d+\.\d+\.\d+)[\w.\-~+]*MariaDB", "mysql", "MariaDB", 1, "mariadb:mariadb"),
    (r"^.{4}\n(\d+\.\d+\.\d+)[\w.\-~+]*", "mysql", "MySQL", 1, "oracle:mysql"),
    (r"^.{4}\xff.{2}Host .* is not allowed to connect to this (MySQL|MariaDB) server", "mysql", "MySQL", None, "oracle:mysql"),
    (r"redis_version:([\d.]+)", "redis", "Redis", 1, "redis:redis"),
    (r"^-(?:NOAUTH|DENIED|ERR).*(?:[Rr]edis|AUTH|[Pp]rotected mode|unknown command)", "redis", "Redis", None, "redis:redis"),
    (r"^VERSION ([\d.]+)", "memcached", "Memcached", 1, "memcached:memcached"),
    (r"^RFB (\d{3}\.\d{3})", "vnc", "VNC", 1, ""),
    (r"^Zookeeper version: ([\d.]+)", "zookeeper", "Apache ZooKeeper", 1, "apache:zookeeper"),
    (r"^\x03\x00\x00.\x0e?\xd0|^\x03\x00\x00\x13\x0e\xd0", "rdp", "Microsoft Terminal Services", None, "microsoft:remote_desktop_services"),
    (r"^\xff[\xfb-\xfe]", "telnet", "", None, ""),
    (r"RabbitMQ[\s\S]{0,400}?version\W{1,8}(\d+\.\d+\.\d+)", "amqp", "RabbitMQ", 1, "vmware:rabbitmq"),
    (r"^\x01\x00\x00\x00[\s\S]{0,40}AMQPLAIN|^AMQP", "amqp", "", None, ""),
    (r"^mongodb-wire:(\d+) version:([\d.+]+)", "mongodb", "MongoDB", 2, "mongodb:mongodb"),
    (r"^postgres-ssl:[SN]", "postgresql", "PostgreSQL", None, "postgresql:postgresql"),
    (r"^RTSP/1\.0 \d+[\s\S]*?Server: ([^\r\n/]+)/?([\d.]+)?", "rtsp", "", None, ""),
    (r"^RTSP/1\.0 \d+", "rtsp", "", None, ""),
    (r"^dns-version:(?:BIND )?(\d[\w.\-]+)", "dns", "BIND", 1, "isc:bind"),
    (r"^dns-version:dnsmasq-([\d.]+)", "dns", "dnsmasq", 1, "thekelleys:dnsmasq"),
    (r"^dns-version:", "dns", "", None, ""),
    (r"^220[ -].*Microsoft ESMTP|^250-.*\bX-EXPS\b", "smtp", "Microsoft Exchange smtpd", None, "microsoft:exchange_server"),
    (r"^\* OK.*(?:Cyrus IMAP) ?v?([\d.]+)?", "imap", "Cyrus IMAP", 1, "cmu:cyrus_imap_server"),
    (r"^\* OK.*Microsoft Exchange", "imap", "Microsoft Exchange imapd", None, "microsoft:exchange_server"),
    (r"^SSH-[\d.]+-(?:Go|paramiko|AsyncSSH|Twisted|Erlang|JSCH|WeOnlyDo|Bitvise|ConfD|HUAWEI|FortiSSH|lancom|Mocana)", "ssh", "", None, ""),
    (r"^\x00\x00\x00.\xfeSMB", "smb", "SMB", None, ""),
    (r"^smb2 dialect=([\d.]+)", "smb", "SMB2 server", None, ""),
    (r"^E\x00\x00\x00.S(?:FATAL|ERROR)", "postgresql", "PostgreSQL", None, "postgresql:postgresql"),
    (r"^\x04\x01\x00.\x00\x00[\s\S]{0,60}?Microsoft SQL Server", "mssql", "Microsoft SQL Server", None, "microsoft:sql_server"),
    (r"^Asterisk Call Manager/([\d.]+)", "asterisk-ami", "Asterisk Call Manager", 1, "digium:asterisk"),
    (r"It looks like you are trying to access MongoDB over HTTP", "mongodb", "MongoDB", None, "mongodb:mongodb"),
    (r"^@RSYNCD: ([\d.]+)", "rsync", "rsyncd", 1, "samba:rsync"),
    (r"(?i)^(?:\S+ )?login: ?$|^\s*(?:User Access Verification|Username:)", "telnet", "", None, ""),
]
BANNER_RULES = [(re.compile(p, re.S | re.M), s, pr, g, c) for p, s, pr, g, c in _B]

# Server / X-Powered-By header -> (product, version group, cpe)
_S = [
    (r"nginx(?:/([\d.]+))?", "nginx", 1, "f5:nginx"),
    (r"openresty(?:/([\d.]+))?", "OpenResty", 1, "openresty:openresty"),
    (r"Apache(?:/([\d.]+))?(?! ?Tomcat|-Coyote)", "Apache httpd", 1, "apache:http_server"),
    (r"Apache-Coyote|Apache Tomcat(?:/([\d.]+))?", "Apache Tomcat", 1, "apache:tomcat"),
    (r"Microsoft-IIS/([\d.]+)", "Microsoft IIS", 1, "microsoft:internet_information_services"),
    (r"Microsoft-HTTPAPI/([\d.]+)", "Microsoft HTTPAPI", 1, ""),
    (r"lighttpd(?:/([\d.]+))?", "lighttpd", 1, "lighttpd:lighttpd"),
    (r"LiteSpeed", "LiteSpeed", None, "litespeedtech:litespeed_web_server"),
    (r"Caddy", "Caddy", None, "caddyserver:caddy"),
    (r"cloudflare", "Cloudflare", None, ""),
    (r"gunicorn(?:/([\d.]+))?", "Gunicorn", 1, "gunicorn:gunicorn"),
    (r"uvicorn", "Uvicorn", None, ""),
    (r"Werkzeug/([\d.]+)", "Werkzeug", 1, "palletsprojects:werkzeug"),
    (r"SimpleHTTP/([\d.]+)", "Python SimpleHTTPServer", 1, ""),
    (r"BaseHTTP/([\d.]+)", "Python http.server", 1, ""),
    (r"Jetty\(?([\d.]+)?", "Jetty", 1, "eclipse:jetty"),
    (r"Kestrel", "Kestrel", None, "microsoft:kestrel"),
    (r"MinIO", "MinIO", None, "minio:minio"),
    (r"Docker/([\d.]+)", "Docker API", 1, "docker:docker"),
    (r"GoAhead", "GoAhead", None, "embedthis:goahead"),
    (r"RomPager/([\d.]+)", "RomPager", 1, "allegrosoft:rompager"),
    (r"mini_httpd/([\d.]+)", "mini_httpd", 1, "acme:mini_httpd"),
    (r"Boa/([\d.]+)", "Boa", 1, "boa:boa"),
    (r"micro_httpd", "micro_httpd", None, ""),
    (r"Hikvision|DNVRS-Webs|App-webs", "Hikvision web", None, "hikvision:ip_camera"),
    (r"squid(?:/([\d.]+))?", "Squid", 1, "squid-cache:squid"),
    (r"Tengine(?:/([\d.]+))?", "Tengine", 1, "alibaba:tengine"),
    (r"envoy", "Envoy", None, "envoyproxy:envoy"),
]
HTTP_SERVER_RULES = [(re.compile(p, re.I), pr, g, c) for p, pr, g, c in _S]

# (where: title|body|header:<name>, regex, application, version group, cpe)
_A = [
    ("header:x-jenkins", r"([\d.]+)", "Jenkins", 1, "jenkins:jenkins"),
    ("header:kbn-version", r"([\d.]+)", "Kibana", 1, "elastic:kibana"),
    ("header:kbn-name", r".", "Kibana", None, "elastic:kibana"),
    ("header:x-influxdb-version", r"v?([\d.]+)", "InfluxDB", 1, "influxdata:influxdb"),
    ("header:x-plex-protocol", r".", "Plex Media Server", None, "plex:media_server"),
    ("header:docker-distribution-api-version", r"registry/([\d.]+)", "Docker Registry", 1, "docker:registry"),
    ("header:x-gitea-version", r"([\d.]+)", "Gitea", 1, "gitea:gitea"),
    ("header:x-nextcloud-version", r"([\d.]+)", "Nextcloud", 1, "nextcloud:nextcloud_server"),
    ("header:www-authenticate", r'realm="?(?:pve|Proxmox)', "Proxmox VE", None, "proxmox:virtual_environment"),
    ("header:www-authenticate", r"realm=\"?(?:RouterOS|MikroTik)", "MikroTik RouterOS", None, "mikrotik:routeros"),
    ("body", r'"buildInfo"\s*:\s*\{[^}]{0,300}?"version"\s*:\s*"([\d.]+)', "Grafana", 1, "grafana:grafana"),
    ("body", r"grafanaBootData|grafana-app", "Grafana", None, "grafana:grafana"),
    ("body", r"Ollama is running", "Ollama", None, "ollama:ollama"),
    ("body", r'"tagline"\s*:\s*"The OpenSearch Project', "OpenSearch", None, "amazon:opensearch"),
    ("body", r'MinIO Console', "MinIO", None, "minio:minio"),
    ("body", r'<meta name="generator" content="Drupal ([\d.]+)', "Drupal", 1, "drupal:drupal"),
    ("body", r'<meta name="generator" content="Joomla!?[^"]*?([\d.]+)?"', "Joomla", 1, "joomla:joomla"),
    ("body", r'<meta name="generator" content="MediaWiki ([\d.]+)', "MediaWiki", 1, "mediawiki:mediawiki"),
    ("body", r'<meta name="generator" content="Ghost ([\d.]+)', "Ghost", 1, "ghost:ghost"),
    ("body", r'<meta name="generator" content="Discourse ([\d.]+)', "Discourse", 1, "discourse:discourse"),
    ("body", r'<meta name="generator" content="Moodle', "Moodle", None, "moodle:moodle"),
    ("body", r'<meta name="generator" content="TYPO3', "TYPO3", None, "typo3:typo3"),
    ("body", r'<meta name="generator" content="GitLab', "GitLab", None, "gitlab:gitlab"),
    ("body", r"/luci-static/|LuCI - Lua Configuration Interface", "OpenWrt LuCI", None, "openwrt:openwrt"),
    ("body", r"roundcube|rcmail", "Roundcube", None, "roundcube:webmail"),
    ("body", r"/zabbix\.php|zabbix\.ico|Zabbix SIA", "Zabbix", None, "zabbix:zabbix"),
    ("body", r"swagger-ui", "Swagger UI", None, "smartbear:swagger_ui"),
    ("body", r"data-netdata|netdata\.dashboard|NETDATA", "Netdata", None, "netdata:netdata"),
    ("body", r"<title>Index of /|<h1>Directory listing for", "Directory listing", None, ""),
    ("title", r"Open WebUI", "Open WebUI", None, "openwebui:open_webui"),
    ("title", r"Uptime Kuma", "Uptime Kuma", None, "uptime.kuma:uptime_kuma"),
    ("title", r"AdGuard Home", "AdGuard Home", None, "adguard:adguardhome"),
    ("title", r"Jellyfin", "Jellyfin", None, "jellyfin:jellyfin"),
    ("title", r"\bEmby\b", "Emby", None, "emby:emby"),
    ("title", r"qBittorrent", "qBittorrent Web UI", None, "qbittorrent:qbittorrent"),
    ("title", r"Transmission Web", "Transmission Web UI", None, "transmissionbt:transmission"),
    ("title", r"Sonarr|Radarr|Lidarr|Prowlarr", "Servarr", None, ""),
    ("title", r"Node-RED", "Node-RED", None, "nodered:node-red"),
    ("title", r"Zigbee2MQTT", "Zigbee2MQTT", None, ""),
    ("title", r"Frigate", "Frigate NVR", None, ""),
    ("title", r"TrueNAS|FreeNAS", "TrueNAS", None, "ixsystems:truenas"),
    ("title", r"OpenWrt|LuCI", "OpenWrt LuCI", None, "openwrt:openwrt"),
    ("title", r"UniFi", "UniFi", None, "ui:unifi_network_application"),
    ("title", r"VMware ESXi|ESXi Host Client", "VMware ESXi", None, "vmware:esxi"),
    ("title", r"vSphere|vCenter", "VMware vCenter", None, "vmware:vcenter_server"),
    ("title", r"iDRAC", "Dell iDRAC", None, "dell:idrac"),
    ("title", r"\biLO\b|Integrated Lights-Out", "HPE iLO", None, "hp:integrated_lights-out"),
    ("title", r"Keycloak", "Keycloak", None, "redhat:keycloak"),
    ("title", r"SonarQube", "SonarQube", None, "sonarsource:sonarqube"),
    ("title", r"Vaultwarden|Bitwarden", "Bitwarden-compatible vault", None, ""),
    ("title", r"\bVault\b", "HashiCorp Vault", None, "hashicorp:vault"),
    ("title", r"\bConsul\b", "HashiCorp Consul", None, "hashicorp:consul"),
    ("title", r"Airflow", "Apache Airflow", None, "apache:airflow"),
    ("title", r"Kubernetes Dashboard", "Kubernetes Dashboard", None, "kubernetes:dashboard"),
    ("title", r"Argo CD", "Argo CD", None, "argoproj:argo_cd"),
    ("title", r"^Harbor$", "Harbor", None, "linuxfoundation:harbor"),
    ("title", r"Nexus Repository|Sonatype Nexus", "Sonatype Nexus", None, "sonatype:nexus_repository_manager"),
    ("title", r"Artifactory|JFrog", "JFrog Artifactory", None, "jfrog:artifactory"),
    ("title", r"Guacamole", "Apache Guacamole", None, "apache:guacamole"),
    ("title", r"Cockpit", "Cockpit", None, "cockpit-project:cockpit"),
    ("title", r"Nagios", "Nagios", None, "nagios:nagios"),
    ("title", r"Zabbix", "Zabbix", None, "zabbix:zabbix"),
    ("title", r"Roundcube", "Roundcube", None, "roundcube:webmail"),
    ("title", r"Outlook", "Microsoft Exchange OWA", None, "microsoft:exchange_server"),
    ("title", r"FortiGate|Fortinet", "Fortinet FortiGate", None, "fortinet:fortios"),
    ("title", r"SonicWall", "SonicWall", None, "sonicwall:sonicos"),
    ("title", r"OPNsense", "OPNsense", None, "opnsense:opnsense"),
    ("title", r"Mattermost", "Mattermost", None, "mattermost:mattermost_server"),
    ("title", r"Rocket\.Chat", "Rocket.Chat", None, "rocket.chat:rocket.chat"),
    ("title", r"Swagger UI", "Swagger UI", None, "smartbear:swagger_ui"),
    ("title", r"Welcome to nginx", "nginx default page", None, "f5:nginx"),
    ("title", r"Apache2 (?:Ubuntu|Debian) Default Page|Test Page for the Apache", "Apache default page", None, "apache:http_server"),
    ("title", r"IIS Windows(?: Server)?", "IIS default page", None, "microsoft:internet_information_services"),
    ("header:x-aspnet-version", r"([\d.]+)", "ASP.NET", 1, "microsoft:asp.net"),
    ("header:x-runtime", r"^[\d.]+$", "Ruby on Rails", None, "rubyonrails:rails"),
    ("header:x-drupal-cache", r".", "Drupal", None, "drupal:drupal"),
    ("body", r'"cluster_name"[\s\S]{0,400}?"number"\s*:\s*"([\d.]+)"', "Elasticsearch", 1, "elastic:elasticsearch"),
    ("body", r'"couchdb"\s*:\s*"Welcome"[\s\S]{0,80}?"version"\s*:\s*"([\d.]+)"', "CouchDB", 1, "apache:couchdb"),
    ("body", r'"ApiVersion"\s*:\s*"[\d.]+"[\s\S]{0,400}"GoVersion"|"message"\s*:\s*"page not found"', "Docker API", None, "docker:docker"),
    ("body", r'"kind"\s*:\s*"Status"[\s\S]{0,200}"apiVersion"|"paths"\s*:\s*\[\s*"/api"', "Kubernetes API", None, "kubernetes:kubernetes"),
    ("body", r'<meta name="generator" content="WordPress ([\d.]+)', "WordPress", 1, "wordpress:wordpress"),
    ("body", r"wp-content/|wp-includes/", "WordPress", None, "wordpress:wordpress"),
    ("title", r"Grafana", "Grafana", None, "grafana:grafana"),
    ("title", r"Kibana|Elastic$", "Kibana", None, "elastic:kibana"),
    ("title", r"phpMyAdmin", "phpMyAdmin", None, "phpmyadmin:phpmyadmin"),
    ("title", r"Jenkins", "Jenkins", None, "jenkins:jenkins"),
    ("title", r"GitLab", "GitLab", None, "gitlab:gitlab"),
    ("title", r"Gitea", "Gitea", None, "gitea:gitea"),
    ("title", r"Portainer", "Portainer", None, "portainer:portainer"),
    ("title", r"Prometheus", "Prometheus", None, "prometheus:prometheus"),
    ("title", r"RabbitMQ Management", "RabbitMQ Management", None, "vmware:rabbitmq"),
    ("title", r"Home Assistant", "Home Assistant", None, "home-assistant:home-assistant"),
    ("title", r"pfSense", "pfSense", None, "netgate:pfsense"),
    ("title", r"RouterOS|MikroTik", "MikroTik RouterOS", None, "mikrotik:routeros"),
    ("title", r"Synology", "Synology DSM", None, "synology:diskstation_manager"),
    ("title", r"Proxmox", "Proxmox VE", None, "proxmox:virtual_environment"),
    ("title", r"Webmin", "Webmin", None, "webmin:webmin"),
    ("title", r"Jupyter(?:Lab| Notebook| Server)?", "Jupyter", None, "jupyter:notebook"),
    ("title", r"Apache Tomcat/([\d.]+)", "Apache Tomcat", 1, "apache:tomcat"),
    ("title", r"Adminer", "Adminer", None, "adminer:adminer"),
    ("title", r"MinIO", "MinIO", None, "minio:minio"),
    ("title", r"Traefik", "Traefik", None, "traefik:traefik"),
    ("title", r"Nextcloud", "Nextcloud", None, "nextcloud:nextcloud_server"),
    ("title", r"Plex", "Plex Media Server", None, "plex:media_server"),
    ("title", r"Pi-hole", "Pi-hole", None, "pi-hole:pi-hole"),
    ("title", r"OctoPrint", "OctoPrint", None, "octoprint:octoprint"),
    ("header:x-powered-by", r"PHP/([\d.]+)", "PHP", 1, "php:php"),
    ("header:x-powered-by", r"Express", "Express", None, "expressjs:express"),
    ("header:x-powered-by", r"ASP\.NET", "ASP.NET", None, "microsoft:asp.net"),
]
HTTP_APP_RULES = [(w, re.compile(p, re.I), a, g, c) for w, p, a, g, c in _A]
# Apps that are runtime/framework hints rather than "the product" of the service.
_FRAMEWORKS = {"PHP", "Express", "ASP.NET", "Ruby on Rails", "Swagger UI", "Directory listing", "nginx default page",
               "Apache default page", "IIS default page", "jQuery", "React", "Vue.js", "AngularJS", "Angular", "Next.js",
               "Nuxt", "Bootstrap", "Svelte", "Ember", "Backbone", "Alpine.js", "htmx"}

# (regex over banners / Server headers, operating system). First match wins.
_OS = [
    (r"Ubuntu", "Linux (Ubuntu)"), (r"Debian|deb\d+u\d", "Linux (Debian)"), (r"Raspbian", "Linux (Raspberry Pi OS)"),
    (r"CentOS", "Linux (CentOS)"), (r"Red Hat|\.el\d", "Linux (RHEL family)"), (r"Fedora", "Linux (Fedora)"),
    (r"Alpine", "Linux (Alpine)"), (r"FreeBSD", "FreeBSD"), (r"OpenBSD", "OpenBSD"), (r"NetBSD", "NetBSD"),
    (r"OpenSSH_for_Windows|Microsoft-IIS|Microsoft-HTTPAPI|Microsoft ESMTP|Win32|Win64|Windows", "Windows"),
    (r"ROSSSH|RouterOS|MikroTik", "MikroTik RouterOS"), (r"Cisco", "Cisco IOS"), (r"OpenWrt|LuCI", "Linux (OpenWrt)"),
    (r"Synology", "Synology DSM"), (r"\(Unix\)|os:Linux", "Linux/Unix"),
]
OS_RULES = [(re.compile(p, re.I), name) for p, name in _OS]


def guess_os(texts):
    """Operating system named in banners or Server headers, or '' when none of them says."""
    blob = "\n".join(t for t in texts if t)
    for rx, name in OS_RULES:
        if rx.search(blob):
            return name
    return ""

PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 88: "kerberos", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 179: "bgp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 502: "modbus", 515: "printer", 548: "afp", 554: "rtsp", 587: "smtp",
    631: "ipp", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs", 2181: "zookeeper", 2375: "docker",
    2376: "docker", 3128: "http-proxy", 3306: "mysql", 3389: "rdp", 5060: "sip", 5432: "postgresql",
    5672: "amqp", 5900: "vnc", 5901: "vnc", 5985: "winrm", 6379: "redis", 6443: "kubernetes",
    6667: "irc", 8009: "ajp13", 9042: "cassandra", 9092: "kafka", 9100: "jetdirect", 9418: "git",
    10250: "kubelet", 11211: "memcached", 27017: "mongodb", 27018: "mongodb", 102: "s7", 47808: "bacnet",
    44818: "ethernet-ip", 20000: "dnp3", 1911: "fox", 5984: "couchdb", 9200: "elasticsearch", 9300: "elasticsearch",
}


def _cpe(prefix, version):
    if not prefix:
        return ""
    return f"cpe:2.3:a:{prefix}:{version or '*'}"


def identify_http(http):
    """Return (product, version, cpe, apps) for a parsed HTTP response dict."""
    headers = http.get("headers") or {}
    product = version = cpe = ""
    server = http.get("server") or headers.get("server") or ""
    for rx, prod, group, cp in HTTP_SERVER_RULES:
        m = rx.search(server)
        if m:
            product, version = prod, (m.group(group) or "") if group else ""
            cpe = _cpe(cp, version)
            break
    apps = []
    for where, rx, app, group, cp in HTTP_APP_RULES:
        if where.startswith("header:"):
            text = headers.get(where[7:], "")
        else:
            text = http.get("title") if where == "title" else (http.get("html") or http.get("body_preview"))
            text = text or ""
        m = rx.search(text) if text else None
        if m and not any(a["name"] == app for a in apps):
            apps.append({"name": app, "version": (m.group(group) or "") if group else "", "cpe": _cpe(cp, (m.group(group) or "") if group else "")})
    for name, version in (http.get("libs") or {}).items():   # JS libraries seen by the browser probe
        if not any(a["name"] == name for a in apps):
            apps.append({"name": str(name)[:40], "version": str(version or "")[:30], "cpe": ""})
    gen = re.match(r"\s*([A-Za-z][\w .!+-]{1,40}?)(?:\s+v?(\d[\w.\-]*))?\s*$", http.get("generator") or "")
    if gen and not any(a["name"].lower() == gen.group(1).strip().lower() for a in apps):
        apps.insert(0, {"name": gen.group(1).strip(), "version": gen.group(2) or "", "cpe": ""})
    primary = next((a for a in apps if a["name"] not in _FRAMEWORKS), None)
    if primary and primary["name"] != product:
        product, version, cpe = primary["name"], primary["version"], primary["cpe"]
    elif not product and server:
        product = server.split("/")[0][:60]
        version = (server.split("/", 1)[1].split()[0] if "/" in server else "")[:30]
    return product, version, cpe, [{"name": a["name"], "version": a["version"]} for a in apps]


def identify(port, banner, extra=None):
    """Best-effort {service, product, version, cpe} for a service. Mutates extra['http']['apps']."""
    extra = extra if extra is not None else {}
    out = {"service": "", "product": "", "version": "", "cpe": ""}
    http = extra.get("http")
    if http:
        out["service"] = "https" if extra.get("tls") else "http"
        out["product"], out["version"], out["cpe"], apps = identify_http(http)
        if apps:
            http["apps"] = apps
        return out
    # Banner first, then anything the deep probe collected: the first rule that names a product wins.
    texts = [banner] + [str(v) for v in ((extra.get("probe") or {}).get("responses") or {}).values()]
    for text in texts:
        if not text:
            continue
        for rx, service, product, group, cpe in BANNER_RULES:
            m = rx.search(text)
            if m:
                if not out["service"] or product:
                    version = (m.group(group) or "") if group else ""
                    out.update(service=service, product=product, version=version, cpe=_cpe(cpe, version))
                break
        if out["product"]:
            break
    if not out["service"]:
        guess = PORT_SERVICES.get(int(port), "")
        if extra.get("tls") and not guess:
            guess = "ssl"
        out["service"] = guess
    return out
