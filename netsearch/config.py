"""Paths and setting defaults. Settings live in the database (see db.get_settings)."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOME = Path(os.environ.get("NETSEARCH_HOME") or ROOT / "data")
DB_PATH = HOME / "netsearch.db"
WEB_DIR = Path(__file__).resolve().parent / "web"
SHOTS_DIR = HOME / "shots"   # screenshots taken by the browser probe
USER_AGENT = "netsearch/0.1 (local research scanner)"

DEFAULTS = {
    # Scanning
    "scan_allow_public": False,   # public (internet-routable) targets are refused unless enabled
    "scan_max_hosts": 4096,       # per-job cap on expanded target count
    "scan_concurrency": 200,      # simultaneous connections
    "scan_rate": 300,             # new connections per second (0 = unlimited)
    "scan_timeout": 2.0,          # seconds per connection
    "scan_default_ports": "top100",
    "scan_exclude": "",           # comma/space separated IPs or CIDRs never to scan
    "scan_rdns": True,
    # AI
    "ai_enabled": True,
    "ai_provider": "local",       # local | anthropic | claude | codex | opencode (see ai.PROVIDERS)
    "ai_base_url": "http://127.0.0.1:8080/v1",
    "ai_model": "",               # blank = the server's first model (local) or claude-opus-5-5 (anthropic)
    "ai_effort": "medium",        # anthropic only
    "ai_timeout": 300,            # seconds to wait for a local model or an agent CLI
    "ai_claude_model": "haiku",   # model for the claude CLI agent
    "ai_codex_model": "gpt-5.6-luna",  # model for the codex CLI agent (blank = Codex's own default)
    "ai_opencode_model": "",      # provider/model for the opencode CLI agent (blank = opencode's default)
    # Enrichment
    "enrich_max_age_hours": 24,   # "Enrich" skips hosts completed more recently than this
    "enrich_ai_probes": 8,        # extra read-only probes the model may request per host (0 = none)
    "probe_browser": True,        # render web services in a headless browser (Playwright)
    "probe_browser_channel": "",  # blank = try bundled Chromium, then Edge, then Chrome; or msedge / chrome
    "probe_nmap": True,           # run nmap -sV on services the built-in probes cannot identify
    "probe_timeout": 4.0,         # seconds per protocol probe
    # Secrets (environment variables listed in SECRETS are used when these are empty)
    "ai_api_key": "",             # only if the local server requires one
    "anthropic_api_key": "",
    "shodan_api_key": "",
    "censys_api_token": "",
    "zoomeye_api_key": "",
}

AI_PROVIDERS = ("local", "anthropic", "claude", "codex", "opencode")

SECRETS = {
    "ai_api_key": "NETSEARCH_AI_API_KEY",
    "anthropic_api_key": "ANTHROPIC_API_KEY",
    "shodan_api_key": "SHODAN_API_KEY",
    "censys_api_token": "CENSYS_API_TOKEN",
    "zoomeye_api_key": "ZOOMEYE_API_KEY",
}
