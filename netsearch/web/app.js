/* NetSearch UI — dependency-free SPA. Everything from the API is untrusted (banners, titles,
   hostnames come from remote machines), so every interpolated value goes through esc(). */
'use strict';

const $ = (sel, el = document) => el.querySelector(sel);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const SEV = ['info', 'low', 'medium', 'high', 'critical'];
const sevClass = s => 'sev-' + (SEV.includes(s) ? s : 'info');

const state = {
  page: 'dashboard', tabs: { explore: 'hosts', scans: 'jobs', sources: 'providers', insights: 'findings', settings: 'scanning', host: 'overview' },
  explore: { q: '', page: 1, sort: 'recent' }, host: null, poll: null, enrichPoll: null, catalog: [],
};

async function api(path, opts = {}) {
  if (opts.json !== undefined) {
    opts.body = JSON.stringify(opts.json);
    opts.headers = { 'Content-Type': 'application/json' };
  }
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON error body */ }
  if (!res.ok) throw new Error((data && data.detail) || `Request failed (${res.status})`);
  return data;
}

function toast(msg, kind = '') {
  const el = document.createElement('div');
  el.className = 'toast ' + kind;
  el.textContent = msg;
  $('#toasts').append(el);
  setTimeout(() => el.remove(), kind === 'error' ? 7000 : 3500);
}
const fail = e => toast(e.message || String(e), 'error');

function ago(iso) {
  if (!iso) return '—';
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}
const term = (field, value) => `${field}:${/\s/.test(String(value)) ? `"${value}"` : value}`;
const chip = (t, extra = '') => `<span class="chip ${sevClass(t.severity)}" data-action="filter" data-q="${esc(term('tag', t.tag))}" title="${esc(t.reason || t.description || '')}">${esc(t.tag)}${extra}</span>`;
const badge = s => s ? `<span class="badge ${sevClass(s)}">${esc(s)}</span>` : '';
const svcPill = s => `<span class="pill" title="${esc(s.name || '')}"><b>${esc(s.port)}</b> ${s.name ? esc(s.name) + ' <span class="muted">·</span> ' : ''}${esc([s.product || s.service, s.version].filter(Boolean).join(' ') || (s.name ? '' : 'unknown'))}</span>`;
const ENRICH_STATUS = { ok: 'done', partial: 'cancelled', error: 'failed' };
const enrichMark = h => h.enriched_at ? `<span class="status ${ENRICH_STATUS[h.enrich_status] || 'cancelled'}" title="Enrichment: ${esc(h.enrich_status)}">enriched ${esc(ago(h.enriched_at))}</span>` : '<span class="status queued">not enriched</span>';
const tabsBar = (page, items) => `<div class="tabs" role="tablist">${items.map(([id, label, count]) =>
  `<button role="tab" data-action="tab" data-page="${page}" data-tab="${id}" class="${state.tabs[page] === id ? 'active' : ''}">${esc(label)}${count != null ? `<span class="count">${esc(count)}</span>` : ''}</button>`).join('')}</div>`;
const bars = (list, field) => {
  if (!list || !list.length) return '<div class="muted small">No data yet</div>';
  const max = Math.max(...list.map(x => x.count));
  return `<div class="bars">${list.map(x => `<div class="bar-row" data-action="filter" data-q="${esc(term(field, x.value))}">
    <span class="lbl" title="${esc(x.value)}">${esc(x.value)}</span><span class="track"><span class="fill" style="display:block;width:${Math.round(100 * x.count / max)}%"></span></span><span class="cnt">${esc(x.count)}</span></div>`).join('')}</div>`;
};

/* ------------------------------------------------------------ drawer */
function openDrawer(title, html) {
  $('#drawer-title').textContent = title;
  $('#drawer-body').innerHTML = html;
  $('#drawer').hidden = $('#overlay').hidden = false;
}
function closeDrawer() {
  $('#drawer').hidden = $('#overlay').hidden = true;
  state.host = null;
  clearTimeout(state.enrichPoll);
}

/* ------------------------------------------------------------ router */
const pages = {};
function go(page, params) {
  const qs = params ? '?' + new URLSearchParams(params) : '';
  const target = `#/${page}${qs}`;
  if (location.hash === target) render(); else location.hash = target;
}
async function render() {
  clearTimeout(state.poll);
  const [path, qs] = location.hash.slice(2).split('?');
  state.page = pages[path] ? path : 'dashboard';
  const params = new URLSearchParams(qs || '');
  document.querySelectorAll('#nav nav a').forEach(a => a.classList.toggle('active', a.dataset.page === state.page));
  try {
    await pages[state.page](params);
  } catch (e) {
    $('#view').innerHTML = `<div class="empty"><h2>Could not load this page</h2><p>${esc(e.message)}</p><button data-action="reload">Retry</button></div>`;
  }
}
window.addEventListener('hashchange', render);

/* ------------------------------------------------------------ dashboard */
pages.dashboard = async () => {
  const s = await api('/api/stats');
  if (!s.hosts) {
    $('#view').innerHTML = `<div class="page-head"><h1>Dashboard</h1></div>
      <div class="empty"><h2>The database is empty</h2>
      <p>Populate it by scanning a network you control, pulling from a source, or importing a file.</p>
      <div class="row" style="justify-content:center"><button class="primary" data-action="new-scan">New scan</button>
      <button data-action="nav" data-to="sources">Sources &amp; import</button></div></div>`;
    return;
  }
  const f = s.findings, sevCount = k => f[k] || 0;
  $('#view').innerHTML = `<div class="page-head"><h1>Dashboard</h1><span class="spacer"></span><button class="primary" data-action="new-scan">New scan</button></div>
    <div class="tiles">
      <div class="tile"><div class="n">${s.hosts}</div><div class="l">hosts · ${s.public_hosts} public</div></div>
      <div class="tile"><div class="n">${s.services}</div><div class="l">services</div></div>
      <div class="tile"><div class="n">${s.enriched}</div><div class="l">hosts enriched · ${s.analyzed} analysed</div></div>
      <div class="tile"><div class="n" style="color:var(--high)">${sevCount('critical') + sevCount('high')}</div><div class="l">high / critical findings</div></div>
      <div class="tile"><div class="n">${sevCount('medium') + sevCount('low') + sevCount('info')}</div><div class="l">other findings</div></div>
    </div>
    <div class="cards">
      <div class="panel"><h3>Top ports</h3>${bars(s.top_ports, 'port')}</div>
      <div class="panel"><h3>Top products</h3>${bars(s.top_products, 'product')}</div>
      <div class="panel"><h3>Top tags</h3>${bars(s.top_tags, 'tag')}</div>
      <div class="panel"><h3>Data sources</h3>${bars(s.top_sources, 'source')}</div>
      <div class="panel" style="grid-column:1/-1"><h3>Recent activity</h3>${s.activity.length ? `<table>${s.activity.map(a =>
        `<tr><td class="muted" style="white-space:nowrap">${esc(ago(a.ts))}</td><td>${esc(a.actor)}</td><td class="mono">${esc(a.action)}</td><td>${esc(a.detail)}</td></tr>`).join('')}</table>` : '<div class="muted small">Nothing yet</div>'}</div>
    </div>`;
};

/* ------------------------------------------------------------ explore */
pages.explore = async params => {
  const ex = state.explore;
  if (params.has('q')) { ex.q = params.get('q'); ex.page = Number(params.get('page') || 1); }
  if (params.get('host')) openHost(params.get('host'), 'overview').catch(fail);  // deep link: #/explore?host=IP
  let res, error = '';
  try {
    res = await api(`/api/search?${new URLSearchParams({ q: ex.q, page: ex.page, sort: ex.sort, size: 25 })}`);
  } catch (e) { error = e.message; res = { total: 0, hosts: [], facets: {}, size: 25 }; }
  const pagesTotal = Math.max(1, Math.ceil(res.total / res.size));
  const facetNames = { port: 'Port', service: 'Service', product: 'Product', tag: 'Tag', country: 'Country', org: 'Organisation' };
  const hostsView = res.hosts.map(h => `<div class="host" data-action="open-host" data-ip="${esc(h.ip)}">
      <div class="top"><span class="ip">${esc(h.ip)}</span>${badge(h.ai_risk)}<span class="meta">${esc([h.hostnames[0], h.org, h.country].filter(Boolean).join(' · '))}</span>
        <span class="spacer" style="flex:1"></span><span class="meta">${esc(ago(h.last_seen))} · ${esc(h.sources.join(', '))}</span>${enrichMark(h)}<button class="mini" data-action="enrich-host" data-ip="${esc(h.ip)}">Enrich</button></div>
      ${h.ai_summary ? `<div class="summary">${esc(h.ai_summary)}</div>` : ''}
      <div>${h.services.slice(0, 14).map(svcPill).join('')}${h.services.length > 14 ? `<span class="muted small">+${h.services.length - 14} more</span>` : ''}${h.services.length ? '' : '<span class="muted small">no services recorded</span>'}</div>
      <div>${h.tags.map(t => chip(t)).join('')}</div></div>`).join('');
  const tableView = `<div class="table-wrap"><table><tr><th>Host</th><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>What it is</th><th>Title</th></tr>${
    res.hosts.flatMap(h => h.services.map(s => `<tr class="click" data-action="open-host" data-ip="${esc(h.ip)}"><td class="mono">${esc(h.ip)}</td><td class="mono">${esc(s.port)}/${esc(s.transport)}</td><td>${esc(s.service)}</td><td>${esc(s.product)}</td><td class="mono">${esc(s.version)}</td><td>${esc(s.name)}</td><td>${esc(s.title)}</td></tr>`)).join('')}</table></div>`;
  $('#view').innerHTML = `<div class="page-head"><h1>Explore</h1><span class="spacer"></span><button data-action="query-help">Query help</button>
      <button class="primary" data-action="enrich-results" ${res.total ? '' : 'disabled'} title="Source lookups, deep probe and AI identification for every host matching this search">Enrich ${res.total === 1 ? '1 result' : esc(res.total) + ' results'}</button></div>
    <form class="searchbar" data-submit="search">
      <input name="q" value="${esc(ex.q)}" placeholder='port:22 product:openssh -tag:outdated-software   or free text' autocomplete="off" spellcheck="false" aria-label="Search query">
      <select name="sort" aria-label="Sort">${[['recent', 'Recently seen'], ['risk', 'Risk'], ['ports', 'Most ports'], ['ip', 'IP address'], ['enriched', 'Recently enriched']].map(([v, l]) => `<option value="${v}" ${ex.sort === v ? 'selected' : ''}>${l}</option>`).join('')}</select>
      <button class="primary">Search</button>
    </form>
    ${error ? `<div class="notice">${esc(error)}</div>` : ''}
    <div class="explore">
      <div class="facets">${Object.entries(facetNames).map(([k, label]) => (res.facets[k] || []).length ? `<div class="panel"><h3>${label}</h3>${bars(res.facets[k], k)}</div>` : '').join('') || '<div class="muted small">Facets appear once there are results.</div>'}</div>
      <div>
        ${tabsBar('explore', [['hosts', 'Hosts', res.total], ['table', 'Services table']])}
        ${res.hosts.length ? (state.tabs.explore === 'table' ? tableView : hostsView) : `<div class="empty"><h2>No hosts match</h2><p>${ex.q ? 'Try fewer filters, or open Query help for the syntax.' : 'Run a scan or import data to get started.'}</p></div>`}
        ${pagesTotal > 1 ? `<div class="pager"><button data-action="page" data-d="-1" ${ex.page <= 1 ? 'disabled' : ''}>← Prev</button><span>Page ${ex.page} of ${pagesTotal}</span><button data-action="page" data-d="1" ${ex.page >= pagesTotal ? 'disabled' : ''}>Next →</button></div>` : ''}
      </div>
    </div>`;
};

const QUERY_HELP = `<p>Combine filters with spaces (AND). Prefix any filter with <span class="mono">-</span> to negate it. Quote values with spaces. Bare words search banners, products, hostnames, organisations and summaries.</p>
<table>${[
  ['port:22 · port:80,443 · port:8000-8100', 'Open port(s)'], ['service:ssh', 'Protocol (exact)'], ['product:nginx · version:1.18', 'Software and version prefix'],
  ['banner:"220 ProFTPD" · title:login · server:apache', 'Banner / HTTP title / Server header'], ['cert:example.com · cpe:openssh', 'TLS certificate text / CPE'],
  ['ip:10.0.0.* · net:10.0.0.0/24', 'Address or CIDR'], ['hostname:example.com · org:hetzner · asn:AS13335 · country:DE', 'Ownership and location'],
  ['tag:exposed-database · risk:high · severity:critical', 'Tags, AI risk, finding severity'], ['cve:CVE-2021-41773 · has:cve', 'Known vulnerabilities'],
  ['has:ai · has:tls · has:finding · has:hostname · has:service', 'Presence checks'], ['has:enriched · -has:enriched · enriched:partial · has:screenshot', 'Enrichment status (ok, partial, error)'], ['name:grafana', 'What the AI says a service is'], ['is:public · is:private', 'Address class'],
  ['source:scan · source:shodan', 'Where the data came from'], ['after:2026-01-01 · before:2026-06-01', 'Last seen'],
].map(([a, b]) => `<tr><td class="mono small">${esc(a)}</td><td>${esc(b)}</td></tr>`).join('')}</table>
<p class="muted small" style="margin-top:12px">Service filters in one query must match the same service: <span class="mono">port:8080 product:jenkins</span> finds Jenkins on 8080. A negated service filter means the host has no such service.</p>`;

/* ------------------------------------------------------------ host drawer */
async function openHost(ip, tab) {
  if (tab) state.tabs.host = tab;
  const h = await api('/api/hosts/' + encodeURIComponent(ip));
  if (!state.catalog.length) state.catalog = await api('/api/tags');
  state.host = h;
  const hostTags = h.tags.filter(t => !t.port);
  const kv = rows => `<dl class="kv">${rows.filter(r => r[1]).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join('')}</dl>`;
  const cve = v => /^CVE-\d{4}-\d+$/.test(v) ? `<a class="pill" target="_blank" rel="noopener noreferrer" href="https://nvd.nist.gov/vuln/detail/${esc(v)}">${esc(v)}</a>` : `<span class="pill">${esc(v)}</span>`;
  const tagChip = t => chip(t, t.origin === 'rule' ? '' : `<button data-action="rm-tag" data-tag="${esc(t.tag)}" data-port="${esc(t.port)}" aria-label="Remove tag">✕</button>`);

  const overview = `
    <div class="insight">
      <div class="row" style="margin-bottom:6px"><h3 style="margin:0">Insight</h3>${badge(h.ai_risk)}<span class="grow"></span><span class="muted small">${h.ai_updated ? esc(h.ai_model) + ' · ' + esc(ago(h.ai_updated)) : ''}</span></div>
      <p>${h.ai_summary ? esc(h.ai_summary) : '<span class="muted">Not analysed yet. Run an analysis to get a summary, a risk level, tags and findings.</span>'}</p>
      <div class="row"><button class="primary" data-action="enrich-host" data-ip="${esc(h.ip)}">Enrich</button><button data-action="analyze">Analyse with AI</button><button data-action="enrich">Source lookups</button><button data-action="rescan">Rescan</button></div>
    </div>
    <div class="section"><h3>Enrichment</h3>${h.enriched_at ? `<div class="row" style="margin-bottom:6px">${enrichMark(h)}<span class="muted small">${esc(h.enriched_at)} · took ${esc(h.enrich_detail.seconds ?? '?')}s</span></div>
      <table>${Object.entries(h.enrich_detail.steps || {}).map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td><span class="status ${v.status === 'ok' ? 'done' : v.status === 'error' ? 'failed' : 'cancelled'}">${esc(v.status)}</span></td><td class="small">${esc(v.note || '')}<div class="muted">${esc(ago(v.at))}</div></td></tr>`).join('')}</table>`
      : '<p class="muted small">Not enriched yet. Enrich runs source lookups, probes each known service (web pages are opened in a headless browser) and asks the AI to say what is running.</p>'}</div>
    <div class="section"><h3>Tags</h3><div>${hostTags.map(tagChip).join('') || '<span class="muted small">No host-level tags</span>'}</div>
      <form class="row" data-submit="add-tag" style="margin-top:8px"><input class="grow" name="tag" list="tag-list" placeholder="Add a tag…" required>
        <select name="port" style="width:auto"><option value="0">host</option>${h.services.map(s => `<option value="${esc(s.port)}">port ${esc(s.port)}</option>`).join('')}</select><button>Add</button>
        <datalist id="tag-list">${state.catalog.map(t => `<option value="${esc(t.tag)}">`).join('')}</datalist></form></div>
    <div class="section"><h3>Host</h3>${kv([
      ['Hostnames', h.hostnames.map(esc).join('<br>')], ['Organisation', esc(h.org)], ['ISP', esc(h.isp !== h.org ? h.isp : '')], ['ASN', esc(h.asn)],
      ['Location', esc([h.city, h.country].filter(Boolean).join(', '))], ['OS', esc(h.os)], ['Address', h.is_public ? 'public' : 'private / non-routable'],
      ['Sources', esc(h.sources.join(', '))], ['First seen', esc(h.first_seen)], ['Last seen', esc(h.last_seen)]])}</div>
    ${h.vulns.length ? `<div class="section"><h3>Reported CVEs (${h.vulns.length})</h3><p class="muted small">Reported by third-party sources from version matching; not verified against this host.</p>${h.vulns.slice(0, 60).map(cve).join('')}</div>` : ''}
    <div class="section"><h3>Notes</h3><form data-submit="save-notes"><textarea name="notes" placeholder="Your notes about this host">${esc(h.notes)}</textarea><div class="row" style="margin-top:8px"><button>Save notes</button><span class="grow"></span><button type="button" class="danger" data-action="delete-host">Delete host</button></div></form></div>`;

  const services = h.services.map(s => {
    const http = s.extra.http, tls = s.extra.tls, nmap = s.extra.nmap, probe = s.extra.probe, aiId = s.extra.ai;
    const web = probe && probe.web, answers = Object.entries((probe && probe.responses) || {});
    const tags = h.tags.filter(t => t.port === s.port);
    return `<details class="svc"><summary><span class="mono"><b>${esc(s.port)}</b>/${esc(s.transport)}</span><span>${esc(s.service || 'unknown')}</span>
      <span class="grow" style="flex:1">${s.name ? `<b>${esc(s.name)}</b> <span class="muted">·</span> ` : ''}${esc([s.product, s.version].filter(Boolean).join(' '))}${http && http.title ? ` <span class="muted">— ${esc(http.title)}</span>` : ''}</span>${tags.map(t => `<span class="chip ${sevClass(t.severity)}" title="${esc(t.reason)}">${esc(t.tag)}</span>`).join('')}</summary>
      <div class="body">
        ${tags.filter(t => t.reason).map(t => `<div class="small"><span class="${sevClass(t.severity)}" style="border:none">●</span> <b>${esc(t.tag)}</b> <span class="muted">(${esc(t.origin)})</span> — ${esc(t.reason)} ${t.origin === 'rule' ? '' : `<button class="link small" data-action="rm-tag" data-tag="${esc(t.tag)}" data-port="${esc(t.port)}">remove</button>`}</div>`).join('')}
        ${s.summary ? `<p style="margin-top:8px">${esc(s.summary)}</p>` : ''}
        ${aiId ? `<div class="muted small">Identified by ${esc(aiId.model)} (${esc(aiId.confidence)} confidence${aiId.product ? ': ' + esc([aiId.product, aiId.version].filter(Boolean).join(' ')) : ''}) · ${esc(ago(aiId.at))}</div>` : ''}
        ${web && web.screenshot ? `<a class="shot" href="/api/shots/${encodeURIComponent(web.screenshot)}" target="_blank" rel="noopener noreferrer"><img loading="lazy" alt="Screenshot of port ${esc(s.port)}" src="/api/shots/${encodeURIComponent(web.screenshot)}?t=${encodeURIComponent(s.probed_at)}"></a>` : ''}
        ${web ? `<h3>Browser view</h3>${kv([['Opened', esc(web.final_url || web.url)], ['Problem', esc(web.error)], ['Generator', esc(web.generator)], ['Application', esc(web.app_name)], ['Description', esc(web.description)],
          ['Headings', esc((web.headings || []).join(' · '))], ['Libraries', esc(Object.entries(web.libs || {}).map(([k, v]) => k + (v ? ' ' + v : '')).join(', '))], ['Cookies', esc((web.cookies || []).join(', '))],
          ['Forms', web.forms ? esc(`${web.forms} form(s), ${web.password_fields || 0} password field(s)`) : ''], ['Blocked requests', esc((web.blocked_hosts || []).join(', '))],
          ['Favicon MD5', web.favicon_md5 ? `<span class="mono small">${esc(web.favicon_md5)}</span>` : ''], ['Page text', web.text ? `<details><summary class="muted small">show</summary><pre>${esc(web.text)}</pre></details>` : '']])}` : ''}
        ${answers.length ? `<h3>Probe answers</h3>${answers.map(([k, v]) => `<div class="small mono muted">${esc(k)}</div><pre>${esc(v)}</pre>`).join('')}` : ''}
        ${s.banner ? `<h3 style="margin-top:10px">Banner</h3><pre>${esc(s.banner)}</pre>` : '<p class="muted small" style="margin-top:8px">No banner captured — this port is known from a source that does not provide one. Rescan to grab it.</p>'}
        ${http ? `<h3>HTTP</h3>${kv([['Status', esc(http.status || '')], ['Title', esc(http.title)], ['Server', esc(http.server)], ['Detected', esc((http.apps || []).map(a => a.name + (a.version ? ' ' + a.version : '')).join(', '))],
          ...Object.entries(http.headers || {}).filter(([k]) => k !== 'server').map(([k, v]) => [k, esc(v)])])}` : ''}
        ${tls ? `<h3>TLS</h3>${kv([['Protocol', esc([tls.version, tls.cipher].filter(Boolean).join(' · '))], ['Common name', esc(tls.cn)], ['Issuer', esc(tls.issuer)], ['Valid', esc(tls.not_before ? `${tls.not_before} → ${tls.not_after}` : '')],
          ['Self-signed', tls.self_signed ? 'yes' : ''], ['SANs', esc((tls.san || []).join(', '))], ['SHA-256', tls.sha256 ? `<span class="mono small">${esc(tls.sha256)}</span>` : '']])}` : ''}
        ${nmap ? `<h3>nmap</h3>${kv([['Extra info', esc(nmap.extrainfo)], ...Object.entries(nmap.scripts || {}).map(([k, v]) => [k, `<pre>${esc(v)}</pre>`])])}` : ''}
        ${kv([['CPE', `<span class="mono small">${esc(s.cpe)}</span>`], ['Sources', esc(s.sources.join(', '))], ['First seen', esc(s.first_seen)], ['Last seen', esc(s.last_seen)], ['Deep probed', esc(s.probed_at)]])}
      </div></details>`;
  }).join('') || '<div class="empty">No services recorded for this host.</div>';

  const findings = h.findings.map(f => `<div class="finding ${sevClass(f.severity)}"><div class="row"><span class="t" style="color:var(--text)">${esc(f.title)}</span>${badge(f.severity)}<span class="grow"></span>
      <span class="muted small">${esc(f.origin)}${f.port ? ' · port ' + esc(f.port) : ''}</span><button class="icon" data-action="rm-finding" data-id="${esc(f.id)}" aria-label="Dismiss finding">✕</button></div><div class="d">${esc(f.detail)}</div></div>`).join('')
    || '<div class="empty">No findings. Run an analysis from the Overview tab.</div>';

  const body = { overview, services, findings, raw: `<pre style="max-height:none">${esc(JSON.stringify(h, null, 2))}</pre>` }[state.tabs.host] || overview;
  openDrawer(h.ip, tabsBar('host', [['overview', 'Overview'], ['services', 'Services', h.services.length], ['findings', 'Findings', h.findings.length], ['raw', 'Raw']]) + body);
  state.host = h;
}

/* ------------------------------------------------------------ enrich */
const ENRICH_STEPS = [['sources', 'Source lookups', 'Reverse DNS, InternetDB, GeoIP and any provider you have a key for'],
  ['probe', 'Deep probe', 'Re-reads each known service, asks protocol questions, opens web pages in a headless browser, nmap -sV for the rest'],
  ['ai', 'AI identification', 'Names and describes each service, tags the host, writes a summary and findings']];

function enrichBody(f) {
  const target = JSON.parse(f.dataset.target), single = !!target.ips;
  const steps = ENRICH_STEPS.map(s => s[0]).filter(k => f[k].checked);
  return { ...target, steps, force: single || !f.skip.checked, max_age_hours: single ? null : Number(f.hours.value) };
}

async function enrichPreview(f) {
  const box = $('#enrich-preview'), btn = f.querySelector('button.primary');
  const body = enrichBody(f), single = !!body.ips;
  if (!body.steps.length) { box.innerHTML = '<div class="notice">Choose at least one step.</div>'; btn.disabled = true; return; }
  const p = await api('/api/enrich/preview', { method: 'POST', json: body });
  const notes = [];
  if (!single) notes.push(`<b>${p.matched}</b> host(s) match · <b>${p.todo}</b> to do${p.fresh ? ` · ${p.fresh} completed in the last ${esc(p.max_age_hours)}h will be skipped` : ''}`);
  if (body.steps.includes('probe') && p.public && !p.scan_allow_public) notes.push(`${p.public} public host(s) will not be probed because public scanning is off. They still get source lookups and AI analysis of the stored data.`);
  if (body.steps.includes('ai')) notes.push(p.ai_enabled ? `AI: ${esc(p.ai_provider_label)}. Hosts are done one at a time; a local model can take a minute or two per host.` : 'AI is switched off in Settings, so the AI step will store a rule-based summary only.');
  box.innerHTML = notes.map(n => `<div class="notice ok">${n}</div>`).join('');
  btn.disabled = !p.todo;
  btn.textContent = single ? 'Enrich this host' : p.todo ? `Enrich ${p.todo} host(s)` : 'Nothing to do';
}

async function enrichDrawer(target) {
  const single = !!target.ips, s = await api('/api/settings');
  const steps = target.steps || ENRICH_STEPS.map(x => x[0]);
  const scope = { ips: target.ips, q: target.q };
  openDrawer(single ? `Enrich ${target.ips[0]}` : 'Enrich hosts', `<form data-submit="start-enrich" data-change="enrich-preview" data-target="${esc(JSON.stringify(scope))}">
    ${single ? '' : `<p>${target.q ? `Every host matching <span class="mono">${esc(target.q)}</span>` : 'Every host in the database'}, one after another in the background.</p>`}
    <div class="field">${ENRICH_STEPS.map(([k, label, hint]) => `<label class="check" style="margin-bottom:8px;align-items:flex-start"><input type="checkbox" name="${k}" ${steps.includes(k) ? 'checked' : ''}><span><b>${label}</b><br><span class="muted small">${hint}</span></span></label>`).join('')}</div>
    <div class="field" ${single ? 'hidden' : ''}><label class="check"><input type="checkbox" name="skip" checked> Skip hosts already enriched in the last <input name="hours" type="number" min="0" step="1" value="${esc(s.enrich_max_age_hours)}" style="width:80px;margin:0 6px"> hours</label>
      <div class="hint">Leave this on to resume a run that was stopped: finished hosts are not repeated.</div></div>
    <div id="enrich-preview"></div>
    <button class="primary" disabled>Enrich</button></form>`);
  await enrichPreview($('#drawer-body form'));
}

function enrichProgress(job, target) {
  const single = target.ips && target.ips.length === 1;
  const draw = j => {
    const o = j.options, active = ['queued', 'running', 'cancelling'].includes(j.status);
    $('#drawer-body').innerHTML = `<div class="row" style="margin-bottom:10px"><span class="status ${esc(j.status)}">${esc(j.status)}</span><span class="muted small">job #${j.id} · steps: ${esc(j.ports)}</span></div>
      <div class="progress" style="height:10px"><div style="width:${j.total ? Math.round(100 * j.done / j.total) : 100}%"></div></div>
      <p style="margin-top:10px"><b>${j.done}</b> of <b>${j.total}</b> host(s) done${o.skipped ? ` · ${esc(o.skipped)} skipped as recently enriched` : ''}</p>
      <p class="muted small">${esc(o.ok || 0)} complete · ${esc(o.partial || 0)} partial · ${esc(o.error || 0)} failed${o.current ? ` · working on <span class="mono">${esc(o.current)}</span>` : ''}</p>
      ${j.error ? `<div class="notice">${esc(j.error)}</div>` : ''}
      ${active ? `<div class="row"><button data-action="cancel-enrich" data-id="${j.id}" ${j.status === 'cancelling' ? 'disabled' : ''}>Stop</button><span class="muted small">It keeps running if you close this panel; progress is on the Scans page.</span></div>`
        : `<div class="notice ok">${j.status === 'done' ? 'Finished.' : 'Stopped. Run Enrich again to carry on: hosts already done are skipped.'}</div>`}`;
    return active;
  };
  const tick = async () => {
    let j;
    try { j = await api('/api/scans/' + job.id); } catch { return; }
    if ($('#drawer').hidden) return;
    if (draw(j)) { state.enrichPoll = setTimeout(tick, 1500); return; }
    if (single && j.status === 'done') { await openHost(target.ips[0], 'services').catch(fail); }
    if (['explore', 'dashboard', 'scans'].includes(state.page)) { const keep = state.host; await render(); state.host = keep; }
  };
  draw(job);
  state.enrichPoll = setTimeout(tick, 800);
}

/* ------------------------------------------------------------ scans */
const jobsTable = d => d.jobs.length ? `<div class="table-wrap"><table><tr><th>#</th><th>Job</th><th>Status</th><th>Targets</th><th>Ports / steps</th><th>Engine</th><th>Progress</th><th>Result</th><th>Started</th><th></th></tr>${d.jobs.map(j => `<tr>
    <td class="mono">${j.id}</td><td>${esc(j.kind || 'scan')}</td><td><span class="status ${esc(j.status)}">${esc(j.status)}</span>${j.error ? `<div class="small muted">${esc(j.error)}</div>` : ''}</td>
    <td class="mono">${esc(j.targets.length > 46 ? j.targets.slice(0, 46) + '…' : j.targets)}<div class="muted small">${esc(j.options.hosts ?? '?')} host(s)${j.kind === 'enrich' && j.options.skipped ? ` · ${esc(j.options.skipped)} skipped as recently done` : ''}${j.options.current ? ` · now ${esc(j.options.current)}` : ''}</div></td><td class="mono">${esc(j.ports.length > 22 ? j.ports.slice(0, 22) + '…' : j.ports)}</td><td>${esc(j.engine)}</td>
    <td><div class="progress"><div style="width:${j.total ? Math.round(100 * j.done / j.total) : 0}%"></div></div><span class="muted small">${j.done}/${j.total}</span></td>
    <td>${j.kind === 'enrich' ? `${j.found} enriched${j.options.error ? `, ${esc(j.options.error)} failed` : ''}` : `${j.found} open`}</td><td class="muted">${esc(ago(j.started || j.created))}</td>
    <td>${['running', 'queued'].includes(j.status) ? `<button data-action="cancel-scan" data-id="${j.id}">Cancel</button>` : j.kind === 'enrich' ? (['cancelled', 'interrupted'].includes(j.status) && j.options.by_query ? `<button data-action="resume-enrich" data-q="${esc(j.options.query)}" data-steps="${esc(j.ports)}">Resume</button>` : '') : j.started ? `<button data-action="filter" data-q="${esc(`after:${j.started} source:${j.engine === 'nmap' ? 'nmap' : 'scan'}`)}">Results</button>` : ''}</td></tr>`).join('')}</table></div>`
  : `<div class="empty"><h2>No scans yet</h2><p>Scan a network you control to start populating the database.</p><button class="primary" data-action="new-scan">New scan</button></div>`;

pages.scans = async () => {
  const [d, s] = await Promise.all([api('/api/scans'), api('/api/settings')]);
  const safety = `<div class="panel"><h3>Scope rules in force</h3>
    <dl class="kv" style="grid-template-columns:200px 1fr"><dt>Public (internet) targets</dt><dd>${s.scan_allow_public ? '<b style="color:var(--medium)">allowed</b>' : 'blocked'}</dd>
    <dt>Never scanned</dt><dd>multicast, link-local (incl. cloud metadata), reserved space${s.scan_exclude ? ', plus exclude list: <span class="mono">' + esc(s.scan_exclude) + '</span>' : ''}</dd>
    <dt>Max hosts per job</dt><dd>${esc(s.scan_max_hosts)}</dd><dt>Rate / concurrency</dt><dd>${esc(s.scan_rate)} conn/s · ${esc(s.scan_concurrency)} parallel</dd></dl>
    <p class="muted small">The scanner connects, reads banners and sends a few read-only requests (HTTP GET /, TLS handshake, Redis INFO, Memcached version). It never authenticates or sends exploit payloads. Only scan networks you own or are authorised to test — unsolicited scanning can breach law, contracts or your ISP's terms.</p>
    <button data-action="nav" data-to="settings">Change in Settings</button></div>`;
  $('#view').innerHTML = `<div class="page-head"><h1>Scans</h1><span class="spacer"></span><button data-action="enrich-all">Enrich all hosts</button><button class="primary" data-action="new-scan">New scan</button></div>
    ${tabsBar('scans', [['jobs', 'Jobs', d.jobs.length], ['safety', 'Scope & safety']])}
    <div id="jobs">${state.tabs.scans === 'safety' ? safety : jobsTable(d)}</div>`;
  if (state.tabs.scans === 'jobs' && d.jobs.some(j => ['running', 'queued', 'cancelling'].includes(j.status))) pollJobs();
};
function pollJobs() {
  state.poll = setTimeout(async () => {
    if (state.page !== 'scans' || state.tabs.scans !== 'jobs') return;
    try {
      const d = await api('/api/scans');
      if ($('#jobs')) $('#jobs').innerHTML = jobsTable(d);
      if (d.jobs.some(j => ['running', 'queued', 'cancelling'].includes(j.status))) pollJobs();
    } catch { /* server restarting; stop polling */ }
  }, 1200);
}

async function newScanDrawer(prefill = '') {
  const [d, s] = await Promise.all([api('/api/scans'), api('/api/settings')]);
  openDrawer('New scan', `<form data-submit="create-scan">
    ${s.scan_allow_public ? '<div class="notice">Public targets are enabled. Only scan addresses you are authorised to test.</div>' : '<div class="notice ok">Private and loopback ranges only. Public targets are blocked until you enable them in Settings → Scanning.</div>'}
    <div class="field"><label for="targets">Targets</label><textarea id="targets" name="targets" required placeholder="192.168.1.0/24&#10;10.0.0.5-20&#10;host.internal">${esc(prefill)}</textarea>
      <div class="hint">IPs, CIDR blocks, ranges or hostnames, separated by spaces, commas or new lines. Up to ${esc(s.scan_max_hosts)} hosts per job.</div></div>
    <div class="grid2">
      <div class="field"><label for="preset">Ports</label><select id="preset" name="preset">${Object.entries(d.presets).map(([k, n]) => `<option value="${esc(k)}" ${k === s.scan_default_ports ? 'selected' : ''}>${esc(k)} (${n} ports)</option>`).join('')}<option value="custom">custom…</option></select></div>
      <div class="field"><label for="custom">Custom ports</label><input id="custom" name="custom" placeholder="22,80,443,8000-8100"><div class="hint">Used when “custom…” is selected.</div></div>
    </div>
    <div class="field"><label for="engine">Engine</label><select id="engine" name="engine"><option value="native">Built-in (fast banner grab + fingerprints)</option><option value="nmap" ${d.nmap ? '' : 'disabled'}>nmap -sV (deeper version detection${d.nmap ? '' : ' — nmap not found'})</option></select></div>
    <details class="adv"><summary>Advanced</summary><div class="grid2">
      <div class="field"><label>Concurrency</label><input name="concurrency" type="number" min="1" max="2000" value="${esc(s.scan_concurrency)}"></div>
      <div class="field"><label>Rate (connections/s)</label><input name="rate" type="number" min="0" value="${esc(s.scan_rate)}"></div>
      <div class="field"><label>Timeout (s)</label><input name="timeout" type="number" min="0.2" max="30" step="0.1" value="${esc(s.scan_timeout)}"></div>
      <div class="field"><label>&nbsp;</label><label class="check"><input type="checkbox" name="rdns" ${s.scan_rdns ? 'checked' : ''}> Reverse-DNS hosts found</label></div>
    </div></details>
    <button class="primary">Start scan</button></form>`);
}

/* ------------------------------------------------------------ sources */
pages.sources = async () => {
  const list = await api('/api/sources');
  const providers = `<div class="cards">${list.map(s => `<div class="panel"><div class="row"><h2>${esc(s.label)}</h2><span class="grow"></span>
      <span class="status ${s.configured ? 'done' : 'cancelled'}">${s.configured ? (s.key_setting ? 'key set' : 'no key needed') : 'needs key'}</span></div>
      <p class="muted" style="margin-top:8px;min-height:60px">${esc(s.description)}${s.verified ? '' : ' <b>Not yet verified against the live API.</b>'}</p>
      <div class="row"><span class="muted small">${s.hosts} host(s) in database</span><span class="grow"></span><button data-action="source" data-name="${esc(s.name)}">${s.key_setting && !s.configured ? 'Configure' : 'Open'}</button></div></div>`).join('')}</div>`;
  const imp = `<div class="panel" style="max-width:640px"><form data-submit="import">
      <div class="field"><label for="file">File</label><input id="file" type="file" name="file" required><div class="hint">nmap XML (<span class="mono">-oX</span>), masscan JSON (<span class="mono">-oJ</span>), Shodan export JSONL, Rapid7 Sonar rDNS/FDNS JSONL, or generic JSONL with <span class="mono">ip</span>, <span class="mono">port</span>, <span class="mono">banner</span> fields. Decompress .gz files first.</div></div>
      <div class="grid2"><div class="field"><label>Format</label><select name="format"><option value="auto">Detect automatically</option><option value="nmap-xml">nmap XML</option><option value="jsonl">JSON lines</option><option value="json">JSON array (masscan)</option></select></div>
      <div class="field"><label>Source label</label><input name="source" value="import" placeholder="e.g. sonar-2026-10"></div></div>
      <button class="primary">Import</button></form></div>`;
  const open = `<div class="panel" style="max-width:760px"><p>Bulk datasets are too large to query live. Download a slice, then load it on the Import tab or with <span class="mono">netsearch import FILE</span>.</p>
    <dl class="kv" style="grid-template-columns:190px 1fr">
      <dt>Rapid7 Project Sonar</dt><dd>Reverse-DNS, forward-DNS and port-study dumps. Lines with <span class="mono">name/type/value</span> import as hostnames; port studies with <span class="mono">ip/port/data</span> import as services. Access terms have changed over the years — check Rapid7 Open Data for current availability.</dd>
      <dt>Shodan exports</dt><dd><span class="mono">shodan download</span> output (one banner per line) imports with products, versions, CVEs and TLS details intact.</dd>
      <dt>Your own scans</dt><dd><span class="mono">nmap -sV -oX out.xml …</span> or <span class="mono">masscan -oJ out.json …</span> run elsewhere.</dd>
      <dt>Archived censuses / BigQuery</dt><dd>Export the rows you need as JSON lines with <span class="mono">ip</span>, <span class="mono">port</span> and optionally <span class="mono">banner</span>, <span class="mono">product</span>, <span class="mono">version</span>, <span class="mono">hostname</span>. Old census data describes the internet as it was; label it with a dated source so it is easy to filter.</dd>
    </dl></div>`;
  $('#view').innerHTML = `<div class="page-head"><h1>Sources</h1></div><p class="sub">Combine your own scans with third-party indexes and files. Everything merges into one record per host.</p>
    ${tabsBar('sources', [['providers', 'Providers', list.length], ['import', 'Import file'], ['datasets', 'Open datasets']])}
    ${{ providers, import: imp, datasets: open }[state.tabs.sources] || providers}`;
};

async function sourceDrawer(name) {
  const s = (await api('/api/sources')).find(x => x.name === name);
  openDrawer(s.label, `<p>${esc(s.description)}</p>
    ${s.verified ? '' : '<div class="notice">This connector was written from the provider’s public API documentation and has not been exercised against the live service. Expect to adjust field mappings in <span class="mono">netsearch/sources.py</span>.</div>'}
    ${s.key_setting ? `<div class="section"><h3>Credential</h3><form data-submit="save-key" data-key="${esc(s.key_setting)}" class="row"><input class="grow" type="password" name="value" autocomplete="off" placeholder="${s.configured ? 'Stored — paste a new key to replace' : 'Paste API key / token'}"><button>Save</button></form>
      <div class="hint muted small" style="margin-top:6px">Stored in the local database. ${s.signup ? `Get one at <a href="${esc(s.signup)}" target="_blank" rel="noopener noreferrer">${esc(s.signup)}</a>.` : ''}</div></div>` : ''}
    <div class="section"><h3>Look up an IP</h3><form data-submit="source-lookup" data-name="${esc(s.name)}" class="row"><input class="grow mono" name="ip" placeholder="203.0.113.10" required><button>Look up &amp; import</button></form></div>
    ${s.can_search ? `<div class="section"><h3>Remote search</h3><form data-submit="source-search" data-name="${esc(s.name)}"><div class="field"><input class="mono" name="query" placeholder="Query in ${esc(s.label)}'s own syntax" required><div class="hint">Results are imported into the local database. Each search can consume provider query credits.</div></div>
      <div class="row"><label style="margin:0">Max hosts</label><input name="limit" type="number" value="50" min="1" max="500" style="width:90px"><span class="grow"></span><button class="primary">Search &amp; import</button></div></form></div>` : ''}`);
}

/* ------------------------------------------------------------ insights */
pages.insights = async () => {
  const tab = state.tabs.insights;
  let body = '';
  if (tab === 'tags') {
    const tags = state.catalog = await api('/api/tags');
    body = `<div class="table-wrap"><table><tr><th>Tag</th><th>Severity</th><th>Hosts</th><th>Meaning</th></tr>${tags.map(t => `<tr class="click" data-action="filter" data-q="${esc(term('tag', t.tag))}">
      <td>${chip(t)}</td><td>${badge(t.severity)}</td><td>${t.hosts}</td><td class="muted">${esc(t.description)}</td></tr>`).join('')}</table></div>`;
  } else if (tab === 'coverage') {
    const gaps = await api('/api/gaps?limit=8');
    body = `<p class="sub" style="margin-top:0">What the database is still missing. Background agents work through these lists with <span class="mono">netsearch gaps --json</span>; see <span class="mono">docs/agents.md</span>.</p>
      <div class="cards">${Object.entries(gaps).map(([k, g]) => `<div class="panel"><div class="row"><h2 class="mono">${esc(k)}</h2><span class="grow"></span><span class="tile-n" style="font-size:20px;font-weight:650">${g.count}</span></div>
        <p class="muted small" style="margin-top:6px">${esc(g.label)}</p>${g.ips.map(ip => `<span class="pill" style="cursor:pointer" data-action="open-host" data-ip="${esc(ip)}">${esc(ip)}</span>`).join('')}</div>`).join('')}</div>`;
  } else {
    const list = await api('/api/findings');
    body = list.length ? list.map(f => `<div class="finding ${sevClass(f.severity)}" style="background:var(--panel);cursor:pointer" data-action="open-host" data-ip="${esc(f.ip)}" data-tab="findings">
      <div class="row"><span class="t" style="color:var(--text)">${esc(f.title)}</span>${badge(f.severity)}<span class="grow"></span><span class="mono small">${esc(f.ip)}${f.port ? ':' + esc(f.port) : ''}</span><span class="muted small">${esc(f.origin)} · ${esc(ago(f.created))}</span></div>
      <div class="d">${esc(f.detail)}</div></div>`).join('')
      : `<div class="empty"><h2>No findings yet</h2><p>Findings come from AI analysis and from agents. Open a host and choose “Analyse with AI”, or run <span class="mono">netsearch analyze --unanalyzed</span>.</p></div>`;
  }
  $('#view').innerHTML = `<div class="page-head"><h1>Insights</h1></div>${tabsBar('insights', [['findings', 'Findings'], ['tags', 'Tags'], ['coverage', 'Coverage']])}${body}`;
};

/* ------------------------------------------------------------ settings */
pages.settings = async () => {
  const s = await api('/api/settings'), m = s._meta;
  const num = (k, label, hint, attrs = '') => `<div class="field"><label for="${k}">${label}</label><input id="${k}" name="${k}" type="number" value="${esc(s[k])}" ${attrs}>${hint ? `<div class="hint">${hint}</div>` : ''}</div>`;
  const secret = (k, label) => `<div class="field"><label for="${k}">${label}</label><div class="row"><input class="grow" id="${k}" name="${k}" type="password" autocomplete="off" placeholder="${s[k + '_set'] ? 'Stored — leave blank to keep' : 'Not set'}">${s[k + '_set'] ? `<button type="button" class="danger" data-action="clear-secret" data-key="${k}">Clear</button>` : ''}</div><div class="hint">Or set the <span class="mono">${esc(m.secret_env[k])}</span> environment variable.</div></div>`;
  const forms = {
    scanning: `<label class="check field"><input type="checkbox" name="scan_allow_public" ${s.scan_allow_public ? 'checked' : ''}> Allow scanning public (internet-routable) addresses</label>
      <div class="notice">Leave this off unless you own the targets or have written permission. Unsolicited scanning may be unlawful where you or the target are, and commonly breaches hosting and ISP terms.</div>
      <div class="grid2">${num('scan_max_hosts', 'Max hosts per job', '', 'min="1"')}${num('scan_concurrency', 'Concurrency', 'Simultaneous connections', 'min="1" max="2000"')}
      ${num('scan_rate', 'Rate limit', 'New connections per second; 0 = unlimited', 'min="0"')}${num('scan_timeout', 'Timeout (s)', '', 'min="0.2" max="30" step="0.1"')}</div>
      <div class="field"><label for="scan_default_ports">Default ports</label><input id="scan_default_ports" name="scan_default_ports" value="${esc(s.scan_default_ports)}"><div class="hint">Preset (top100, top20, web, databases, remote) or a list like 22,80,443,8000-8100.</div></div>
      <div class="field"><label for="scan_exclude">Never scan</label><textarea id="scan_exclude" name="scan_exclude" placeholder="10.0.0.1, 192.168.50.0/24">${esc(s.scan_exclude)}</textarea><div class="hint">IPs or CIDR blocks that are always refused.</div></div>
      <label class="check field"><input type="checkbox" name="scan_rdns" ${s.scan_rdns ? 'checked' : ''}> Reverse-DNS hosts after a scan</label>`,
    ai: `<label class="check field"><input type="checkbox" name="ai_enabled" ${s.ai_enabled ? 'checked' : ''}> Use AI to identify services and analyse hosts</label>
      <p class="muted small">Enrichment and analysis send a host's services, banners, page text and metadata to the provider chosen here. With AI off or the provider failing, a rule-based summary is stored instead and labelled “heuristic”.</p>
      <div class="grid2"><div class="field"><label for="ai_provider">Which AI to use</label><select id="ai_provider" name="ai_provider">${Object.entries(m.ai_providers).map(([v, l]) => `<option value="${esc(v)}" ${s.ai_provider === v ? 'selected' : ''}>${esc(l)}${m.agents[v] === '' ? ' — not found on PATH' : ''}</option>`).join('')}</select><div class="hint">Save, then use Test to check it answers.</div></div>
      ${num('ai_timeout', 'Timeout (s)', 'Per request, for local models and agents', 'min="10"')}</div>
      <div class="row field"><button type="button" data-action="ai-test">Test saved provider</button><span id="ai-test-result" class="small muted"></span></div>
      <h3>Agents</h3>
      <p class="muted small">Agent CLIs are run once per request with their tools switched off (Claude: no tools; Codex: read-only sandbox in an empty folder; opencode: all permissions denied). They use whatever account each CLI is signed in to.</p>
      <div class="grid2"><div class="field"><label for="ai_claude_model">claude model</label><input id="ai_claude_model" name="ai_claude_model" value="${esc(s.ai_claude_model)}" placeholder="haiku"><div class="hint">${m.agents.claude ? esc(m.agents.claude) : 'claude not found on PATH'}</div></div>
      <div class="field"><label for="ai_codex_model">codex model</label><input id="ai_codex_model" name="ai_codex_model" value="${esc(s.ai_codex_model)}" placeholder="Codex default"><div class="hint">${m.agents.codex ? esc(m.agents.codex) : 'codex not found on PATH'} · blank = Codex's own default</div></div>
      <div class="field"><label for="ai_opencode_model">opencode model</label><input id="ai_opencode_model" name="ai_opencode_model" value="${esc(s.ai_opencode_model)}" placeholder="opencode default"><div class="hint">${m.agents.opencode ? esc(m.agents.opencode) : 'opencode not found on PATH'} · provider/model, see <span class="mono">opencode models</span></div></div></div>
      <h3>Local model</h3>
      <div class="field"><label for="ai_base_url">Server URL</label><input id="ai_base_url" name="ai_base_url" value="${esc(s.ai_base_url)}"><div class="hint">Base of an OpenAI-compatible API (llama.cpp, Ollama, LM Studio…), ending in /v1.</div></div>
      <div class="grid2"><div class="field"><label for="ai_model">Model</label><input id="ai_model" name="ai_model" value="${esc(s.ai_model)}" placeholder="Automatic"><div class="hint">Used by the local server and the Anthropic API. Blank = the server's first model, or claude-opus-5-5.</div></div>${secret('ai_api_key', 'API key (optional)')}</div>
      <h3>Anthropic API</h3>
      ${secret('anthropic_api_key', 'Anthropic API key')}
      <div class="grid2"><div class="field"><label for="ai_effort">Effort</label><select id="ai_effort" name="ai_effort">${['low', 'medium', 'high', 'xhigh', 'max'].map(e => `<option ${s.ai_effort === e ? 'selected' : ''}>${e}</option>`).join('')}</select><div class="hint">Higher = more thorough and more tokens per host.</div></div></div>`,
    enrichment: `<p class="muted small">Enrich runs three steps per host: source lookups, a deep probe of the services already known, and AI identification. The deep probe obeys the scope rules on the Scanning tab, so public hosts are only probed when public scanning is allowed.</p>
      <div class="grid2">${num('enrich_max_age_hours', 'Skip hosts enriched within (hours)', 'Lets you stop a run and resume it later; 0 = never skip', 'min="0" step="1"')}
      ${num('enrich_ai_probes', 'Extra probes the AI may request', 'Per host, from a fixed read-only menu; 0 = none', 'min="0" max="20"')}
      ${num('probe_timeout', 'Probe timeout (s)', 'Per protocol probe', 'min="1" max="15" step="0.5"')}
      <div class="field"><label for="probe_browser_channel">Browser</label><select id="probe_browser_channel" name="probe_browser_channel">${[['', 'Automatic'], ['msedge', 'Microsoft Edge'], ['chrome', 'Google Chrome']].map(([v, l]) => `<option value="${v}" ${s.probe_browser_channel === v ? 'selected' : ''}>${l}</option>`).join('')}</select></div></div>
      <label class="check field"><input type="checkbox" name="probe_browser" ${s.probe_browser ? 'checked' : ''}> Open web services in a headless browser (Playwright) and keep a screenshot</label>
      <p class="muted small">The browser loads only the address being probed: requests to any other host are blocked and listed. Pages are untrusted; nothing is typed, clicked or submitted.</p>
      <label class="check field"><input type="checkbox" name="probe_nmap" ${s.probe_nmap ? 'checked' : ''}> Use nmap -sV for services the built-in probes cannot identify${m.nmap ? '' : ' (nmap not found)'}</label>`,
    keys: `${secret('shodan_api_key', 'Shodan API key')}${secret('censys_api_token', 'Censys personal access token')}${secret('zoomeye_api_key', 'ZoomEye API key')}
      <p class="muted small">Keys are stored unencrypted in the local SQLite database. Shodan InternetDB, reverse DNS and ip-api.com need no key.</p>`,
  };
  const tab = state.tabs.settings;
  $('#view').innerHTML = `<div class="page-head"><h1>Settings</h1></div>${tabsBar('settings', [['scanning', 'Scanning'], ['enrichment', 'Enrichment'], ['ai', 'AI'], ['keys', 'API keys'], ['about', 'About']])}
    ${tab === 'about' ? `<div class="panel" style="max-width:640px"><dl class="kv"><dt>Version</dt><dd>${esc(m.version)}</dd><dt>Database</dt><dd class="mono small">${esc(m.db_path)}</dd><dt>nmap</dt><dd class="mono small">${esc(m.nmap || 'not found')}</dd></dl>
      <p class="muted small">CLI: <span class="mono">netsearch --help</span> · agent guides in <span class="mono">docs/</span> and <span class="mono">.claude/skills/</span>.</p></div>`
      : `<div class="panel" style="max-width:640px"><form data-submit="save-settings">${forms[tab] || forms.scanning}<button class="primary">Save</button></form></div>`}`;
};

/* ------------------------------------------------------------ actions */
const refreshHost = () => state.host && openHost(state.host.ip);
const busy = async (el, label, fn) => {
  const old = el.textContent;
  el.disabled = true; el.textContent = label;
  try { await fn(); } catch (e) { fail(e); } finally { el.disabled = false; el.textContent = old; }
};

const actions = {
  'close-drawer': closeDrawer,
  reload: render,
  nav: el => go(el.dataset.to),
  tab: el => { state.tabs[el.dataset.page] = el.dataset.tab; el.dataset.page === 'host' ? refreshHost() : render(); },
  filter: (el, e) => {
    e.stopPropagation();
    const q = el.dataset.q, ex = state.explore;
    const merged = state.page === 'explore' && !ex.q.includes(q) ? (ex.q + ' ' + q).trim() : q;
    closeDrawer();
    go('explore', { q: merged });
  },
  page: el => go('explore', { q: state.explore.q, page: state.explore.page + Number(el.dataset.d) }),
  'query-help': () => openDrawer('Query syntax', QUERY_HELP),
  'open-host': el => openHost(el.dataset.ip, el.dataset.tab || 'overview').catch(fail),
  'new-scan': () => newScanDrawer().catch(fail),
  rescan: () => newScanDrawer(state.host.ip).catch(fail),
  source: el => sourceDrawer(el.dataset.name).catch(fail),
  analyze: el => busy(el, 'Analysing…', async () => {
    const r = await api(`/api/hosts/${state.host.ip}/analyze`, { method: 'POST' });
    toast(r.mode === 'ai' ? `Analysis complete: ${r.risk} risk, ${r.findings.length} finding(s)` : `AI unavailable (${r.note}). ${r.kept_previous ? 'Kept the previous analysis.' : 'Stored a rule-based summary.'}`, r.mode === 'ai' ? '' : 'error');
    await refreshHost();
  }),
  enrich: el => busy(el, 'Enriching…', async () => {
    const r = await api(`/api/hosts/${state.host.ip}/enrich`, { method: 'POST', json: {} });
    toast(Object.entries(r.results).map(([k, v]) => `${k}: ${v}`).join(' · '));
    await refreshHost();
  }),
  'enrich-results': () => enrichDrawer({ q: state.explore.q }).catch(fail),
  'enrich-all': () => enrichDrawer({ q: '' }).catch(fail),
  'enrich-host': el => enrichDrawer({ ips: [el.dataset.ip] }).catch(fail),
  'resume-enrich': el => enrichDrawer({ q: el.dataset.q, steps: el.dataset.steps.split(',') }).catch(fail),
  'cancel-enrich': async el => { await api(`/api/scans/${el.dataset.id}/cancel`, { method: 'POST' }).catch(fail); el.disabled = true; el.textContent = 'Stopping after this host…'; },
  'ai-test': el => busy(el, 'Testing…', async () => {
    const r = await api('/api/ai/test', { method: 'POST' });
    $('#ai-test-result').textContent = r.ok ? `${r.provider}: ${r.model} answered in ${r.seconds}s` : `${r.provider} failed: ${r.error}`;
    $('#ai-test-result').className = 'small ' + (r.ok ? '' : 'sev-high');
  }),
  'rm-tag': async (el, e) => {
    e.stopPropagation();
    await api(`/api/hosts/${state.host.ip}/tags?${new URLSearchParams({ tag: el.dataset.tag, port: el.dataset.port })}`, { method: 'DELETE' }).catch(fail);
    refreshHost();
  },
  'rm-finding': async el => { await api('/api/findings/' + el.dataset.id, { method: 'DELETE' }).catch(fail); refreshHost(); },
  'delete-host': async el => {
    if (el.dataset.armed !== '1') { el.dataset.armed = '1'; el.textContent = 'Click again to delete'; return; }
    await api('/api/hosts/' + state.host.ip, { method: 'DELETE' }).catch(fail);
    closeDrawer(); render();
  },
  'cancel-scan': async el => { await api(`/api/scans/${el.dataset.id}/cancel`, { method: 'POST' }).catch(fail); render(); },
  'clear-secret': async el => { await api('/api/settings', { method: 'PUT', json: { [el.dataset.key]: null } }).catch(fail); toast('Cleared'); render(); },
};

const formData = f => Object.fromEntries(new FormData(f).entries());
const submits = {
  'quick-search': f => { go('explore', { q: f.q.value }); f.reset(); },
  search: f => { state.explore.sort = f.sort.value; go('explore', { q: f.q.value.trim() }); },
  'add-tag': async f => {
    await api(`/api/hosts/${state.host.ip}/tags`, { method: 'POST', json: { tag: f.tag.value, port: Number(f.port.value) } });
    state.catalog = [];
    await refreshHost();
  },
  'save-notes': async f => { await api(`/api/hosts/${state.host.ip}/notes`, { method: 'PUT', json: { notes: f.notes.value } }); toast('Notes saved'); },
  'create-scan': async f => {
    const d = formData(f);
    const job = await api('/api/scans', { method: 'POST', json: {
      targets: d.targets, ports: d.preset === 'custom' ? d.custom : d.preset, engine: d.engine,
      options: { concurrency: Number(d.concurrency), rate: Number(d.rate), timeout: Number(d.timeout), rdns: !!d.rdns } } });
    toast(`Scan #${job.id} started: ${job.options.hosts} host(s)`);
    closeDrawer();
    state.tabs.scans = 'jobs';
    go('scans');
  },
  import: async f => {
    const file = f.file.files[0];
    const r = await api(`/api/import?${new URLSearchParams({ format: f.format.value, source: f.source.value || 'import' })}`, { method: 'POST', body: file });
    toast(`Imported ${r.records} record(s) covering ${r.hosts} host(s)`);
    f.reset();
  },
  'save-key': async f => {
    await api('/api/settings', { method: 'PUT', json: { [f.dataset.key]: f.value.value } });
    toast('Credential saved');
    closeDrawer(); render();
  },
  'source-lookup': async f => {
    const ip = f.ip.value.trim();
    const r = await api(`/api/hosts/${encodeURIComponent(ip)}/enrich`, { method: 'POST', json: { sources: [f.dataset.name] } });
    const result = r.results[f.dataset.name];
    if (result.startsWith('ok')) { toast(result); await openHost(ip, 'services'); } else toast(`${f.dataset.name}: ${result}`, 'error');
  },
  'source-search': async f => {
    const r = await api(`/api/sources/${f.dataset.name}/search`, { method: 'POST', json: { query: f.query.value, limit: Number(f.limit.value) } });
    toast(`Imported ${r.imported} host(s)`);
    closeDrawer();
    go('explore', { q: 'source:' + f.dataset.name });
  },
  'start-enrich': async f => {
    const job = await api('/api/enrich', { method: 'POST', json: enrichBody(f) });
    enrichProgress(job, JSON.parse(f.dataset.target));
  },
  'save-settings': async f => {
    const d = formData(f);
    f.querySelectorAll('input[type=checkbox]').forEach(c => { d[c.name] = c.checked; });
    await api('/api/settings', { method: 'PUT', json: d });
    toast('Settings saved');
    render();
  },
};

document.addEventListener('click', e => {
  const el = e.target.closest('[data-action]');
  if (!el || (el.tagName === 'FORM')) return;
  const fn = actions[el.dataset.action];
  if (fn) { if (el.tagName === 'A' || el.tagName === 'BUTTON') e.preventDefault(); Promise.resolve(fn(el, e)).catch(fail); }
});
document.addEventListener('submit', e => {
  const f = e.target.closest('form[data-submit]');
  if (!f) return;
  e.preventDefault();
  const btn = f.querySelector('button.primary, button:not([type=button])');
  if (btn) btn.disabled = true;
  Promise.resolve().then(() => submits[f.dataset.submit](f)).catch(fail).finally(() => { if (btn) btn.disabled = false; });
});
document.addEventListener('change', e => {
  const f = e.target.closest('form[data-change]');
  if (f && f.dataset.change === 'enrich-preview') enrichPreview(f).catch(fail);
});
document.addEventListener('keydown', e => { if (e.key === 'Escape' && !$('#drawer').hidden) closeDrawer(); });

if (!location.hash) location.hash = '#/dashboard'; else render();
