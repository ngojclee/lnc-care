'use strict';
// LNC Care admin console — LN UI Engine lite: dual theme, hash-slug pages, lite-select, toasts, modals, zero frameworks.

const PAGES = [
  'overview', 'inbox', 'conversations', 'posts', 'evidence', 'fleet',
  'channels', 'rules', 'connector', 'audit', 'keys', 'settings'
];

const TITLES = {
  overview: 'Overview',
  inbox: 'Triage inbox',
  conversations: 'Conversations',
  posts: 'Posts & archives',
  evidence: 'Evidence vault',
  fleet: 'Account fleet',
  channels: 'Channels & OAuth',
  rules: 'Triage rules',
  connector: 'MCP connector',
  audit: 'Audit log',
  keys: 'API keys',
  settings: 'Settings'
};

const PROVIDERS = {
  meta: 'Meta (Facebook & Instagram)',
  tiktok: 'TikTok Business',
  youtube: 'YouTube'
};
const PROV_SHORT = { meta: 'M', tiktok: 'T', youtube: 'Y' };

const BUCKET_META = [
  { key: 'all', label: 'All' },
  { key: 'should_consult', label: 'Should consult' },
  { key: 'needs_review', label: 'Needs review' },
  { key: 'praise', label: 'VIP & praise' },
  { key: 'complaint', label: 'Complaints' },
  { key: 'spam_clone', label: 'Spam / clone' },
  { key: 'evidence', label: 'Defamation / evidence' }
];

const ACTION_LABELS = {
  should_consult: ['Should consult', 'b-ok'],
  needs_review: ['Needs manual review', 'b-warn'],
  prioritize_care: ['Priority order care', 'b-warn'],
  preserve_evidence: ['Preserve forensic evidence', 'b-err'],
  hide_spam: ['Hide spam / clone', 'b-err']
};

const CONN_STATES = {
  not_connected: ['Not connected', 'b-dim'],
  pending_review: ['Not authorized', 'b-warn'],
  verified: ['Verified', 'b-ok'],
  expired: ['Expired', 'b-err']
};

const ERRORS = {
  provider_permission_denied: 'The provider denied access. Verify OAuth scopes and page permissions.',
  provider_unavailable: 'The provider could not be reached. Check network egress and stored credentials.',
  reauthorization_required: 'This connection expired and must be authorized again.',
  provider_rate_limited: 'Provider rate limit reached. Try again shortly.',
  master_key_not_configured: 'LNC_MASTER_KEY is not configured on this service.',
  agent_hub_or_bridge_not_configured: 'Neither LNC Agent Hub nor the LNC Ads LAN bridge is configured.',
  shared_oauth_broker_unavailable: 'Shared OAuth broker is currently unreachable.',
  management_key_env_managed: 'Management key is controlled by environment variable and cannot be rotated in UI.',
  mcp_gateway_not_configured: 'LNC_MCP_GATEWAY_URL is not configured on this service.'
};

const ICON_COPY = '<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';

const state = {
  csrf: '',
  shopId: null,
  overview: null,
  comments: [],
  commentSummary: null,
  selectedCommentId: null,
  selectedBucket: 'all',
  selectedAssignment: 'all',
  selectedChannelId: '',
  searchQuery: '',
  conversations: [],
  selectedConversationId: null,
  conversationMessages: [],
  leads: [],
  handoffs: [],
  posts: [],
  selectedPostId: null,
  postDetail: null,
  evidenceCases: [],
  fleet: { runtimes: [], leases: [] },
  discovered: {},
  selectedAppProvider: 'meta',
  rules: [],
  connector: null,
  audit: { events: [], valid: true, checked: 0 },
  auditFilter: '',
  keysInventory: { keys: [], mgmt: {} },
  createdSecretBanner: null,
  settings: null
};

const $ = sel => document.querySelector(sel);
const $$ = sel => [...document.querySelectorAll(sel)];
const esc = v => String(v ?? '').replace(/[&<>"']/g, ch => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[ch]));
const num = v => new Intl.NumberFormat('en-US').format(Number(v) || 0);
const when = ts => {
  if (!ts) return '-';
  const d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
  return Number.isNaN(d.getTime()) ? esc(ts) : d.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
};
const badge = (text, cls = 'b-dim') => `<span class="badge ${cls}"><span class="dot"></span>${esc(text)}</span>`;
const provBadge = p => `<span class="prov"><span class="prov-ic prov-${esc(p || 'meta')}">${esc(PROV_SHORT[p] || 'C')}</span>${esc(PROVIDERS[p] || p || 'Meta')}</span>`;
const copyChip = text => `<span class="copy-chip"><code>${esc(text)}</code><button type="button" class="copy-btn" data-copy="${esc(text)}" aria-label="Copy">${ICON_COPY}</button></span>`;
const errorText = err => ERRORS[err?.message] || err?.message || 'Request failed';

function initials(name) {
  const parts = String(name || 'U').trim().split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  return (parts[0] || 'U').slice(0, 2).toUpperCase();
}

function card(title, body, { sub = '', tools = '', flush = false, foot = '' } = {}) {
  return `<div class="card">` +
    `<div class="card-header"><div><h2>${title}</h2>${sub ? `<div class="sub">${sub}</div>` : ''}</div>${tools ? `<div class="toolbar">${tools}</div>` : ''}</div>` +
    `<div class="card-body${flush ? ' flush' : ''}">${body}</div>` +
    `${foot ? `<div class="card-foot">${foot}</div>` : ''}</div>`;
}

function table(heads, rows, emptyText) {
  if (!rows.length) return `<div class="empty">${esc(emptyText)}</div>`;
  const ths = heads.map(h => `<th${h.startsWith('#') ? ' class="num"' : ''}>${esc(h.replace(/^#/, ''))}</th>`).join('');
  return `<div class="table-wrap"><table class="data-table"><thead><tr>${ths}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
}

function paintTableError(cols, err) {
  return `<div class="table-wrap"><table class="data-table"><tbody><tr><td colspan="${cols}" class="table-err">Failed to load: ${esc(errorText(err))}</td></tr></tbody></table></div>`;
}

/* ---------- lite-select (rounded popup matching trigger radius) ---------- */
function enhanceSelect(select) {
  if (!select) return;
  if (select._enhanceRender) { select._enhanceRender(); return; }
  select.classList.add('select-src');
  const wrap = document.createElement('div');
  wrap.className = 'select';
  if (select.style.flex) wrap.style.flex = select.style.flex;
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'select-btn';
  btn.setAttribute('aria-haspopup', 'listbox');
  btn.setAttribute('aria-expanded', 'false');
  if (select.disabled) btn.disabled = true;
  if (select.getAttribute('aria-label')) btn.setAttribute('aria-label', select.getAttribute('aria-label'));
  btn.innerHTML = '<span class="select-value"></span><span class="select-arrow" aria-hidden="true">&#9662;</span>';
  const menu = document.createElement('div');
  menu.className = 'select-menu';
  menu.setAttribute('role', 'listbox');

  const closeMenu = () => {
    wrap.classList.remove('open');
    btn.setAttribute('aria-expanded', 'false');
  };

  const renderMenu = () => {
    const value = select.value;
    btn.disabled = select.disabled;
    btn.querySelector('.select-value').textContent = select.selectedOptions[0]?.textContent ?? '';
    menu.innerHTML = '';
    [...select.options].forEach(option => {
      const item = document.createElement('button');
      item.type = 'button';
      item.setAttribute('role', 'option');
      item.setAttribute('aria-selected', String(option.value === value));
      item.textContent = option.textContent;
      item.addEventListener('click', ev => {
        ev.preventDefault();
        ev.stopPropagation();
        select.value = option.value;
        select.dispatchEvent(new Event('change', { bubbles: true }));
        closeMenu();
        btn.focus();
      });
      menu.append(item);
    });
  };

  btn.addEventListener('click', ev => {
    ev.preventDefault();
    ev.stopPropagation();
    if (btn.disabled) return;
    const next = !wrap.classList.contains('open');
    $$('.select.open').forEach(other => {
      if (other !== wrap) {
        other.classList.remove('open');
        other.querySelector('.select-btn')?.setAttribute('aria-expanded', 'false');
      }
    });
    wrap.classList.toggle('open', next);
    btn.setAttribute('aria-expanded', String(next));
    if (next) renderMenu();
  });

  wrap.addEventListener('keydown', ev => {
    if (ev.key === 'Escape') { closeMenu(); btn.focus(); }
  });

  select.addEventListener('change', renderMenu);
  if (select.form) select.form.addEventListener('reset', () => setTimeout(renderMenu, 0));
  select._enhanceRender = renderMenu;
  select.after(wrap);
  wrap.append(btn, menu);
  renderMenu();
}

const enhanceAllSelects = (root = document) => root.querySelectorAll('select').forEach(enhanceSelect);

document.addEventListener('mousedown', ev => {
  $$('.select.open').forEach(wrap => {
    if (!wrap.contains(ev.target)) {
      wrap.classList.remove('open');
      wrap.querySelector('.select-btn')?.setAttribute('aria-expanded', 'false');
    }
  });
});

/* ---------- HTTP, toast, modal, clipboard ---------- */
async function api(url, options = {}) {
  const method = options.method || 'GET';
  const headers = { ...(options.headers || {}) };
  let body = options.body;
  if (body && typeof body !== 'string') {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }
  if (method !== 'GET' && method !== 'HEAD') {
    headers['X-CSRF-Token'] = state.csrf;
  }
  const res = await fetch(url, { credentials: 'same-origin', ...options, method, headers, body });
  if (res.status === 401) {
    location.assign('/login.html');
    throw new Error('Authentication required');
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(typeof data.detail === 'string' ? data.detail : (data.error || `Request failed (${res.status})`));
  }
  return data;
}

function toast(message, kind = 'ok') {
  const host = $('#toasts');
  if (!host) return;
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.innerHTML = `<div class="msg">${esc(message)}</div><button type="button" class="x" aria-label="Dismiss">&times;</button>`;
  el.querySelector('.x').onclick = () => el.remove();
  host.append(el);
  setTimeout(() => el.remove(), kind === 'err' ? 8500 : 4200);
}
const fail = err => toast(errorText(err), 'err');

function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
  const area = document.createElement('textarea');
  area.value = text;
  document.body.append(area);
  area.select();
  const ok = document.execCommand('copy');
  area.remove();
  return ok ? Promise.resolve() : Promise.reject(new Error('Copy failed'));
}

function wireCopyButtons(root = document) {
  root.querySelectorAll('[data-copy]').forEach(btn => {
    btn.onclick = ev => {
      ev.stopPropagation();
      copyText(btn.dataset.copy).then(() => toast('Copied to clipboard', 'ok'), fail);
    };
  });
}

function modal(html, { wide = false } = {}) {
  const root = $('#modal-root');
  root.innerHTML = `<div class="modal-back"><div class="modal-card${wide ? ' wide' : ''}" role="dialog" aria-modal="true">${html}</div></div>`;
  const back = root.firstElementChild;
  const onKey = ev => { if (ev.key === 'Escape') close(); };
  const close = () => {
    document.removeEventListener('keydown', onKey);
    root.innerHTML = '';
  };
  document.addEventListener('keydown', onKey);
  back.addEventListener('click', ev => { if (ev.target === back) close(); });
  back.querySelectorAll('[data-close]').forEach(b => { b.onclick = close; });
  enhanceAllSelects(back);
  wireCopyButtons(back);
  return { root: back, close };
}

function confirmModal({ title, body, confirm = 'Confirm', danger = false }) {
  return new Promise(resolve => {
    let settled = false;
    const m = modal(
      `<h3>${esc(title)}</h3><p>${body}</p>` +
      `<div class="acts">` +
      `<button type="button" class="btn" data-close>Cancel</button>` +
      `<button type="button" class="btn ${danger ? 'btn-danger' : 'btn-primary'}" data-ok>${esc(confirm)}</button>` +
      `</div>`
    );
    m.root.querySelector('[data-ok]').onclick = () => {
      settled = true;
      m.close();
      resolve(true);
    };
    const obs = new MutationObserver(() => {
      if (!document.body.contains(m.root) && !settled) {
        obs.disconnect();
        resolve(false);
      }
    });
    obs.observe($('#modal-root'), { childList: true });
  });
}

async function busy(btn, fn) {
  if (!btn) return fn().catch(fail);
  const prev = btn.disabled;
  btn.disabled = true;
  try {
    return await fn();
  } catch (err) {
    fail(err);
  } finally {
    btn.disabled = prev;
  }
}

/* ---------- Shell & Routing ---------- */
function currentPage() {
  const raw = (location.hash || '#overview').slice(1);
  const [slug] = raw.split('?');
  return PAGES.includes(slug) ? slug : 'overview';
}

function consumeHashQuery() {
  const raw = (location.hash || '').slice(1);
  const [slug, q] = raw.split('?');
  if (!q) return;
  const qp = new URLSearchParams(q);
  history.replaceState(null, '', `${location.pathname}#${PAGES.includes(slug) ? slug : 'overview'}`);
  if (qp.get('oauth_status') === 'connected') {
    toast(`Shared ${qp.get('provider') || 'OAuth'} account connected. Syncing vault...`, 'ok');
    api('/api/admin/hub/sync', { method: 'POST' }).then(() => refreshOverview()).catch(fail);
  } else if (qp.get('oauth_error')) {
    toast(`OAuth error: ${ERRORS[qp.get('oauth_error')] || qp.get('oauth_error')}`, 'err');
  }
}

function renderShell() {
  const page = currentPage();
  $$('.side a[data-page]').forEach(a => a.classList.toggle('on', a.dataset.page === page));
  $$('.page').forEach(sec => sec.classList.toggle('on', sec.id === `page-${page}`));
  $('#main-content')?.classList.toggle('wide', page === 'inbox' || page === 'conversations');

  const o = state.overview;
  const orgName = o?.organization?.name || 'LNC Care';
  $('#crumb').innerHTML = `<span id="org-name">${esc(orgName)}</span> / <b>${esc(TITLES[page] || 'Overview')}</b>`;

  if (o) {
    $('#ver').textContent = `v${o.version}`;
    $('#app-build').textContent = o.version ? `Version ${o.version}` : 'Version unavailable';

    const hub = o.agent_hub || {};
    const br = o.bridge || {};
    const ssoHub = $('#sso-hub-link');
    const ssoAds = $('#sso-ads-link');
    if (ssoHub) ssoHub.hidden = !hub.sso_path;
    if (ssoAds) ssoAds.hidden = !((br.enabled && br.peers && br.peers['lnc-ads']) || hub.sso_path);

    const shopSel = $('#shop-select');
    if (shopSel) {
      shopSel.innerHTML = `<option value="">All shops</option>` +
        (o.shops || []).map(s => `<option value="${s.id}"${String(state.shopId) === String(s.id) ? ' selected' : ''}>${esc(s.name)}</option>`).join('');
      enhanceSelect(shopSel);
    }

    const inb = o.inbox_summary || {};
    const setCount = (id, val) => { const el = $(id); if (el) el.textContent = val ? String(val) : ''; };
    setCount('#count-inbox', inb.total || 0);
    setCount('#count-conversations', inb.conversations_open || 0);
    setCount('#count-channels', (o.channels || []).filter(c => c.approved).length);
    setCount('#count-evidence', o.evidence_cases_count || 0);
    setCount('#count-fleet', o.fleet_summary?.total || 0);
  }
}

async function route() {
  consumeHashQuery();
  const page = currentPage();
  if (page !== 'keys') state.createdSecretBanner = null;
  renderShell();
  if (page === 'overview') renderOverviewPage();
  if (page === 'inbox') await loadInbox();
  if (page === 'conversations') await loadConversations();
  if (page === 'posts') await loadPosts();
  if (page === 'evidence') await loadEvidence();
  if (page === 'fleet') await loadFleet();
  if (page === 'channels') renderChannelsPage();
  if (page === 'rules') await loadRules();
  if (page === 'connector') await loadConnector();
  if (page === 'audit') await loadAudit();
  if (page === 'keys') await loadKeys();
  if (page === 'settings') await loadSettings();
}

async function refreshOverview() {
  const q = state.shopId ? `?shop_id=${encodeURIComponent(state.shopId)}` : '';
  state.overview = await api(`/api/admin/overview${q}`);
  renderShell();
  if (currentPage() === 'overview') renderOverviewPage();
  if (currentPage() === 'channels') renderChannelsPage();
}

/* ==========================================================================
   1. OVERVIEW
   ========================================================================== */
function renderOverviewPage() {
  const host = $('#body-overview');
  const o = state.overview;
  if (!o) {
    host.innerHTML = '<div class="skel" style="width:55%"></div>';
    return;
  }
  const inb = o.inbox_summary || { total: 0, by_bucket: {} };
  const approvedChannels = (o.channels || []).filter(c => c.approved);
  const hub = o.agent_hub || {};
  const br = o.bridge || {};
  const gw = o.mcp_gateway || {};

  const stats = [
    ['Total comments', num(inb.total || 0), `${num(inb.by_bucket?.should_consult || 0)} ready to consult`],
    ['Open conversations', num(inb.conversations_open || 0), `${num(inb.leads_new || 0)} new leads · ${num(inb.handoffs_open || 0)} handoffs`],
    ['Approved channels', `${approvedChannels.length} / ${(o.channels || []).length}`, state.shopId ? 'Filtered by active shop' : 'Across all shops'],
    ['Forensic cases', num(o.evidence_cases_count || 0), 'SHA-256 chain of custody'],
    ['Healthy runtimes', `${o.fleet_summary?.healthy || 0} / ${o.fleet_summary?.total || 0}`, 'Graph API · VeilBrowser · Orbine']
  ].map(([l, n, s]) => `<div class="stat"><div class="l">${esc(l)}</div><div class="n">${esc(n)}</div><div class="s">${esc(s)}</div></div>`).join('');

  const chRows = (o.channels || []).map(ch => `<tr>
    <td><div class="cell-main">${esc(ch.name)}</div><div class="cell-sub">${esc(ch.handle || ch.external_id)}</div></td>
    <td>${provBadge(ch.provider)}</td>
    <td class="mono">${esc(ch.adapter)}</td>
    <td class="num">${num(ch.followers_count)}</td>
    <td class="num">${num(ch.posts_count)}</td>
    <td class="num">${num(ch.comments_count)}</td>
    <td>${badge(ch.reply_policy || 'draft_only', ch.approved ? 'b-ok' : 'b-warn')}</td>
  </tr>`);

  const vaultModeBadge = hub.mode === 'vault_synced'
    ? badge('Agent Hub synced', 'b-ok')
    : (hub.mode === 'ads_bridge_fallback' ? badge('LNC Ads bridge active', 'b-ok') : badge('Standalone local vault', 'b-dim'));

  const govHtml = `<dl class="kv">
    <dt>Vault mode</dt><dd>${vaultModeBadge}</dd>
    <dt>LNC Agent Hub</dt><dd>${hub.url ? `<code>${esc(hub.url)}</code> ${hub.reachable ? badge('Reachable', 'b-ok') : badge('Offline', 'b-warn')}` : badge('Not configured', 'b-dim')}</dd>
    <dt>LNC Ads LAN bridge</dt><dd>${br.ads_internal_url ? `<code>${esc(br.ads_internal_url)}</code> ${hub.bridge_fallback_ready ? badge('Ready', 'b-ok') : badge('Configured', 'b-dim')}` : badge('Disabled', 'b-dim')}</dd>
    <dt>Unified MCP gateway</dt><dd>${gw.gateway_url ? `<code>${esc(gw.gateway_url)}</code>` : badge('Not configured', 'b-dim')}</dd>
    <dt>Provider write gate</dt><dd>${o.writes_enabled ? badge('Guarded writes enabled', 'b-warn') : badge('Draft-for-approval only', 'b-ok')}</dd>
  </dl>`;

  const shopItems = (o.shops || []).length
    ? `<div class="shop-list">${o.shops.map(s => `<div class="shop-item"><span class="cell-main">${esc(s.name)}</span><span class="mono cell-sub">#${s.id}</span></div>`).join('')}</div>`
    : `<p class="hint">No shops created yet. Add a shop to scope channels, triage queues and leads.</p>`;

  const shopHtml = `${shopItems}
    <form id="shop-form" class="inline-form">
      <input type="text" name="name" placeholder="New shop name (e.g. LuxeClaw)" maxlength="80" required>
      <button type="submit" class="btn btn-primary">Create shop</button>
    </form>`;

  host.innerHTML = `<div class="stat-grid">${stats}</div>
    <div class="grid-wide">
      ${card('Owned & discovered channels', table(['Channel', 'Provider', 'Adapter', '#Followers', '#Posts', '#Comments', 'Reply policy'], chRows, 'No channels registered yet. Sync Shared Vault or load the demo workspace.'), {
        sub: 'Channels bound to the active shop or discovered from shared OAuth.',
        flush: true,
        tools: `<button type="button" class="btn btn-sm" id="btn-run-worker">Run worker queue</button><button type="button" class="btn btn-sm" id="btn-seed-demo">Load demo workspace</button>`
      })}
      <div class="stack-sm" style="gap:16px">
        ${card('Ecosystem & safety boundary', govHtml, { sub: 'Independent local vault cache with automatic Hub & LAN fallback.' })}
        ${card('Shops', shopHtml, { sub: 'Multi-brand isolation across LNC Agent Hub, LNC Ads and LNC Care.' })}
      </div>
    </div>`;

  $('#btn-seed-demo')?.addEventListener('click', ev => busy(ev.currentTarget, async () => {
    const res = await api('/api/admin/seed-demo', { method: 'POST' });
    toast(`Demo workspace loaded (${res.channels} channels, ${res.comments} comments)`, 'ok');
    await refreshOverview();
  }));
  $('#btn-run-worker')?.addEventListener('click', ev => busy(ev.currentTarget, async () => {
    const res = await api('/api/admin/jobs/run', { method: 'POST' });
    toast(`Processed ${res.processed || 0} background jobs`, 'ok');
    await refreshOverview();
  }));
  $('#shop-form')?.addEventListener('submit', ev => {
    ev.preventDefault();
    const fd = new FormData(ev.currentTarget);
    busy(ev.currentTarget.querySelector('button'), async () => {
      await api('/api/admin/shops', { method: 'POST', body: { name: fd.get('name') } });
      toast('Shop created', 'ok');
      await refreshOverview();
    });
  });
}

/* ==========================================================================
   2. SPLIT-PANE TRIAGE & CONSULTATION STUDIO (#inbox)
   ========================================================================== */
async function loadInbox() {
  const host = $('#body-inbox');
  try {
    const params = new URLSearchParams();
    if (state.shopId) params.set('shop_id', state.shopId);
    if (state.selectedChannelId) params.set('channel_id', state.selectedChannelId);
    if (state.selectedBucket && state.selectedBucket !== 'all') params.set('bucket', state.selectedBucket);
    if (state.selectedAssignment && state.selectedAssignment !== 'all') params.set('assignment', state.selectedAssignment);
    if (state.searchQuery) params.set('search', state.searchQuery);

    const data = await api(`/api/admin/comments?${params.toString()}`);
    state.comments = data.comments || [];
    state.commentSummary = data.summary || { total: 0, by_bucket: {}, assignment: { all: 0, unassigned: 0, assigned: 0 } };
    if (!state.selectedCommentId && state.comments.length) {
      state.selectedCommentId = state.comments[0].id;
    } else if (state.selectedCommentId && !state.comments.some(c => c.id === state.selectedCommentId)) {
      state.selectedCommentId = state.comments[0]?.id || null;
    }
    renderInboxStudio();
  } catch (err) {
    host.innerHTML = paintTableError(1, err);
  }
}

function renderInboxStudio() {
  const host = $('#body-inbox');
  const sum = state.commentSummary || { total: 0, by_bucket: {}, assignment: { all: 0, unassigned: 0, assigned: 0 } };
  const asg = sum.assignment || { all: 0, unassigned: 0, assigned: 0 };
  const channels = state.overview?.channels || [];

  const segHtml = BUCKET_META.map(b => {
    const cnt = b.key === 'all' ? (sum.total || 0) : ((sum.by_bucket && sum.by_bucket[b.key]) || 0);
    return `<button type="button" class="seg-btn${state.selectedBucket === b.key ? ' on' : ''}" data-bucket="${b.key}">` +
      `<span>${esc(b.label)}</span><span class="cnt">${num(cnt)}</span></button>`;
  }).join('');

  const subtabsHtml = [
    ['all', `All ${num(asg.all || 0)}`],
    ['unassigned', `Unassigned ${num(asg.unassigned || 0)}`],
    ['assigned', `Assigned ${num(asg.assigned || 0)}`]
  ].map(([k, lbl]) => `<button type="button" class="subtab-btn${state.selectedAssignment === k ? ' on' : ''}" data-asg="${k}">${esc(lbl)}</button>`).join('');

  let queueListHtml = '';
  if (!state.comments.length) {
    queueListHtml = `<div class="empty">No comments match the active filter.<div style="margin-top:10px"><button type="button" class="btn btn-sm btn-primary" id="inbox-seed-btn">Load demo workspace</button></div></div>`;
  } else {
    const groups = new Map();
    for (const cm of state.comments) {
      const bKey = cm.bucket || 'needs_review';
      if (!groups.has(bKey)) groups.set(bKey, []);
      groups.get(bKey).push(cm);
    }
    for (const [bKey, items] of groups.entries()) {
      const meta = BUCKET_META.find(m => m.key === bKey) || { label: bKey };
      queueListHtml += `<div class="queue-group-header"><span class="queue-group-tag">${esc(meta.label)}</span><span>${items.length} ${items.length === 1 ? 'comment' : 'comments'}</span></div>`;
      for (const cm of items) {
        const sc = cm.evaluation ? Number(cm.evaluation.overall_score || 0) : 50;
        const scFmt = Number.isInteger(sc) ? String(sc) : sc.toFixed(1);
        queueListHtml += `<div class="queue-card${cm.id === state.selectedCommentId ? ' on' : ''}" data-cm-id="${cm.id}">
          <div class="queue-avatar">${esc(initials(cm.author_name))}</div>
          <div>
            <div class="queue-author">${esc(cm.author_name)}</div>
            <div class="queue-meta">${esc(cm.author_meta || cm.channel_name)}</div>
            <div class="queue-snippet">${esc(cm.text)}</div>
          </div>
          <div class="queue-score">${esc(scFmt)}</div>
        </div>`;
      }
    }
  }

  host.innerHTML = `<div class="seg-bar" id="triage-bucket-bar">${segHtml}</div>
    <div class="triage-split">
      <div class="triage-queue-pane">
        <div class="triage-queue-controls">
          <div class="triage-subtabs">${subtabsHtml}</div>
          <div class="triage-filters-row">
            <select id="inbox-channel-filter" aria-label="Filter by channel">
              <option value="">All channels</option>
              ${channels.map(ch => `<option value="${ch.id}"${String(state.selectedChannelId) === String(ch.id) ? ' selected' : ''}>${esc(ch.name)}</option>`).join('')}
            </select>
            <input type="search" id="inbox-search" value="${esc(state.searchQuery)}" placeholder="Search author or text...">
          </div>
          <div class="triage-sort-row"><span>Grouped by priority bucket</span><span>Highest score &#8595;</span></div>
        </div>
        <div class="triage-queue-list" id="triage-queue-list">${queueListHtml}</div>
      </div>
      <div class="triage-detail-pane" id="triage-detail-pane"></div>
    </div>`;

  enhanceAllSelects(host);

  host.querySelectorAll('[data-bucket]').forEach(btn => {
    btn.onclick = () => { state.selectedBucket = btn.dataset.bucket; loadInbox(); };
  });
  host.querySelectorAll('[data-asg]').forEach(btn => {
    btn.onclick = () => { state.selectedAssignment = btn.dataset.asg; loadInbox(); };
  });
  $('#inbox-channel-filter')?.addEventListener('change', ev => {
    state.selectedChannelId = ev.target.value || '';
    loadInbox();
  });
  $('#inbox-search')?.addEventListener('input', ev => {
    state.searchQuery = ev.target.value.trim();
    clearTimeout(state._searchTimer);
    state._searchTimer = setTimeout(() => loadInbox(), 240);
  });
  $('#inbox-seed-btn')?.addEventListener('click', ev => busy(ev.currentTarget, async () => {
    await api('/api/admin/seed-demo', { method: 'POST' });
    toast('Demo workspace loaded', 'ok');
    await refreshOverview();
    await loadInbox();
  }));
  host.querySelectorAll('[data-cm-id]').forEach(el => {
    el.onclick = () => {
      state.selectedCommentId = Number(el.dataset.cmId);
      host.querySelectorAll('[data-cm-id]').forEach(c => c.classList.toggle('on', Number(c.dataset.cmId) === state.selectedCommentId));
      renderInboxDetailPane();
    };
  });

  renderInboxDetailPane();
}

function renderInboxDetailPane() {
  const pane = $('#triage-detail-pane');
  if (!pane) return;
  const cm = state.comments.find(c => c.id === state.selectedCommentId);
  if (!cm) {
    pane.innerHTML = `<div class="empty" style="margin:auto">Select a comment from the queue to inspect rubric evaluation and consultation drafts.</div>`;
    return;
  }
  const ev = cm.evaluation || {
    overall_score: 50,
    threshold: 80,
    recommended_action: 'needs_review',
    tier_label: 'Tier 3/5: Review',
    confidence: 75,
    data_quality: 'Full post & comment context',
    reasoning_bullets: ['Awaiting rubric evaluation'],
    label_scores: [],
    reply_strategy: { objective: 'Review customer intent', tone: 'Helpful & factual', next_step_cta: '' }
  };
  const [actText, actCls] = ACTION_LABELS[ev.recommended_action] || [ev.recommended_action || 'Review', 'b-warn'];
  const scorePct = Math.max(0, Math.min(100, Number(ev.overall_score || 0)));
  const thresholdPct = Math.max(10, Math.min(95, Number(ev.threshold || 80)));
  const pubDraft = (cm.drafts || []).find(d => d.kind === 'public') || { text: '' };
  const privDraft = (cm.drafts || []).find(d => d.kind === 'private_dm') || { text: '' };
  const strat = ev.reply_strategy || {};

  const rubricRows = (ev.label_scores || []).map(lbl => {
    const p = Math.max(0, Math.min(100, Number(lbl.probability || 0)));
    const pText = p < 1 ? '<1%' : `${p}%`;
    const barCls = lbl.polarity === 'negative'
      ? (p >= 45 ? 'neg-high' : 'pos-mid')
      : (p >= 60 ? 'pos-high' : 'pos-mid');
    const yesCls = lbl.human_agreed === true ? 'active-yes' : '';
    const noCls = lbl.human_agreed === false ? 'active-no' : '';
    const displayLabel = lbl.label_en || lbl.key;
    return `<div class="rubric-row">
      <div class="rubric-label-name">${esc(displayLabel)}</div>
      <div class="rubric-prob">${esc(pText)}</div>
      <div class="rubric-bar-track"><div class="rubric-bar-fill ${barCls}" style="width:${Math.max(2, p)}%"></div></div>
      <div class="rubric-feedback-btns">
        <button type="button" class="fb-btn ${yesCls}" data-fb-label="${esc(lbl.key)}" data-fb-agreed="1" title="Agree with score" aria-label="Agree with ${esc(displayLabel)}">&#10003;</button>
        <button type="button" class="fb-btn ${noCls}" data-fb-label="${esc(lbl.key)}" data-fb-agreed="0" title="Disagree with score" aria-label="Disagree with ${esc(displayLabel)}">&#10005;</button>
      </div>
    </div>`;
  }).join('');

  pane.innerHTML = `<div class="triage-detail-scroll">
      <div class="eval-top-header">
        <div class="eval-rec-wrap">
          <span class="cell-sub">AI recommendation</span>
          ${badge(actText, actCls)}
          ${badge(cm.status || 'needs_reply', cm.status === 'replied' ? 'b-ok' : 'b-dim')}
        </div>
        <div>
          <span class="cell-sub">Overall score </span>
          <span class="eval-score-big">${esc(ev.overall_score)}<small>/100</small></span>
        </div>
      </div>

      <div class="threshold-bar-wrap">
        <div class="threshold-track">
          <div class="threshold-fill" style="width:${scorePct}%"></div>
          <div class="threshold-tick" style="left:${thresholdPct}%"></div>
        </div>
        <div class="threshold-labels">
          <span>0</span>
          <span class="threshold-marker-label" style="left:${thresholdPct}%">Auto-suggest threshold ${thresholdPct}</span>
          <span>100</span>
        </div>
      </div>

      <div class="comment-context-box">
        <div class="comment-context-head">
          <span><b>${esc(cm.author_name)}</b> · ${esc(cm.author_meta || 'Audience member')} · on <b>${esc(cm.channel_name)}</b> (<code>${esc(cm.adapter)}</code>)</span>
          <button type="button" class="btn btn-sm" id="re-eval-btn">Re-evaluate</button>
        </div>
        <div class="comment-context-text">"${esc(cm.text)}"</div>
        <div class="cell-sub">Post context: ${esc(cm.post_caption || 'N/A')}</div>
      </div>

      <div>
        <div class="cell-main">${esc(ev.tier_label || 'Rubric assessment')}</div>
        <ul class="reasoning-bullets">
          ${(ev.reasoning_bullets || []).map(b => `<li>${esc(b)}</li>`).join('')}
        </ul>
        <div class="cell-sub">Confidence ${esc(ev.confidence)}% · Data: ${esc(ev.data_quality)} · Code-first prompt-injection isolation</div>
      </div>

      <div class="rubric-section">
        <div class="rubric-head">
          <span>Rubric dimension</span>
          <span style="text-align:right">Prob.</span>
          <span>Probability distribution</span>
          <span style="text-align:right">Calibrate</span>
        </div>
        ${rubricRows}
      </div>

      <div class="consultation-studio">
        <div class="strategy-card">
          <div><b>Consultation strategy:</b> ${esc(strat.objective || 'Address inquiry clearly and invite follow-up.')}</div>
          <div class="cell-sub"><b>Tone:</b> ${esc(strat.tone || 'Warm & professional')} · <b>Next step CTA:</b> ${esc(strat.next_step_cta || 'Confirm details in direct message')}</div>
        </div>
        <div class="draft-editors-grid">
          <label class="field"><span class="field-label">Public comment reply draft</span>
            <textarea id="draft-public-text" placeholder="Draft public comment reply...">${esc(pubDraft.text)}</textarea>
          </label>
          <label class="field"><span class="field-label">Private DM consultation draft</span>
            <textarea id="draft-private-text" placeholder="Draft private message follow-up...">${esc(privDraft.text)}</textarea>
          </label>
        </div>
      </div>
    </div>

    <div class="triage-bottom-bar">
      <div class="quick-decision-bar">
        <button type="button" class="decision-btn${cm.human_decision === 1 ? ' on' : ''}" data-decision="1"><span>Want to consult</span><span class="kbd-badge">1</span></button>
        <button type="button" class="decision-btn${cm.human_decision === 2 ? ' on' : ''}" data-decision="2"><span>Hold for review</span><span class="kbd-badge">2</span></button>
        <button type="button" class="decision-btn${cm.human_decision === 3 ? ' on' : ''}" data-decision="3"><span>Skip / ignore</span><span class="kbd-badge">3</span></button>
      </div>
      <div class="bottom-cta-row">
        <button type="button" class="btn btn-danger" id="btn-reject-hide">Reject / hide</button>
        <button type="button" class="btn" id="btn-capture-evidence">Seal forensic evidence</button>
        <button type="button" class="btn btn-primary" id="btn-approve-consult">Approve consultation drafts</button>
      </div>
    </div>`;

  $('#re-eval-btn')?.addEventListener('click', evBtn => busy(evBtn.currentTarget, async () => {
    await api(`/api/admin/comments/${cm.id}/evaluate`, { method: 'POST', body: {} });
    toast('Rubric evaluation refreshed', 'ok');
    await loadInbox();
  }));

  pane.querySelectorAll('[data-fb-label]').forEach(btn => {
    btn.onclick = () => busy(btn, async () => {
      await api(`/api/admin/comments/${cm.id}/feedback`, {
        method: 'POST',
        body: { label: btn.dataset.fbLabel, agreed: btn.dataset.fbAgreed === '1' }
      });
      toast(`Saved calibration for ${btn.dataset.fbLabel}`, 'ok');
      await loadInbox();
    });
  });

  pane.querySelectorAll('[data-decision]').forEach(btn => {
    btn.onclick = () => busy(btn, async () => {
      const dec = Number(btn.dataset.decision);
      await api(`/api/admin/comments/${cm.id}/feedback`, {
        method: 'POST',
        body: { label: '_decision', agreed: dec === 1, human_decision: dec }
      });
      toast(`Recorded operator decision #${dec}`, 'ok');
      await loadInbox();
    });
  });

  $('#btn-reject-hide')?.addEventListener('click', async evBtn => {
    const ok = await confirmModal({
      title: 'Hide & archive spam comment?',
      body: `Mark comment by <b>${esc(cm.author_name)}</b> as hidden spam/clone? This action is recorded in the hash-chained audit log.`,
      confirm: 'Hide comment',
      danger: true
    });
    if (!ok) return;
    await busy(evBtn.currentTarget, async () => {
      await api(`/api/admin/comments/${cm.id}/state`, {
        method: 'POST',
        body: { status: 'hidden', bucket: 'spam_clone' }
      });
      toast('Comment marked hidden', 'ok');
      await loadInbox();
    });
  });

  $('#btn-capture-evidence')?.addEventListener('click', evBtn => busy(evBtn.currentTarget, async () => {
    const res = await api('/api/admin/evidence/capture', {
      method: 'POST',
      body: {
        comment_id: cm.id,
        target_url: cm.post_permalink || `https://www.facebook.com/comment/${cm.external_id}`,
        title: `Forensic Case · ${cm.author_name} (UID ${cm.author_external_id || 'unknown'})`
      }
    });
    toast(`Sealed forensic case #${res.case_id} (${res.manifest_sha256.slice(0, 12)}...)`, 'ok');
    await refreshOverview();
  }));

  $('#btn-approve-consult')?.addEventListener('click', evBtn => busy(evBtn.currentTarget, async () => {
    const pubText = $('#draft-public-text').value.trim();
    const privText = $('#draft-private-text').value.trim();
    if (!pubText && !privText) {
      toast('Enter a public reply or private DM draft before approving', 'err');
      return;
    }
    if (pubText) {
      await api(`/api/admin/comments/${cm.id}/drafts`, {
        method: 'POST',
        body: { text: pubText, kind: 'public', status: 'approved', strategy_summary: strat.objective || '' }
      });
    }
    if (privText) {
      await api(`/api/admin/comments/${cm.id}/drafts`, {
        method: 'POST',
        body: { text: privText, kind: 'private_dm', status: 'approved', strategy_summary: strat.objective || '' }
      });
    }
    toast('Consultation drafts approved and logged', 'ok');
    await loadInbox();
  }));
}

/* ==========================================================================
   3. CONVERSATIONS, LEADS & HANDOFFS (#conversations)
   ========================================================================== */
async function loadConversations() {
  const host = $('#body-conversations');
  try {
    const q = state.shopId ? `?shop_id=${encodeURIComponent(state.shopId)}` : '';
    const [convRes, leadsRes, handoffsRes] = await Promise.all([
      api(`/api/admin/conversations${q}`),
      api(`/api/admin/leads${q}`),
      api(`/api/admin/handoffs${q}`)
    ]);
    state.conversations = convRes.conversations || [];
    state.leads = leadsRes.leads || [];
    state.handoffs = handoffsRes.handoffs || [];
    if (!state.selectedConversationId && state.conversations.length) {
      state.selectedConversationId = state.conversations[0].id;
    } else if (state.selectedConversationId && !state.conversations.some(c => c.id === state.selectedConversationId)) {
      state.selectedConversationId = state.conversations[0]?.id || null;
    }
    if (state.selectedConversationId) {
      const mRes = await api(`/api/admin/conversations/${state.selectedConversationId}/messages`);
      state.conversationMessages = mRes.messages || [];
    } else {
      state.conversationMessages = [];
    }
    renderConversationsPage();
  } catch (err) {
    host.innerHTML = paintTableError(1, err);
  }
}

function renderConversationsPage() {
  const host = $('#body-conversations');
  const convRows = state.conversations.map(cv => `<tr data-conv-id="${cv.id}" style="cursor:pointer${cv.id === state.selectedConversationId ? ';background:var(--primary-light)' : ''}">
    <td><div class="cell-main">${esc(cv.participant_name)}</div><div class="cell-sub">${esc(cv.channel_name)}</div></td>
    <td>${badge(cv.status, cv.status === 'replied' ? 'b-ok' : (cv.status === 'open' ? 'b-warn' : 'b-dim'))}</td>
    <td class="num">${num(cv.unread_count)}</td>
    <td>${esc((cv.last_message_preview || '').slice(0, 70))}</td>
    <td class="cell-sub">${when(cv.updated_at)}</td>
  </tr>`);

  const activeConv = state.conversations.find(c => c.id === state.selectedConversationId);
  const threadHtml = activeConv
    ? `<div class="msg-thread">${state.conversationMessages.length ? state.conversationMessages.map(m => `<div class="msg-bubble ${m.direction === 'outbound' ? 'outbound' : ''}">
          <div class="msg-meta"><b>${esc(m.sender_name || m.direction)}</b> · ${when(m.created_at)} · ${esc(m.status)}</div>
          <div>${esc(m.text)}</div>
        </div>`).join('') : '<div class="empty">No messages recorded in this thread yet.</div>'}</div>
      <form id="conv-reply-form" style="margin-top:12px">
        <label class="field"><span class="field-label">Guarded outbound reply (${esc(activeConv.reply_policy || 'draft_only')})</span>
          <textarea name="text" placeholder="Write consultation response..." required></textarea>
        </label>
        <button type="submit" class="btn btn-primary">Save / send reply</button>
      </form>`
    : '<div class="empty">Select a conversation thread to inspect messages and draft replies.</div>';

  const leadRows = state.leads.map(l => `<tr>
    <td><div class="cell-main">${esc(l.customer_name)}</div><div class="cell-sub">${esc(l.contact_handle || l.phone || l.email || '-')}</div></td>
    <td>${esc(l.source)}</td>
    <td class="num">${Number(l.intent_score || 0).toFixed(0)}</td>
    <td>${badge(l.status, l.status === 'converted' ? 'b-ok' : 'b-acc')}</td>
  </tr>`);

  const handoffRows = state.handoffs.map(h => `<tr>
    <td>${badge(h.priority, h.priority === 'urgent' || h.priority === 'high' ? 'b-err' : 'b-dim')}</td>
    <td><div class="cell-main">${esc(h.summary)}</div><div class="cell-sub">Assignee: ${esc(h.assignee)}</div></td>
    <td>${badge(h.status, h.status === 'resolved' ? 'b-ok' : 'b-warn')}</td>
  </tr>`);

  host.innerHTML = `<div class="grid-wide">
    <div class="stack-sm" style="gap:16px">
      ${card('Direct message conversations', table(['Participant', 'Status', '#Unread', 'Latest preview', 'Updated'], convRows, 'No DM conversations ingested yet.'), { flush: true })}
      ${card(activeConv ? `Thread · ${esc(activeConv.participant_name)}` : 'Conversation thread', threadHtml)}
    </div>
    <div class="stack-sm" style="gap:16px">
      ${card('Qualified customer leads', `${table(['Customer', 'Source', '#Intent', 'Status'], leadRows, 'No leads captured yet.')}
        <hr class="section-sep">
        <form id="lead-form" class="field-grid">
          <label class="field"><span class="field-label">Customer name</span><input type="text" name="customer_name" placeholder="Customer full name" required></label>
          <label class="field"><span class="field-label">Contact / phone</span><input type="text" name="phone" placeholder="+33 or @handle"></label>
          <div class="field" style="grid-column:1/-1"><button type="submit" class="btn btn-sm btn-primary">Record lead</button></div>
        </form>`, { sub: 'Synced with care__lead_upsert MCP tool.' })}
      ${card('Operator handoff tickets', `${table(['Priority', 'Summary', 'Status'], handoffRows, 'No open handoff escalations.')}
        <hr class="section-sep">
        <form id="handoff-form">
          <div class="field-grid">
            <label class="field"><span class="field-label">Priority</span>
              <select name="priority"><option value="normal">Normal</option><option value="high">High</option><option value="urgent">Urgent</option><option value="low">Low</option></select>
            </label>
            <label class="field"><span class="field-label">Assignee</span><input type="text" name="assignee" value="care-team" required></label>
          </div>
          <label class="field"><span class="field-label">Escalation summary</span><input type="text" name="summary" placeholder="Order verification or VIP callback needed" required></label>
          <button type="submit" class="btn btn-sm btn-primary">Create handoff</button>
        </form>`, { sub: 'Synced with care__ticket_handoff MCP tool.' })}
    </div>
  </div>`;

  enhanceAllSelects(host);
  host.querySelectorAll('[data-conv-id]').forEach(row => {
    row.onclick = async () => {
      state.selectedConversationId = Number(row.dataset.convId);
      const mRes = await api(`/api/admin/conversations/${state.selectedConversationId}/messages`);
      state.conversationMessages = mRes.messages || [];
      renderConversationsPage();
    };
  });
  $('#conv-reply-form')?.addEventListener('submit', ev => {
    ev.preventDefault();
    const fd = new FormData(ev.currentTarget);
    busy(ev.currentTarget.querySelector('button'), async () => {
      const r = await api(`/api/admin/conversations/${state.selectedConversationId}/messages`, {
        method: 'POST',
        body: { text: fd.get('text') }
      });
      toast(r.status === 'sent' ? 'Outbound reply sent' : 'Reply saved as guarded draft', 'ok');
      await loadConversations();
    });
  });
  $('#lead-form')?.addEventListener('submit', ev => {
    ev.preventDefault();
    const fd = new FormData(ev.currentTarget);
    busy(ev.currentTarget.querySelector('button'), async () => {
      await api('/api/admin/leads', {
        method: 'POST',
        body: { customer_name: fd.get('customer_name'), phone: fd.get('phone'), shop_id: state.shopId }
      });
      toast('Lead recorded', 'ok');
      await loadConversations();
      await refreshOverview();
    });
  });
  $('#handoff-form')?.addEventListener('submit', ev => {
    ev.preventDefault();
    const fd = new FormData(ev.currentTarget);
    busy(ev.currentTarget.querySelector('button'), async () => {
      await api('/api/admin/handoffs', {
        method: 'POST',
        body: { priority: fd.get('priority'), assignee: fd.get('assignee'), summary: fd.get('summary'), shop_id: state.shopId }
      });
      toast('Handoff ticket created', 'ok');
      await loadConversations();
      await refreshOverview();
    });
  });
}

/* ==========================================================================
   4. POSTS, SNAPSHOT SERIES & ARCHIVES (#posts)
   ========================================================================== */
async function loadPosts() {
  const host = $('#body-posts');
  try {
    const q = state.shopId ? `?shop_id=${encodeURIComponent(state.shopId)}` : '';
    const data = await api(`/api/admin/posts${q}`);
    state.posts = data.posts || [];
    $('#count-posts') && ($('#count-posts').textContent = state.posts.length ? String(state.posts.length) : '');
    if (!state.selectedPostId && state.posts.length) state.selectedPostId = state.posts[0].id;
    if (state.selectedPostId) {
      const det = await api(`/api/admin/posts/${state.selectedPostId}`).catch(() => null);
      state.postDetail = det?.post || null;
    } else {
      state.postDetail = null;
    }
    renderPostsPage();
  } catch (err) {
    host.innerHTML = paintTableError(1, err);
  }
}

function renderPostsPage() {
  const host = $('#body-posts');
  const rows = state.posts.map(p => {
    const snap = p.latest_snapshot || {};
    return `<tr data-post-row="${p.id}" style="cursor:pointer${p.id === state.selectedPostId ? ';background:var(--primary-light)' : ''}">
      <td><div class="cell-main">${esc(p.channel_name)}</div><div class="cell-sub">${esc(p.provider)}</div></td>
      <td>${badge(p.kind || 'post', 'b-dim')}</td>
      <td>${esc((p.caption || '').slice(0, 76))}${(p.caption || '').length > 76 ? '...' : ''}</td>
      <td class="num">${num(snap.reactions || 0)}</td>
      <td class="num">${num(snap.comments_count || 0)}</td>
      <td class="num">${num((p.archives || []).length)}</td>
      <td><div class="row-actions"><button type="button" class="btn btn-sm" data-archive-post="${p.id}">Archive</button></div></td>
    </tr>`;
  });

  const p = state.postDetail;
  let detailHtml = '<div class="empty">Select a post row to inspect its daily impressions trend and archived SHA-256 media.</div>';
  if (p) {
    const snaps = p.snapshots || [];
    const maxImp = Math.max(100, ...snaps.map(s => s.impressions || 0));
    const pts = snaps.map((s, idx) => {
      const x = 24 + (idx * 252) / Math.max(1, snaps.length - 1);
      const y = 94 - ((s.impressions || 0) / maxImp) * 74;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
    detailHtml = `<div class="stack-sm">
      <div><span class="cell-main">${esc(p.channel_name)}</span> · <a href="${esc(p.permalink || '#')}" target="_blank" rel="noopener noreferrer">${esc(p.external_id)} &#8599;</a></div>
      <div style="font-size:13.5px">${esc(p.caption || 'No caption')}</div>
      <div style="background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px">
        <div class="cell-sub">Impressions snapshot trend</div>
        ${snaps.length ? `<svg viewBox="0 0 300 108" style="width:100%;height:108px"><polyline fill="none" stroke="var(--primary)" stroke-width="2.5" points="${pts}"/></svg>
          <div class="cell-sub" style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px">
            ${snaps.map(s => `<span>${esc(s.snapshot_date.slice(5))}: <b>${num(s.impressions)}</b></span>`).join('')}
          </div>` : '<div class="empty">No metric snapshots recorded yet.</div>'}
      </div>
      <div>
        <div class="field-label">Archived media & screenshots (${(p.archives || []).length})</div>
        ${(p.archives || []).length
          ? `<div class="stack-sm">${p.archives.map(a => `<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap"><span><code>${esc(a.kind)}</code> · <span class="cell-sub">${esc(a.path)}</span></span>${copyChip(a.sha256 || '')}</div>`).join('')}</div>`
          : '<div class="cell-sub">Click Archive to enqueue worker media and screenshot preservation.</div>'}
      </div>
    </div>`;
  }

  host.innerHTML = `<div class="grid-wide">
    ${card('Ingested posts & reels', table(['Channel', 'Kind', 'Caption', '#Reactions', '#Comments', '#Archives', 'Actions'], rows, 'No posts ingested yet.'), { flush: true })}
    ${card('Snapshot & archive inspector', detailHtml)}
  </div>`;

  wireCopyButtons(host);
  host.querySelectorAll('[data-post-row]').forEach(row => {
    row.onclick = async ev => {
      if (ev.target.closest('[data-archive-post]')) return;
      state.selectedPostId = Number(row.dataset.postRow);
      const det = await api(`/api/admin/posts/${state.selectedPostId}`).catch(() => null);
      state.postDetail = det?.post || null;
      renderPostsPage();
    };
  });
  host.querySelectorAll('[data-archive-post]').forEach(btn => {
    btn.onclick = ev => {
      ev.stopPropagation();
      const pid = Number(btn.dataset.archivePost);
      busy(btn, async () => {
        await api(`/api/admin/posts/${pid}/archive`, { method: 'POST' });
        toast(`Archived media & screenshot for post #${pid}`, 'ok');
        state.selectedPostId = pid;
        await loadPosts();
      });
    };
  });
}

/* ==========================================================================
   5. FORENSIC EVIDENCE VAULT (#evidence)
   ========================================================================== */
async function loadEvidence() {
  const host = $('#body-evidence');
  try {
    const data = await api('/api/admin/evidence');
    state.evidenceCases = data.cases || [];
    renderEvidencePage();
  } catch (err) {
    host.innerHTML = paintTableError(1, err);
  }
}

function renderEvidencePage() {
  const host = $('#body-evidence');
  const formHtml = `<form id="evidence-form">
    <label class="field"><span class="field-label">Case title</span>
      <input type="text" name="title" placeholder="Defamatory impersonation post against brand" required>
    </label>
    <label class="field"><span class="field-label">Target URL (post, comment or profile)</span>
      <input type="url" name="target_url" placeholder="https://www.facebook.com/permalink.php?story_fbid=..." required>
    </label>
    <label class="field"><span class="field-label">Linked comment ID (optional)</span>
      <input type="number" name="comment_id" placeholder="e.g. 6">
    </label>
    <button type="submit" class="btn btn-primary">Seal 5-layer forensic bundle</button>
  </form>`;

  const stdHtml = `<dl class="kv">
    <dt>Layer 1 · Raw payload</dt><dd>Exact Graph/Web JSON with UTC server headers and immutable IDs.</dd>
    <dt>Layer 2 · Visual proof</dt><dd>Full-page PNG render + serialized DOM HTML snapshot.</dd>
    <dt>Layer 3 · Network HAR</dt><dd>TLS response metadata proving server-originated content.</dd>
    <dt>Layer 4 · Actor graph</dt><dd>Numeric UID, handle history and public profile snapshot.</dd>
    <dt>Layer 5 · Custody seal</dt><dd><code>manifest.json</code> SHA-256 digest + <code>+6h / +24h / +72h</code> deletion watchdog.</dd>
  </dl>`;

  const rows = state.evidenceCases.map(c => {
    const item = (c.items || [])[0] || {};
    return `<tr>
      <td class="mono">#${c.id}</td>
      <td><div class="cell-main">${esc(c.title)}</div><div class="cell-sub">${esc((item.captured_text || '').slice(0, 88))}</div></td>
      <td><div class="cell-main">${esc(c.subject_name || 'Unknown')}</div><div class="cell-sub mono">UID: ${esc(c.subject_uid || '-')}</div></td>
      <td><a href="${esc(item.target_url || '#')}" target="_blank" rel="noopener noreferrer">${esc((item.target_url || '').slice(0, 40))}... &#8599;</a></td>
      <td>${copyChip(c.bundle_sha256 || '')}</td>
      <td>${badge(`${item.alive_status || 'alive'} (+6h/+24h/+72h)`, item.alive_status === 'deleted' ? 'b-err' : 'b-ok')}</td>
      <td class="mono">${esc(c.bundle_zip_path || '-')}</td>
    </tr>`;
  });

  host.innerHTML = `<div class="grid-2">
      ${card('Capture forensic evidence', formHtml, { sub: 'Preserve defamatory or abusive content before the author edits or deletes it.' })}
      ${card('Five-layer preservation standard', stdHtml, { sub: 'Append-only WORM storage suitable for platform abuse reports and legal intake.' })}
    </div>
    ${card('Sealed evidence cases', table(['Case', 'Title & excerpt', 'Subject', 'Target URL', 'SHA-256 manifest', 'Watchdog', 'Bundle path'], rows, 'No forensic evidence cases sealed yet.'), { flush: true })}`;

  wireCopyButtons(host);
  $('#evidence-form')?.addEventListener('submit', ev => {
    ev.preventDefault();
    const fd = new FormData(ev.currentTarget);
    const cmId = fd.get('comment_id');
    busy(ev.currentTarget.querySelector('button'), async () => {
      const res = await api('/api/admin/evidence/capture', {
        method: 'POST',
        body: {
          title: fd.get('title'),
          target_url: fd.get('target_url'),
          comment_id: cmId ? Number(cmId) : null
        }
      });
      toast(`Sealed forensic case #${res.case_id}`, 'ok');
      await loadEvidence();
      await refreshOverview();
    });
  });
}

/* ==========================================================================
   6. MULTI-ACCOUNT FLEET (#fleet)
   ========================================================================== */
async function loadFleet() {
  const host = $('#body-fleet');
  try {
    state.fleet = await api('/api/admin/fleet');
    renderFleetPage();
  } catch (err) {
    host.innerHTML = paintTableError(1, err);
  }
}

function renderFleetPage() {
  const host = $('#body-fleet');
  const formHtml = `<form id="fleet-form">
    <div class="field-grid">
      <label class="field"><span class="field-label">Runtime label</span><input type="text" name="label" placeholder="FB Care Consultant #03" required></label>
      <label class="field"><span class="field-label">Platform</span>
        <select name="platform"><option value="facebook">Facebook</option><option value="instagram">Instagram</option><option value="tiktok">TikTok</option><option value="youtube">YouTube</option></select>
      </label>
      <label class="field"><span class="field-label">Account role</span>
        <select name="account_role">
          <option value="care_consultant">Care consultant (human-assisted)</option>
          <option value="owned_page">Owned page (Graph API)</option>
          <option value="evidence_scout">Evidence scout (read-only)</option>
          <option value="personal_main">Personal main (0 auto-writes)</option>
        </select>
      </label>
      <label class="field"><span class="field-label">Runtime adapter</span>
        <select name="adapter">
          <option value="veilbrowser">VeilBrowser (isolated Chromium)</option>
          <option value="meta_api">Official Meta Graph API</option>
          <option value="orbine_mobile">Orbine ARM64 mobile container</option>
          <option value="scrapling_public">Scrapling public fetch</option>
        </select>
      </label>
      <label class="field"><span class="field-label">Profile / container ID</span><input type="text" name="runtime_profile_id" placeholder="vb_prof_fb_03" required></label>
      <label class="field"><span class="field-label">Sticky residential exit IP</span><input type="text" name="expected_exit_ip" placeholder="82.64.110.25"></label>
    </div>
    <button type="submit" class="btn btn-primary">Save runtime profile</button>
  </form>`;

  const guardHtml = `<dl class="kv">
    <dt>Personal main safety</dt><dd><code>personal_main</code> enforces <code>daily_write_budget = 0</code> in schema and backend.</dd>
    <dt>Sticky exit IP check</dt><dd>Worker verifies proxy exit IP & ASN before opening any social URL.</dd>
    <dt>Single-worker lease</dt><dd>SQLite <code>runtime_leases</code> prevents concurrent multi-tab collisions.</dd>
    <dt>Circuit breaker</dt><dd>Any login wall or CAPTCHA halts automation and alerts the operator.</dd>
  </dl>`;

  const rows = (state.fleet.runtimes || []).map(r => `<tr>
    <td class="mono">#${r.id}</td>
    <td class="cell-main">${esc(r.label)}</td>
    <td>${esc(r.platform)}</td>
    <td>${badge(r.account_role, r.account_role === 'personal_main' ? 'b-warn' : 'b-dim')}</td>
    <td class="mono">${esc(r.adapter)}</td>
    <td class="mono">${esc(r.runtime_profile_id)}</td>
    <td class="mono">${esc(r.expected_exit_ip || 'Direct')} (${esc(r.expected_country)})</td>
    <td>${badge(r.health_status, r.health_status === 'healthy' ? 'b-ok' : 'b-err')}</td>
    <td class="num mono">${r.reads_today}/${r.daily_read_budget} R · ${r.writes_today}/${r.daily_write_budget} W</td>
  </tr>`);

  host.innerHTML = `<div class="grid-2">
      ${card('Register account runtime', formHtml, { sub: 'Bind isolated profiles across Official API, VeilBrowser and Orbine.' })}
      ${card('Antidetect & safety guardrails', guardHtml, { sub: 'Zero CAPTCHA bypass — human operator completes any challenge.' })}
    </div>
    ${card('Active runtime pool', table(['ID', 'Label', 'Platform', 'Role', 'Adapter', 'Profile ID', 'Exit IP', 'Health', '#Daily budget'], rows, 'No account runtimes registered yet.'), { flush: true })}`;

  enhanceAllSelects(host);
  $('#fleet-form')?.addEventListener('submit', ev => {
    ev.preventDefault();
    const fd = new FormData(ev.currentTarget);
    busy(ev.currentTarget.querySelector('button'), async () => {
      await api('/api/admin/fleet', {
        method: 'POST',
        body: {
          label: fd.get('label'),
          platform: fd.get('platform'),
          account_role: fd.get('account_role'),
          adapter: fd.get('adapter'),
          runtime_profile_id: fd.get('runtime_profile_id'),
          expected_exit_ip: fd.get('expected_exit_ip')
        }
      });
      toast('Runtime profile saved', 'ok');
      await loadFleet();
      await refreshOverview();
    });
  });
}

/* ==========================================================================
   7. CHANNELS & OAUTH (#channels)
   ========================================================================== */
function renderChannelsPage() {
  const host = $('#body-channels');
  const o = state.overview;
  if (!o) {
    host.innerHTML = '<div class="skel" style="width:50%"></div>';
    return;
  }
  const hub = o.agent_hub || {};
  const br = o.bridge || {};
  const defaultShop = o.shops.find(s => String(s.id) === String(state.shopId))?.name || o.shops[0]?.name || 'LuxeClaw';

  const sharedHtml = `<p class="hint">Connect once via LNC Agent Hub (or LNC Ads LAN bridge fallback) so credentials are shared across LNC Agent Hub, LNC Ads and LNC Care while cached locally in LNC Care's encrypted vault.</p>
    <dl class="kv" style="margin-bottom:14px">
      <dt>Active vault mode</dt><dd><code>${esc(hub.mode || 'standalone_local_vault')}</code></dd>
      <dt>LNC Agent Hub</dt><dd><code>${esc(hub.url || 'not set')}</code> (${hub.reachable ? 'reachable' : 'offline'})</dd>
      <dt>LNC Ads LAN bridge</dt><dd><code>${esc(br.ads_internal_url || 'not set')}</code> (${hub.bridge_fallback_ready ? 'ready' : 'standby'})</dd>
    </dl>
    <form id="shared-oauth-form" class="inline-form">
      <select name="provider" aria-label="Provider"><option value="meta">Meta (FB Page &amp; Instagram)</option><option value="tiktok">TikTok Business</option><option value="youtube">YouTube</option></select>
      <input type="text" name="shop" value="${esc(defaultShop)}" placeholder="Shop name (e.g. LuxeClaw)" required>
      <input type="text" name="label" placeholder="Connection label (optional)">
      <button type="submit" class="btn btn-primary">Connect shared account &#8599;</button>
    </form>`;

  const appCfg = o.integrations?.apps?.[state.selectedAppProvider] || {};
  const appFormHtml = `<form id="app-form" data-revision="${appCfg.revision || 0}">
    <label class="field"><span class="field-label">Provider</span>
      <select name="provider" id="app-provider-select">
        ${Object.entries(PROVIDERS).map(([k, v]) => `<option value="${k}"${state.selectedAppProvider === k ? ' selected' : ''}>${esc(v)}</option>`).join('')}
      </select>
    </label>
    <label class="field"><span class="field-label">Client / App ID</span><input type="text" name="client_id" value="${esc(appCfg.client_id || '')}" required></label>
    <label class="field"><span class="field-label">Client / App secret</span><input type="password" name="client_secret" value="${appCfg.configured ? '********' : ''}" placeholder="Encrypted in Vault" required></label>
    <label class="field"><span class="field-label">Webhook verify token</span><input type="text" name="webhook_verify_token" value="${esc(appCfg.webhook_verify_token || '')}" placeholder="Meta hub.verify_token"></label>
    <label class="check"><input type="checkbox" name="confirm_replace"><span>Confirm replacing existing stored secret</span></label>
    <button type="submit" class="btn btn-primary">Save app credentials</button>
  </form>`;

  const connRows = (o.integrations?.connections || []).map(c => {
    const [stTxt, stCls] = CONN_STATES[c.state] || [c.state, 'b-dim'];
    return `<tr>
      <td class="mono">#${c.id}</td>
      <td>${provBadge(c.provider)}</td>
      <td class="cell-main">${esc(c.label)}</td>
      <td>${badge(stTxt, stCls)}</td>
      <td><div class="row-actions">
        <button type="button" class="btn btn-sm" data-conn-act="authorize" data-id="${c.id}">Authorize</button>
        <button type="button" class="btn btn-sm" data-conn-act="discover" data-id="${c.id}">Discover</button>
        <button type="button" class="btn btn-sm btn-danger" data-conn-act="disconnect" data-id="${c.id}" data-label="${esc(c.label)}">Disconnect</button>
      </div></td>
    </tr>`;
  });

  const connCardHtml = `<form id="connection-form" class="inline-form" style="margin-bottom:14px">
      <select name="provider" aria-label="Connection provider"><option value="meta">Meta</option><option value="tiktok">TikTok</option><option value="youtube">YouTube</option></select>
      <input type="text" name="label" placeholder="Connection label (e.g. Brand Meta Business)" required>
      <button type="submit" class="btn btn-primary">Add connection</button>
    </form>
    ${table(['ID', 'Provider', 'Label', 'State', 'Actions'], connRows, 'No OAuth connections registered yet.')}`;

  const allChannels = [...(o.channels || [])];
  Object.entries(state.discovered).forEach(([connId, list]) => {
    (list || []).forEach(d => {
      if (!allChannels.some(r => r.external_id === d.external_id)) {
        allChannels.push({ ...d, connection_id: Number(connId), approved: false, reply_policy: 'draft_only', auto_suggest_threshold: 80 });
      }
    });
  });

  const shopOpts = (o.shops || []).map(s => `<option value="${s.id}">${esc(s.name)}</option>`).join('');
  const chRows = allChannels.map(ch => `<tr>
    <td><div class="cell-main">${esc(ch.name)}</div><div class="cell-sub">${esc(ch.handle || ch.external_id)}</div></td>
    <td>${provBadge(ch.provider || 'meta')}</td>
    <td>${esc(ch.kind || 'page')}</td>
    <td class="mono">${esc(ch.adapter || 'meta_api')}</td>
    <td><code>${esc(ch.reply_policy || 'draft_only')}</code> · <span class="cell-sub">${ch.auto_suggest_threshold || 80}/100</span></td>
    <td>${ch.approved ? badge('Approved', 'b-ok') : badge('Pending approval', 'b-warn')}</td>
    <td><div class="row-actions">
      ${ch.connection_id && o.shops.length && !ch.approved
        ? `<select data-shop-for="${esc(ch.external_id)}" aria-label="Target shop">${shopOpts}</select>
           <button type="button" class="btn btn-sm btn-primary" data-approve="${esc(ch.external_id)}" data-conn="${ch.connection_id}">Approve</button>`
        : ''}
      ${ch.id && ch.approved ? `<button type="button" class="btn btn-sm" data-policy-channel="${ch.id}" data-policy="${esc(ch.reply_policy || 'draft_only')}" data-threshold="${ch.auto_suggest_threshold || 80}" data-name="${esc(ch.name)}">Policy</button>` : ''}
      ${ch.id && ch.adapter === 'meta_api' && ch.approved ? `<button type="button" class="btn btn-sm" data-sync-channel="${ch.id}">Sync now</button>` : ''}
    </div></td>
  </tr>`);

  host.innerHTML = `${card('Shared platform vault & OAuth broker', sharedHtml)}
    <div class="grid-2">
      ${card('Local OAuth app credentials', appFormHtml, { sub: 'Optional standalone OAuth client credentials encrypted in Vault.' })}
      ${card('Provider connections', connCardHtml, { sub: 'Authorize, discover owned pages and manage token lifecycle.' })}
    </div>
    ${card('Discovered & approved channels', table(['Channel', 'Provider', 'Kind', 'Adapter', 'Policy & threshold', 'Status', 'Actions'], chRows, 'No channels discovered yet.'), { flush: true })}`;

  enhanceAllSelects(host);

  $('#app-provider-select')?.addEventListener('change', ev => {
    state.selectedAppProvider = ev.target.value;
    renderChannelsPage();
  });

  $('#shared-oauth-form')?.addEventListener('submit', ev => {
    ev.preventDefault();
    const fd = new FormData(ev.currentTarget);
    busy(ev.currentTarget.querySelector('button'), async () => {
      const res = await api('/api/admin/oauth/shared/start', {
        method: 'POST',
        body: { provider: fd.get('provider'), shop: fd.get('shop'), label: fd.get('label') }
      });
      if (res.authorization_url) location.assign(res.authorization_url);
      else toast('Shared OAuth flow initiated', 'ok');
    });
  });

  $('#app-form')?.addEventListener('submit', ev => {
    ev.preventDefault();
    const fd = new FormData(ev.currentTarget);
    const provider = fd.get('provider');
    busy(ev.currentTarget.querySelector('button'), async () => {
      await api(`/api/admin/integrations/${provider}`, {
        method: 'POST',
        body: {
          client_id: fd.get('client_id'),
          client_secret: fd.get('client_secret'),
          webhook_verify_token: fd.get('webhook_verify_token'),
          confirm_replace: fd.get('confirm_replace') === 'on',
          revision: Number(ev.currentTarget.dataset.revision || 0)
        }
      });
      toast(`Saved ${PROVIDERS[provider] || provider} credentials`, 'ok');
      await refreshOverview();
    });
  });

  $('#connection-form')?.addEventListener('submit', ev => {
    ev.preventDefault();
    const fd = new FormData(ev.currentTarget);
    busy(ev.currentTarget.querySelector('button'), async () => {
      await api('/api/admin/connections', { method: 'POST', body: { provider: fd.get('provider'), label: fd.get('label') } });
      toast('Connection added', 'ok');
      await refreshOverview();
    });
  });

  host.querySelectorAll('[data-conn-act]').forEach(btn => {
    btn.onclick = async () => {
      const id = Number(btn.dataset.id);
      const act = btn.dataset.connAct;
      if (act === 'disconnect') {
        const ok = await confirmModal({
          title: 'Disconnect provider account?',
          body: `Revoke local credentials for <b>${esc(btn.dataset.label || `#${id}`)}</b>? Existing ingested history remains intact.`,
          confirm: 'Disconnect',
          danger: true
        });
        if (!ok) return;
      }
      await busy(btn, async () => {
        if (act === 'authorize') {
          const r = await api(`/api/admin/connections/${id}/authorize`, { method: 'POST' });
          if (r.authorization_url) location.assign(r.authorization_url);
          else toast('Authorization URL generated', 'ok');
        } else if (act === 'discover') {
          const r = await api(`/api/admin/connections/${id}/discover`, { method: 'POST' });
          state.discovered[id] = r.channels || [];
          toast(`Discovered ${(r.channels || []).length} channels`, 'ok');
        } else if (act === 'disconnect') {
          await api(`/api/admin/connections/${id}/disconnect`, { method: 'POST' });
          toast('Connection disconnected', 'ok');
        }
        await refreshOverview();
      });
    };
  });

  host.querySelectorAll('[data-approve]').forEach(btn => {
    btn.onclick = () => busy(btn, async () => {
      const ext = btn.dataset.approve;
      const connId = Number(btn.dataset.conn);
      const sel = host.querySelector(`[data-shop-for="${CSS.escape(ext)}"]`);
      await api(`/api/admin/connections/${connId}/channels/approve`, {
        method: 'POST',
        body: { external_id: ext, shop_id: Number(sel.value), reply_policy: 'draft_only' }
      });
      toast(`Approved channel ${ext}`, 'ok');
      await refreshOverview();
    });
  });

  host.querySelectorAll('[data-sync-channel]').forEach(btn => {
    btn.onclick = () => busy(btn, async () => {
      const r = await api(`/api/admin/channels/${Number(btn.dataset.syncChannel)}/sync`, { method: 'POST' });
      toast(`Synced ${r.posts} posts & ${r.comments} comments`, 'ok');
      await refreshOverview();
    });
  });

  host.querySelectorAll('[data-policy-channel]').forEach(btn => {
    btn.onclick = () => {
      const cid = Number(btn.dataset.policyChannel);
      const m = modal(`<h3>Channel reply policy · ${esc(btn.dataset.name)}</h3>
        <form id="channel-policy-modal-form" style="margin-top:12px">
          <label class="field"><span class="field-label">Reply policy</span>
            <select name="reply_policy">
              <option value="draft_only"${btn.dataset.policy === 'draft_only' ? ' selected' : ''}>Draft only (human approval required)</option>
              <option value="guarded_reply"${btn.dataset.policy === 'guarded_reply' ? ' selected' : ''}>Guarded reply (idempotent + audited)</option>
              <option value="rule_auto_reply"${btn.dataset.policy === 'rule_auto_reply' ? ' selected' : ''}>Rule auto-reply (explicit owner rule)</option>
            </select>
          </label>
          <label class="field"><span class="field-label">Auto-suggest score threshold (10-99)</span>
            <input type="number" name="auto_suggest_threshold" min="10" max="99" value="${esc(btn.dataset.threshold)}" required>
          </label>
          <div class="acts">
            <button type="button" class="btn" data-close>Cancel</button>
            <button type="submit" class="btn btn-primary">Save policy</button>
          </div>
        </form>`);
      m.root.querySelector('#channel-policy-modal-form').onsubmit = ev => {
        ev.preventDefault();
        const fd = new FormData(ev.currentTarget);
        busy(ev.currentTarget.querySelector('[type="submit"]'), async () => {
          await api(`/api/admin/channels/${cid}/policy`, {
            method: 'POST',
            body: { reply_policy: fd.get('reply_policy'), auto_suggest_threshold: Number(fd.get('auto_suggest_threshold')) }
          });
          m.close();
          toast('Channel policy updated', 'ok');
          await refreshOverview();
        });
      };
    };
  });
}

/* ==========================================================================
   8. DETERMINISTIC TRIAGE RULES (#rules)
   ========================================================================== */
async function loadRules() {
  const host = $('#body-rules');
  try {
    const data = await api('/api/admin/rules');
    state.rules = data.rules || [];
    renderRulesPage();
  } catch (err) {
    host.innerHTML = paintTableError(1, err);
  }
}

function renderRulesPage() {
  const host = $('#body-rules');
  const formHtml = `<form id="rule-form">
    <label class="field"><span class="field-label">Rule name</span><input type="text" name="name" placeholder="VIP wholesale inquiry" required></label>
    <label class="field"><span class="field-label">Pattern</span><input type="text" name="pattern" placeholder="wholesale|distributor|bulk order" required></label>
    <div class="field-grid">
      <label class="field"><span class="field-label">Match kind</span>
        <select name="match_kind"><option value="keyword">Keyword</option><option value="regex">Regular expression</option><option value="author">Author handle</option></select>
      </label>
      <label class="field"><span class="field-label">Target bucket</span>
        <select name="auto_bucket">
          <option value="should_consult">Should consult</option>
          <option value="complaint">Complaints</option>
          <option value="evidence">Defamation / evidence</option>
          <option value="spam_clone">Spam / clone</option>
          <option value="praise">VIP &amp; praise</option>
          <option value="needs_review">Needs review</option>
        </select>
      </label>
    </div>
    <button type="submit" class="btn btn-primary">Save rule</button>
  </form>`;

  const rows = state.rules.map(r => `<tr>
    <td class="cell-main">${esc(r.name)}</td>
    <td class="mono">${esc(r.match_kind)}</td>
    <td><code>${esc(r.pattern)}</code></td>
    <td>${badge(r.auto_bucket, 'b-acc')}</td>
    <td class="mono">${esc(r.auto_status)}</td>
  </tr>`);

  host.innerHTML = `<div class="grid-2">
    ${card('Create or update triage rule', formHtml, { sub: 'Pre-route comments before AI rubric scoring.' })}
    ${card('Configured deterministic rules', table(['Name', 'Match kind', 'Pattern', 'Bucket', 'Auto status'], rows, 'No custom triage rules configured yet.'), { flush: true })}
  </div>`;

  enhanceAllSelects(host);
  $('#rule-form')?.addEventListener('submit', ev => {
    ev.preventDefault();
    const fd = new FormData(ev.currentTarget);
    busy(ev.currentTarget.querySelector('button'), async () => {
      await api('/api/admin/rules', {
        method: 'POST',
        body: { name: fd.get('name'), pattern: fd.get('pattern'), match_kind: fd.get('match_kind'), auto_bucket: fd.get('auto_bucket') }
      });
      toast('Triage rule saved', 'ok');
      await loadRules();
    });
  });
}

/* ==========================================================================
   9. BUSINESS MCP CONNECTOR (#connector)
   ========================================================================== */
async function loadConnector() {
  const host = $('#body-connector');
  try {
    state.connector = await api('/api/admin/connector');
    renderConnectorPage();
  } catch (err) {
    host.innerHTML = paintTableError(1, err);
  }
}

function renderConnectorPage() {
  const host = $('#body-connector');
  const c = state.connector;
  const gw = c.mcp_gateway || {};
  const srcBadge = src => src === 'environment' ? badge('Env managed', 'b-dim') : (src === 'database' ? badge('Saved in Vault', 'b-ok') : badge('Unset', 'b-warn'));

  const pairHtml = `<dl class="kv">
    <dt>MCP endpoint</dt><dd>${copyChip(c.endpoint || '/mcp')}</dd>
    <dt>Audience</dt><dd>${copyChip(c.audience || 'lnc-care')}</dd>
    <dt>Hub namespace</dt><dd>${copyChip(c.namespace || 'care__*')}</dd>
    <dt>Transport</dt><dd><code>${esc(c.transport || 'streamable-http')}</code> (zero-redirect)</dd>
    <dt>Connector bearer</dt><dd>${c.bearer_configured ? badge('Configured', 'b-ok') : badge('Missing', 'b-err')} ${srcBadge(c.bearer_source)}</dd>
    <dt>Delegation HMAC</dt><dd>${c.delegation_secret_configured ? badge('Configured', 'b-ok') : badge('Missing', 'b-err')} ${srcBadge(c.delegation_secret_source)}</dd>
    <dt>Delegation required</dt><dd>${c.require_delegation ? badge('Enforced (v3/v4 nonce)', 'b-ok') : badge('Disabled', 'b-warn')}</dd>
    <dt>Allowed max scopes</dt><dd><code>${esc((c.max_scopes || []).join(', '))}</code></dd>
  </dl>`;

  const gwHtml = `<dl class="kv">
    <dt>Gateway URL</dt><dd>${gw.gateway_url ? copyChip(gw.gateway_url) : badge('Not configured', 'b-dim')}</dd>
    <dt>Service API key</dt><dd>${gw.has_api_key ? badge('Configured (svc:lnc-care)', 'b-ok') : badge('Missing', 'b-warn')}</dd>
    <dt>Allowed peer prefixes</dt><dd><code>${esc((gw.allowed_prefixes || ['ads__']).join(', '))}</code></dd>
    <dt>Topology</dt><dd class="cell-sub">${esc(gw.route || 'lnc-care -> LNC-Agent-Hub (/mcp) -> Business MCP Hub (:8790/mcp) -> lnc-ads (/mcp)')}</dd>
  </dl>`;

  const prompts = [
    ['Triage LuxeClaw inbox', 'List pending comments in shop LuxeClaw with care__comments_list, evaluate top consult leads and prepare reply drafts.'],
    ['Cross-reference ad post', 'Inspect comment thread #1 in LNC Care and call care__ads_gateway_call with ads__page_posts_list for LuxeClaw to check active ad context.'],
    ['Seal defamation bundle', 'Capture a 5-layer forensic evidence bundle with care__evidence_capture for the abusive comment and verify its SHA-256 manifest.']
  ].map(([title, prompt]) => `<tr>
    <td class="cell-main">${esc(title)}</td>
    <td class="cell-sub">${esc(prompt)}</td>
    <td><div class="row-actions"><button type="button" class="btn btn-sm" data-copy="${esc(prompt)}">Copy prompt</button></div></td>
  </tr>`);

  const toolRows = Object.entries(c.tools || {}).map(([name, scopes]) => `<tr>
    <td><code>care__${esc(name)}</code></td>
    <td><code>${esc(scopes.join(', '))}</code></td>
  </tr>`);

  const scopeRows = (c.available_scopes || []).map(sc => `<tr>
    <td><code>${esc(sc)}</code></td>
    <td>${(c.max_scopes || []).includes(sc) ? badge('Permitted', 'b-ok') : badge('Blocked by max_scopes', 'b-dim')}</td>
  </tr>`);

  host.innerHTML = `<div class="grid-2">
      ${card('Business MCP Hub pairing', pairHtml, { sub: 'Inbound Hub v3/v4 HMAC delegation contract.' })}
      ${card('Unified Agent Hub MCP gateway', gwHtml, { sub: 'Outbound cross-app calls to LNC Ads via LNC-Agent-Hub.' })}
    </div>
    ${card('Operator & agent prompt playbook', table(['Scenario', 'Prompt', 'Action'], prompts, ''), { flush: true })}
    <div class="grid-2">
      ${card(`Exposed MCP tools (${toolRows.length})`, table(['Tool', 'Required scopes'], toolRows, 'No tools registered.'), { flush: true })}
      ${card('Delegation scopes', table(['Scope', 'Runtime ceiling'], scopeRows, 'No scopes defined.'), { flush: true })}
    </div>`;

  wireCopyButtons(host);
}

/* ==========================================================================
   10. SHA-256 HASH-CHAINED AUDIT LOG (#audit)
   ========================================================================== */
async function loadAudit() {
  const host = $('#body-audit');
  try {
    state.audit = await api('/api/admin/audit');
    renderAuditPage();
  } catch (err) {
    host.innerHTML = paintTableError(1, err);
  }
}

function renderAuditPage() {
  const host = $('#body-audit');
  const a = state.audit;
  const q = state.auditFilter.toLowerCase();
  const filtered = (a.events || []).filter(e => {
    if (!q) return true;
    return `${e.actor} ${e.action} ${e.subject} ${JSON.stringify(e.details || {})}`.toLowerCase().includes(q);
  });

  const rows = filtered.map(e => `<tr>
    <td class="num mono">${e.sequence}</td>
    <td class="mono">${esc(e.created_at)}</td>
    <td>${esc(e.actor)}</td>
    <td><code>${esc(e.action)}</code></td>
    <td>${esc(e.subject)}</td>
    <td class="mono">${esc(JSON.stringify(e.details || {}))}</td>
  </tr>`);

  const chainBadge = a.valid
    ? badge(`Valid chain · ${num(a.checked)} events`, 'b-ok')
    : badge(`Integrity mismatch at #${a.broken_sequence}`, 'b-err');

  host.innerHTML = card('Audit events', table(['#Seq', 'Timestamp (UTC)', 'Actor', 'Action', 'Subject', 'Details'], rows, 'No matching audit events.'), {
    sub: 'Tamper-evident SHA-256 hash chain across every admin, SSO and MCP mutation.',
    flush: true,
    tools: `<input type="search" id="audit-search-input" value="${esc(state.auditFilter)}" placeholder="Filter actor, action, subject..." style="width:230px;height:30px;font-size:12.5px">${chainBadge}`
  });

  $('#audit-search-input')?.addEventListener('input', ev => {
    state.auditFilter = ev.target.value;
    const pos = ev.target.selectionStart;
    renderAuditPage();
    const nextInput = $('#audit-search-input');
    if (nextInput) { nextInput.focus(); nextInput.setSelectionRange(pos, pos); }
  });
}

/* ==========================================================================
   11. THE API KEYS & MANAGEMENT KEY PAGE (#keys)
   ========================================================================== */
async function loadKeys() {
  const host = $('#body-keys');
  try {
    state.keysInventory = await api('/api/keys');
    renderKeysPage();
  } catch (err) {
    host.innerHTML = paintTableError(1, err);
  }
}

function renderKeysPage() {
  const host = $('#body-keys');
  const items = state.keysInventory.keys || [];
  const mgmt = state.keysInventory.mgmt || {};
  const o = state.overview || {};
  const hub = o.agent_hub || {};
  const br = o.bridge || {};
  const gw = o.mcp_gateway || {};

  const revealHtml = state.createdSecretBanner
    ? `<div class="alert alert-success" style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
        <div><b>${esc(state.createdSecretBanner.title)}:</b> ${copyChip(state.createdSecretBanner.secret)} <span class="cell-sub">Store this secret securely now — plaintext is never listed in key tables.</span></div>
        <div class="btn-grp">
          <button type="button" class="btn btn-sm btn-primary" data-copy="${esc(state.createdSecretBanner.secret)}">Copy secret</button>
          <button type="button" class="btn btn-sm" id="dismiss-secret-banner">Dismiss</button>
        </div>
      </div>`
    : '';

  const createFormHtml = `<form id="api-key-form" class="inline-form" style="margin-bottom:16px">
    <input type="text" name="label" placeholder="Key label (e.g. LNC Agent Hub poller)" maxlength="80" required>
    <input type="password" name="secret" placeholder="Optional custom secret (min 24 chars)" minlength="24" autocomplete="new-password">
    <button type="submit" class="btn btn-primary">Create API key</button>
  </form>`;

  const keyRows = items.map(k => {
    const stCls = k.status === 'enabled' ? 'b-ok' : (k.status === 'disabled' ? 'b-warn' : 'b-err');
    const isRuntime = k.source === 'runtime';
    const isRevoked = k.status === 'revoked';
    return `<tr>
      <td class="cell-main">${esc(k.label)}</td>
      <td class="mono">${esc(k.prefix)}...</td>
      <td>${k.source === 'environment' ? badge('Env managed', 'b-dim') : badge('Runtime', 'b-acc')}</td>
      <td>${badge(k.status, stCls)}</td>
      <td class="cell-sub">${when(k.created_at)}</td>
      <td><div class="row-actions">
        ${isRuntime && k.copy_available && !isRevoked ? `<button type="button" class="btn btn-sm" data-key-copy="${k.id}">Copy</button>` : ''}
        ${isRuntime && !isRevoked ? `<button type="button" class="btn btn-sm" data-key-rename="${k.id}" data-label="${esc(k.label)}">Rename</button>` : ''}
        ${isRuntime && !isRevoked ? `<button type="button" class="btn btn-sm" data-key-toggle="${k.id}">${k.status === 'enabled' ? 'Disable' : 'Enable'}</button>` : ''}
        ${isRuntime && !isRevoked ? `<button type="button" class="btn btn-sm btn-danger" data-key-revoke="${k.id}" data-label="${esc(k.label)}">Revoke</button>` : ''}
        ${isRuntime && isRevoked ? `<button type="button" class="btn btn-sm btn-danger" data-key-delete="${k.id}" data-label="${esc(k.label)}">Delete</button>` : ''}
      </div></td>
    </tr>`;
  });

  const mgmtBody = `<dl class="kv" style="margin-bottom:14px">
      <dt>Status</dt><dd>${mgmt.configured ? badge('Configured', 'b-ok') : badge('Not configured', 'b-err')}</dd>
      <dt>Key prefix</dt><dd class="mono">${esc(mgmt.prefix || '-')}</dd>
      <dt>Ownership</dt><dd>${mgmt.source === 'environment' ? badge('Env managed', 'b-dim') : (mgmt.source === 'runtime' ? badge('Runtime (PBKDF2)', 'b-acc') : badge('Unset', 'b-warn'))}</dd>
      ${mgmt.created_at ? `<dt>Rotated at</dt><dd>${when(mgmt.created_at)}</dd>` : ''}
    </dl>
    ${mgmt.bootstrap_ignored ? `<div class="alert alert-info" style="margin-bottom:14px">Bootstrap ignored: runtime key exists in database and owns sign-in.</div>` : ''}
    ${mgmt.source === 'environment'
      ? `<p class="hint" style="margin:0">Controlled by <code>MANAGEMENT_KEY</code> in stack environment. To enable UI-owned rotation without container restarts, provide <code>CARE_ADMIN_BOOTSTRAP_KEY</code> instead of <code>MANAGEMENT_KEY</code>.</p>`
      : `<form id="mgmt-rotate-form">
          ${mgmt.configured ? `<label class="field"><span class="field-label">Current management key</span><input type="password" name="current_key" placeholder="Verify current management key" autocomplete="current-password" required></label>` : ''}
          <label class="field"><span class="field-label">Replacement secret (optional, min 16 chars)</span><input type="password" name="secret" placeholder="Leave blank to auto-generate strong key" minlength="16" autocomplete="new-password"></label>
          <button type="submit" class="btn btn-danger">Rotate management key</button>
        </form>`}`;

  const outboundBody = `<dl class="kv">
    <dt>Local Master Vault</dt><dd>${badge('AES-256-GCM verified', 'b-ok')}</dd>
    <dt>LNC Agent Hub</dt><dd>${hub.has_api_key ? badge('svc:lnc-care configured', 'b-ok') : badge('API key unset', 'b-dim')}</dd>
    <dt>LNC Ads LAN Bridge</dt><dd>${br.enabled ? badge('HMAC shared secret active', 'b-ok') : badge('Disabled', 'b-dim')}</dd>
    <dt>Unified MCP Gateway</dt><dd>${gw.configured ? badge('Gateway ready', 'b-ok') : badge('Unset', 'b-dim')}</dd>
  </dl>
  <p class="hint" style="margin:12px 0 0">Service API keys authenticate programmatic <code>GET /api/status</code> probes via <code>Authorization: Bearer &lt;key&gt;</code> or <code>X-API-Key</code>.</p>`;

  host.innerHTML = `${revealHtml}
    ${card('API keys', `${createFormHtml}${table(['Label', 'Prefix', 'Source', 'Status', 'Created', 'Actions'], keyRows, 'No API keys have been created.')}`, {
      sub: 'Scoped service keys stored as SHA-256 hashes in SQLite with Vault-encrypted copy envelopes.'
    })}
    <div class="grid-2">
      ${card('Management key', mgmtBody, { sub: 'Controls operator sign-in sessions at /login.html.' })}
      ${card('Ecosystem credential posture', outboundBody, { sub: 'Masked status of server-to-server secrets.' })}
    </div>`;

  wireCopyButtons(host);
  $('#dismiss-secret-banner')?.addEventListener('click', () => {
    state.createdSecretBanner = null;
    renderKeysPage();
  });

  $('#api-key-form')?.addEventListener('submit', ev => {
    ev.preventDefault();
    const fd = new FormData(ev.currentTarget);
    busy(ev.currentTarget.querySelector('button'), async () => {
      const res = await api('/api/keys', {
        method: 'POST',
        body: { label: fd.get('label'), secret: fd.get('secret') || '' }
      });
      state.createdSecretBanner = { title: `Created API key "${res.item.label}"`, secret: res.secret };
      toast('API key created', 'ok');
      await loadKeys();
    });
  });

  host.querySelectorAll('[data-key-copy]').forEach(btn => {
    btn.onclick = () => busy(btn, async () => {
      const res = await api(`/api/keys/${Number(btn.dataset.keyCopy)}/copy`, { method: 'POST' });
      await copyText(res.secret);
      toast('API key copied to clipboard', 'ok');
    });
  });

  host.querySelectorAll('[data-key-rename]').forEach(btn => {
    btn.onclick = () => {
      const id = Number(btn.dataset.keyRename);
      const m = modal(`<h3>Rename API key</h3>
        <form id="rename-key-form" style="margin-top:12px">
          <label class="field"><span class="field-label">Key label</span>
            <input type="text" name="label" value="${esc(btn.dataset.label)}" maxlength="80" required>
          </label>
          <div class="acts">
            <button type="button" class="btn" data-close>Cancel</button>
            <button type="submit" class="btn btn-primary">Save label</button>
          </div>
        </form>`);
      m.root.querySelector('#rename-key-form').onsubmit = ev => {
        ev.preventDefault();
        const fd = new FormData(ev.currentTarget);
        busy(ev.currentTarget.querySelector('[type="submit"]'), async () => {
          await api(`/api/keys/${id}`, { method: 'PATCH', body: { label: fd.get('label') } });
          m.close();
          toast('API key renamed', 'ok');
          await loadKeys();
        });
      };
    };
  });

  host.querySelectorAll('[data-key-toggle]').forEach(btn => {
    btn.onclick = () => busy(btn, async () => {
      const res = await api(`/api/keys/${Number(btn.dataset.keyToggle)}/toggle`, { method: 'POST' });
      toast(`API key ${res.status}`, 'ok');
      await loadKeys();
    });
  });

  host.querySelectorAll('[data-key-revoke]').forEach(btn => {
    btn.onclick = async () => {
      const ok = await confirmModal({
        title: 'Revoke API key permanently?',
        body: `Revoke <b>${esc(btn.dataset.label)}</b>? Its encrypted copy envelope will be wiped immediately and any client using it will receive HTTP 401.`,
        confirm: 'Revoke key',
        danger: true
      });
      if (!ok) return;
      await busy(btn, async () => {
        await api(`/api/keys/${Number(btn.dataset.keyRevoke)}/revoke`, { method: 'POST' });
        toast('API key revoked', 'ok');
        await loadKeys();
      });
    };
  });

  host.querySelectorAll('[data-key-delete]').forEach(btn => {
    btn.onclick = async () => {
      const ok = await confirmModal({
        title: 'Delete revoked key record?',
        body: `Remove the tombstoned record for <b>${esc(btn.dataset.label)}</b> from the keys ledger?`,
        confirm: 'Delete record',
        danger: true
      });
      if (!ok) return;
      await busy(btn, async () => {
        await api(`/api/keys/${Number(btn.dataset.keyDelete)}`, { method: 'DELETE' });
        toast('Revoked key record deleted', 'ok');
        await loadKeys();
      });
    };
  });

  $('#mgmt-rotate-form')?.addEventListener('submit', async ev => {
    ev.preventDefault();
    const fd = new FormData(ev.currentTarget);
    const ok = await confirmModal({
      title: 'Rotate management key?',
      body: 'Rotating the management key invalidates all active admin browser sessions immediately. Copy the replacement key before signing in again.',
      confirm: 'Rotate key',
      danger: true
    });
    if (!ok) return;
    await busy(ev.currentTarget.querySelector('button'), async () => {
      const res = await api('/api/mgmt/rotate', {
        method: 'POST',
        body: { current_key: fd.get('current_key') || '', secret: fd.get('secret') || '' }
      });
      modal(`<h3>Management key rotated</h3>
        <p>Copy your new management key now. Your previous session has been invalidated.</p>
        <div class="alert alert-success" style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap">
          ${copyChip(res.key)}
          <button type="button" class="btn btn-sm btn-primary" data-copy="${esc(res.key)}">Copy key</button>
        </div>
        <div class="acts"><a href="/login.html" class="btn btn-primary">Proceed to sign in</a></div>`);
    });
  });
}

/* ==========================================================================
   12. SETTINGS (#settings)
   ========================================================================== */
async function loadSettings() {
  const host = $('#body-settings');
  try {
    state.settings = await api('/api/settings');
    renderSettingsPage();
  } catch (err) {
    host.innerHTML = paintTableError(1, err);
  }
}

function renderSettingsPage() {
  const host = $('#body-settings');
  const s = state.settings;
  const vals = s.values || {};
  const srcs = s.sources || {};
  const secs = s.secrets || {};
  const srcTag = src => src === 'environment'
    ? badge('Env managed', 'b-dim')
    : (src === 'database' ? badge('Saved in DB', 'b-acc') : badge('Default', 'b-dim'));
  const secTag = meta => meta?.source === 'environment'
    ? badge('Env managed', 'b-dim')
    : (meta?.source === 'database' ? badge('Saved in Vault', 'b-ok') : badge('Unset', 'b-warn'));

  const cfgFormHtml = `<form id="settings-form">
    <label class="field">
      <span class="field-label">Public base URL ${srcTag(srcs.public_base_url)}</span>
      <input type="text" name="public_base_url" value="${esc(vals.public_base_url || '')}" placeholder="https://care-mcp.lengoc.me" ${srcs.public_base_url === 'environment' ? 'disabled' : ''}>
    </label>
    <label class="field">
      <span class="field-label">Allowed hosts (comma-separated) ${srcTag(srcs.allowed_hosts)}</span>
      <input type="text" name="allowed_hosts" value="${esc((vals.allowed_hosts || []).join(', '))}" ${srcs.allowed_hosts === 'environment' ? 'disabled' : ''}>
      <span class="field-help">Localhost, 127.0.0.1 and container hostname are always permitted for health probes.</span>
    </label>
    <label class="field">
      <span class="field-label">MCP max scopes (comma-separated) ${srcTag(srcs.mcp_max_scopes)}</span>
      <input type="text" name="mcp_max_scopes" value="${esc((vals.mcp_max_scopes || []).join(', '))}" ${srcs.mcp_max_scopes === 'environment' ? 'disabled' : ''}>
    </label>
    <label class="field">
      <span class="field-label">Archive retention days ${srcTag(srcs.archive_retention_days)}</span>
      <input type="number" name="archive_retention_days" min="1" max="3650" value="${esc(vals.archive_retention_days ?? 365)}" ${srcs.archive_retention_days === 'environment' ? 'disabled' : ''}>
    </label>
    <button type="submit" class="btn btn-primary">Save runtime settings</button>
  </form>`;

  const bearerEnv = secs.connector_bearer?.source === 'environment';
  const delEnv = secs.delegation_secret?.source === 'environment';
  const secFormHtml = `<p class="hint">Write-only pairing secrets for Business MCP Hub (<code>env_or_cfg</code>). When an environment variable is set in Portainer, the field is locked so UI edits never silently diverge from runtime env.</p>
    <form id="pairing-secrets-form">
      <label class="field">
        <span class="field-label">Connector bearer token ${secTag(secs.connector_bearer)}</span>
        <input type="password" name="connector_bearer" placeholder="${secs.connector_bearer?.configured ? 'Stored (enter new value to replace)' : 'Enter LNC_CONNECTOR_TOKEN'}" autocomplete="new-password" ${bearerEnv ? 'disabled' : ''}>
      </label>
      <label class="field">
        <span class="field-label">Delegation HMAC secret ${secTag(secs.delegation_secret)}</span>
        <input type="password" name="delegation_secret" placeholder="${secs.delegation_secret?.configured ? 'Stored (enter new value to replace)' : 'Enter LNC_DELEGATION_SECRET'}" autocomplete="new-password" ${delEnv ? 'disabled' : ''}>
      </label>
      <button type="submit" class="btn btn-primary" ${bearerEnv && delEnv ? 'disabled' : ''}>Save pairing secrets</button>
    </form>`;

  host.innerHTML = `<div class="grid-2">
    ${card('Runtime configuration', cfgFormHtml, { sub: 'Database settings apply immediately unless locked by environment.' })}
    ${card('Hub pairing secrets', secFormHtml, { sub: 'Encrypted in Vault under pairing/connector when not env-managed.' })}
  </div>`;

  $('#settings-form')?.addEventListener('submit', ev => {
    ev.preventDefault();
    const fd = new FormData(ev.currentTarget);
    const payload = {};
    if (srcs.public_base_url !== 'environment') payload.public_base_url = fd.get('public_base_url');
    if (srcs.allowed_hosts !== 'environment') payload.allowed_hosts = String(fd.get('allowed_hosts') || '').split(',').map(x => x.trim()).filter(Boolean);
    if (srcs.mcp_max_scopes !== 'environment') payload.mcp_max_scopes = String(fd.get('mcp_max_scopes') || '').split(',').map(x => x.trim()).filter(Boolean);
    if (srcs.archive_retention_days !== 'environment') payload.archive_retention_days = Number(fd.get('archive_retention_days'));
    busy(ev.currentTarget.querySelector('button'), async () => {
      state.settings = await api('/api/settings', { method: 'POST', body: payload });
      toast('Runtime settings saved', 'ok');
      renderSettingsPage();
    });
  });

  $('#pairing-secrets-form')?.addEventListener('submit', ev => {
    ev.preventDefault();
    const fd = new FormData(ev.currentTarget);
    const payload = {};
    const cb = String(fd.get('connector_bearer') || '').trim();
    const ds = String(fd.get('delegation_secret') || '').trim();
    if (cb) payload.connector_bearer = cb;
    if (ds) payload.delegation_secret = ds;
    if (!cb && !ds) {
      toast('Enter a new token or secret to update Vault', 'err');
      return;
    }
    busy(ev.currentTarget.querySelector('button'), async () => {
      state.settings = await api('/api/settings', { method: 'POST', body: payload });
      toast('Hub pairing secrets encrypted in Vault', 'ok');
      renderSettingsPage();
    });
  });
}

/* ---------- Global Listeners & Boot ---------- */
async function pollHealth() {
  const pill = $('#health');
  if (!pill) return;
  try {
    const r = await fetch('/health', { credentials: 'same-origin' });
    pill.className = `pill ${r.ok ? 'ok' : 'bad'}`;
    pill.innerHTML = `<span class="dot"></span>${r.ok ? 'Healthy' : 'Degraded'}`;
  } catch {
    pill.className = 'pill bad';
    pill.innerHTML = '<span class="dot"></span>Offline';
  }
}

const syncThemeLabel = () => {
  const el = $('#theme-label');
  if (el) el.textContent = document.documentElement.dataset.theme === 'light' ? 'Dark theme' : 'Light theme';
};
syncThemeLabel();

$('#theme-toggle')?.addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = next;
  syncThemeLabel();
  try { localStorage.setItem('lnc-care-theme', next); } catch {}
});

$('#signout')?.addEventListener('click', async ev => {
  ev.preventDefault();
  try { await api('/api/auth/logout', { method: 'POST' }); } catch {}
  location.assign('/login.html');
});

$('#shop-select')?.addEventListener('change', async ev => {
  state.shopId = ev.target.value ? Number(ev.target.value) : null;
  try {
    localStorage.setItem('lnccare.shop', state.shopId === null ? 'all' : String(state.shopId));
  } catch {}
  await refreshOverview();
  await route();
});

$$('[data-refresh]').forEach(btn => {
  btn.onclick = () => busy(btn, async () => {
    state.discovered = {};
    await refreshOverview();
    await route();
    toast('Refreshed', 'ok');
  });
});

$$('[data-hub-sync]').forEach(btn => {
  btn.onclick = () => busy(btn, async () => {
    const res = await api('/api/admin/hub/sync', { method: 'POST' });
    toast(`Synced via ${res.source}: +${res.pulled_shops} shops, +${res.pulled_channels || 0} channels`, 'ok');
    await refreshOverview();
    await route();
  });
});

$('#audit-verify-btn')?.addEventListener('click', ev => busy(ev.currentTarget, async () => {
  const r = await api('/api/admin/audit/verify');
  toast(r.valid ? `Valid chain · ${num(r.checked)} events` : `Chain broken at #${r.broken_sequence}`, r.valid ? 'ok' : 'err');
  await loadAudit();
}));

window.addEventListener('hashchange', () => {
  $('#modal-root').innerHTML = '';
  route().catch(fail);
  window.scrollTo(0, 0);
});

window.addEventListener('keydown', ev => {
  if ($('#modal-root')?.children.length) return;
  if (['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) return;
  if (currentPage() !== 'inbox' || !state.selectedCommentId) return;
  if (['1', '2', '3'].includes(ev.key)) {
    const btn = document.querySelector(`[data-decision="${ev.key}"]`);
    if (btn) btn.click();
  }
});

let scrollTimer;
window.addEventListener('scroll', () => {
  document.documentElement.classList.add('is-scrolling');
  clearTimeout(scrollTimer);
  scrollTimer = setTimeout(() => document.documentElement.classList.remove('is-scrolling'), 650);
}, { passive: true });

(async () => {
  try {
    if (!location.hash) history.replaceState(null, '', '#overview');
    renderShell();
    const auth = await fetch('/api/auth/status', { credentials: 'same-origin' }).then(r => r.json());
    if (!auth.ok && !auth.authenticated) {
      location.replace('/login.html');
      return;
    }
    state.csrf = auth.csrf_token || auth.csrf || '';
    try {
      const storedShop = localStorage.getItem('lnccare.shop');
      if (storedShop && storedShop !== 'all') state.shopId = Number(storedShop);
    } catch {}
    await refreshOverview();
    if (state.shopId !== null && !(state.overview?.shops || []).some(s => s.id === state.shopId)) {
      state.shopId = null;
      await refreshOverview();
    }
    await route();
    pollHealth();
    setInterval(pollHealth, 60000);
  } catch (err) {
    const host = $('#body-overview');
    if (host) host.innerHTML = `<div class="alert alert-danger">${esc(errorText(err))}</div>`;
  }
})();
