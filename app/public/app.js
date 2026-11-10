const state = {
  csrf: "",
  shopId: null,
  overview: null,
  comments: [],
  commentSummary: null,
  selectedCommentId: null,
  selectedBucket: "all",
  selectedAssignment: "all",
  selectedChannelId: "",
  searchQuery: "",
  posts: [],
  selectedPostId: null,
  discovered: {}
};

const VIEW_TITLES = {
  inbox: "Triage & Consultation Queue",
  overview: "Care Console Overview",
  posts: "Ingested Posts, Metric Snapshots & Media Archives",
  evidence: "Forensic Evidence Vault (Lập vi bằng số)",
  fleet: "Multi-Account Runtime Fleet (VeilBrowser · Orbine · Graph API)",
  channels: "OAuth Integrations, Connections & Approved Channels",
  rules: "Deterministic Triage Rules",
  connector: "Business MCP Hub Connector (care__*)",
  audit: "SHA-256 Hash-Chained Audit Log",
  settings: "Runtime Settings"
};

const BUCKET_META = [
  { key: "all", label: "All" },
  { key: "should_consult", label: "Should consult" },
  { key: "needs_review", label: "Needs review" },
  { key: "praise", label: "VIP & praise" },
  { key: "complaint", label: "Complaints" },
  { key: "spam_clone", label: "Spam / clone" },
  { key: "evidence", label: "Defamation / Evidence" }
];

const ACTION_LABELS = {
  should_consult: { text: "Should consult · Nên tư vấn", cls: "good" },
  needs_review: { text: "Needs manual review · Cần xem tay", cls: "warn" },
  prioritize_care: { text: "Priority care · Chăm sóc đơn hàng", cls: "warn" },
  preserve_evidence: { text: "Preserve evidence · Lập vi bằng", cls: "bad" },
  hide_spam: { text: "Hide spam / clone · Ẩn spam", cls: "bad" }
};

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
  }[ch]));
}

function initials(name) {
  const parts = String(name || "U").trim().split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  return (parts[0] || "U").slice(0, 2).toUpperCase();
}

function banner(message, kind = "ok") {
  const el = document.getElementById("banner");
  el.textContent = message;
  el.className = `alert ${kind}`;
  el.hidden = false;
  clearTimeout(banner._t);
  banner._t = setTimeout(() => { el.hidden = true; }, 4500);
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body && typeof options.body !== "string") {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(options.body);
  }
  if (options.method && options.method !== "GET") {
    headers["X-CSRF-Token"] = state.csrf;
  }
  const res = await fetch(path, { credentials: "same-origin", ...options, headers });
  if (res.status === 401) {
    location.replace("/login.html");
    throw new Error("Authentication required");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || data.error || `HTTP ${res.status}`);
  return data;
}

function setView() {
  const rawHash = (location.hash || "#inbox").slice(1) || "inbox";
  const [view, hashQuery] = rawHash.split("?");
  if (hashQuery) {
    const qp = new URLSearchParams(hashQuery);
    if (qp.get("oauth_status") === "connected") {
      banner(`Shared ${qp.get("provider") || "OAuth"} account connected! Syncing shared channels...`);
      api("/api/admin/hub/sync", { method: "POST" }).then(() => refreshOverview()).catch(() => {});
    } else if (qp.get("oauth_error")) {
      banner(`OAuth error: ${qp.get("oauth_error")}`, "error");
    }
  }
  document.querySelectorAll(".view").forEach((section) => {
    section.hidden = section.dataset.view !== view;
  });
  document.querySelectorAll("#nav a").forEach((link) => {
    link.classList.toggle("active", link.dataset.view === view);
  });
  document.getElementById("view-title").textContent = VIEW_TITLES[view] || "LNC Care";
  if (view === "inbox") loadInbox();
  if (view === "posts") loadPosts();
  if (view === "evidence") loadEvidence();
  if (view === "fleet") loadFleet();
  if (view === "rules") loadRules();
  if (view === "connector") loadConnector();
  if (view === "audit") loadAudit();
  if (view === "settings") loadSettings();
}

function renderOverview() {
  const o = state.overview;
  if (!o) return;
  document.getElementById("org-label").textContent = `${o.organization.name} (${o.organization.id})`;
  document.getElementById("version-badge").textContent = `v${o.version}`;
  document.getElementById("writes-badge").textContent = o.writes_enabled ? "Writes enabled" : "Draft-for-approval";

  const hub = o.agent_hub || {};
  const br = o.bridge || {};
  const ssoHubLink = document.getElementById("sso-hub-link");
  const ssoAdsLink = document.getElementById("sso-ads-link");
  if (ssoHubLink) {
    ssoHubLink.hidden = !hub.sso_path;
  }
  if (ssoAdsLink) {
    ssoAdsLink.hidden = !((br.enabled && br.peers && br.peers["lnc-ads"]) || hub.sso_path);
  }
  const vaultBadge = document.getElementById("vault-badge");
  if (vaultBadge) {
    if (hub.mode === "vault_synced") {
      vaultBadge.textContent = "Hub Vault synced";
      vaultBadge.className = "badge good";
    } else if (hub.mode === "ads_bridge_fallback") {
      vaultBadge.textContent = "LNC Ads bridge active";
      vaultBadge.className = "badge good";
    } else {
      vaultBadge.textContent = "Local Vault verified";
      vaultBadge.className = "badge";
    }
  }

  const shopSelect = document.getElementById("shop-select");
  shopSelect.innerHTML = `<option value="">All shops</option>` + o.shops.map((s) =>
    `<option value="${s.id}" ${String(state.shopId) === String(s.id) ? "selected" : ""}>${esc(s.name)}</option>`
  ).join("");

  const inbox = o.inbox_summary || { total: 0, by_bucket: {}, by_status: {} };
  const approvedChannels = o.channels.filter((c) => c.approved).length;
  document.getElementById("overview-kpis").innerHTML = [
    ["Total Comments", `${inbox.total || 0}`],
    ["Should Consult", `${(inbox.by_bucket && inbox.by_bucket.should_consult) || 0}`],
    ["Approved Channels", `${approvedChannels} / ${o.channels.length}`],
    ["Evidence Vault Cases", `${o.evidence_cases_count || 0}`],
    ["Healthy Fleet Runtimes", `${o.fleet_summary.healthy} / ${o.fleet_summary.total}`]
  ].map(([label, val]) => `<div class="kpi"><span class="muted">${esc(label)}</span><strong>${esc(val)}</strong></div>`).join("");

  document.querySelector("#overview-channels tbody").innerHTML = o.channels.map((ch) => `
    <tr>
      <td><strong>${esc(ch.name)}</strong><br><span class="muted small">${esc(ch.handle || ch.external_id)}</span></td>
      <td>${esc(ch.provider)}</td>
      <td><code>${esc(ch.adapter)}</code></td>
      <td>${Number(ch.followers_count || 0).toLocaleString()}</td>
      <td>${ch.posts_count || 0}</td>
      <td>${ch.comments_count || 0}</td>
      <td><span class="badge ${ch.approved ? "good" : "warn"}">${esc(ch.reply_policy)}</span></td>
    </tr>
  `).join("") || `<tr><td colspan="7" class="muted">No channels yet. Click "Load Demo Workspace" in the sidebar to populate realistic data.</td></tr>`;

  // Populate inbox channel filter
  const chFilter = document.getElementById("inbox-channel-filter");
  chFilter.innerHTML = `<option value="">All channels</option>` + o.channels.map((ch) =>
    `<option value="${ch.id}" ${String(state.selectedChannelId) === String(ch.id) ? "selected" : ""}>${esc(ch.name)}</option>`
  ).join("");

  renderChannelsView();
}

/* ==========================================================================
   1. SPLIT-PANE TRIAGE & CONSULTATION INBOX
   ========================================================================== */
async function loadInbox() {
  const params = new URLSearchParams();
  if (state.shopId) params.set("shop_id", state.shopId);
  if (state.selectedChannelId) params.set("channel_id", state.selectedChannelId);
  if (state.selectedBucket && state.selectedBucket !== "all") params.set("bucket", state.selectedBucket);
  if (state.selectedAssignment && state.selectedAssignment !== "all") params.set("assignment", state.selectedAssignment);
  if (state.searchQuery) params.set("search", state.searchQuery);

  const data = await api(`/api/admin/comments?${params.toString()}`);
  state.comments = data.comments || [];
  state.commentSummary = data.summary || { total: 0, by_bucket: {}, assignment: { all: 0, unassigned: 0, assigned: 0 } };

  if (!state.selectedCommentId && state.comments.length > 0) {
    state.selectedCommentId = state.comments[0].id;
  } else if (state.selectedCommentId && !state.comments.some((c) => c.id === state.selectedCommentId)) {
    state.selectedCommentId = state.comments[0] ? state.comments[0].id : null;
  }

  renderBucketBar();
  renderQueuePane();
  renderDetailPane();
}

function renderBucketBar() {
  const sum = state.commentSummary || { total: 0, by_bucket: {} };
  const bar = document.getElementById("triage-bucket-bar");
  bar.innerHTML = BUCKET_META.map((b) => {
    const cnt = b.key === "all" ? (sum.total || 0) : ((sum.by_bucket && sum.by_bucket[b.key]) || 0);
    const active = state.selectedBucket === b.key ? "active" : "";
    return `<button type="button" class="bucket-pill ${active}" data-bucket="${b.key}">
      <span>${esc(b.label)}</span>
      <span class="cnt">${cnt}</span>
    </button>`;
  }).join("");

  bar.querySelectorAll("[data-bucket]").forEach((btn) => {
    btn.onclick = () => {
      state.selectedBucket = btn.dataset.bucket;
      loadInbox().catch((e) => banner(e.message, "error"));
    };
  });
}

function renderQueuePane() {
  const sum = state.commentSummary || { assignment: { all: 0, unassigned: 0, assigned: 0 } };
  const asg = sum.assignment || { all: 0, unassigned: 0, assigned: 0 };
  const subtabs = document.getElementById("triage-assignment-tabs");
  subtabs.innerHTML = [
    ["all", `All ${asg.all || 0}`],
    ["unassigned", `Unassigned ${asg.unassigned || 0}`],
    ["assigned", `Assigned ${asg.assigned || 0}`]
  ].map(([k, label]) =>
    `<button type="button" class="subtab-btn ${state.selectedAssignment === k ? "active" : ""}" data-asg="${k}">${esc(label)}</button>`
  ).join("");

  subtabs.querySelectorAll("[data-asg]").forEach((btn) => {
    btn.onclick = () => {
      state.selectedAssignment = btn.dataset.asg;
      loadInbox().catch((e) => banner(e.message, "error"));
    };
  });

  const listEl = document.getElementById("triage-queue-list");
  if (!state.comments.length) {
    listEl.innerHTML = `<div class="empty-state">
      <p>No comments match this filter.</p>
      <button type="button" class="primary" id="empty-seed-btn">Load Demo Workspace</button>
    </div>`;
    const btn = document.getElementById("empty-seed-btn");
    if (btn) btn.onclick = triggerSeedDemo;
    return;
  }

  // Group comments by bucket in the queue list (just like Friend Triage groups by "Nên chấp nhận", "Cần xem tay", etc.)
  const groups = new Map();
  for (const cm of state.comments) {
    const bKey = cm.bucket || "needs_review";
    if (!groups.has(bKey)) groups.set(bKey, []);
    groups.get(bKey).push(cm);
  }

  let html = "";
  for (const [bKey, items] of groups.entries()) {
    const meta = BUCKET_META.find((m) => m.key === bKey) || { label: bKey };
    html += `
      <div class="queue-group-header">
        <span class="queue-group-tag">${esc(meta.label)}</span>
        <span>${items.length} ${items.length === 1 ? "person" : "people"}</span>
      </div>
    `;
    for (const cm of items) {
      const score = cm.evaluation ? cm.evaluation.overall_score : 50;
      const scoreFmt = Number.isInteger(score) ? String(score) : score.toFixed(1).replace(".", ",");
      const active = cm.id === state.selectedCommentId ? "active" : "";
      html += `
        <div class="queue-card ${active}" data-cm-id="${cm.id}">
          <div class="queue-avatar">${esc(initials(cm.author_name))}</div>
          <div>
            <div class="queue-author">${esc(cm.author_name)}</div>
            <div class="queue-meta">${esc(cm.author_meta || cm.channel_name)}</div>
            <div class="queue-snippet">${esc(cm.text)}</div>
          </div>
          <div class="queue-score">${esc(scoreFmt)}</div>
        </div>
      `;
    }
  }
  listEl.innerHTML = html;

  listEl.querySelectorAll("[data-cm-id]").forEach((card) => {
    card.onclick = () => {
      state.selectedCommentId = Number(card.dataset.cmId);
      renderQueuePane();
      renderDetailPane();
    };
  });
}

function renderDetailPane() {
  const pane = document.getElementById("triage-detail-pane");
  const cm = state.comments.find((c) => c.id === state.selectedCommentId);
  if (!cm) {
    pane.innerHTML = `<div class="empty-state">Select a comment from the queue to inspect AI rubric evaluation and consultation drafts.</div>`;
    return;
  }

  const ev = cm.evaluation || {
    overall_score: 50,
    threshold: 80,
    recommended_action: "needs_review",
    tier_label: "Tier 3/5: Review",
    confidence: 75,
    data_quality: "Full post & comment context",
    reasoning_bullets: ["Awaiting evaluation"],
    label_scores: [],
    reply_strategy: { objective: "Review comment", tone: "Helpful", key_points: [], next_step_cta: "" }
  };

  const actMeta = ACTION_LABELS[ev.recommended_action] || { text: ev.recommended_action, cls: "warn" };
  const scorePct = Math.max(0, Math.min(100, Number(ev.overall_score || 0)));
  const thresholdPct = Math.max(10, Math.min(95, Number(ev.threshold || 80)));

  const publicDraft = (cm.drafts || []).find((d) => d.kind === "public") || { text: "", strategy_summary: "" };
  const privateDraft = (cm.drafts || []).find((d) => d.kind === "private_dm") || { text: "", strategy_summary: "" };
  const strat = ev.reply_strategy || {};

  pane.innerHTML = `
    <div class="triage-detail-scroll">
      <!-- Top AI Recommendation & Big Score -->
      <div class="eval-top-header">
        <div class="eval-rec-wrap">
          <span class="muted">AI Recommendation</span>
          <span class="eval-rec-pill ${actMeta.cls}">${esc(actMeta.text)}</span>
          <span class="badge mono">${esc(cm.status)}</span>
        </div>
        <div>
          <span class="muted">Overall Score </span>
          <span class="eval-score-big">${esc(ev.overall_score)}<small>/100</small></span>
        </div>
      </div>

      <!-- Threshold Progress Bar -->
      <div class="threshold-bar-wrap">
        <div class="threshold-track">
          <div class="threshold-fill" style="width: ${scorePct}%"></div>
          <div class="threshold-tick" style="left: ${thresholdPct}%"></div>
        </div>
        <div class="threshold-labels">
          <span>0</span>
          <span class="threshold-marker-label" style="left: ${thresholdPct}%">Auto-suggest threshold ${thresholdPct}</span>
          <span>100</span>
        </div>
      </div>

      <!-- Comment & Post Context Box -->
      <div class="comment-context-box">
        <div class="comment-context-head">
          <span><strong>${esc(cm.author_name)}</strong> · ${esc(cm.author_meta || "Customer")} · on <strong>${esc(cm.channel_name)}</strong> (<code>${esc(cm.adapter)}</code>)</span>
          <button type="button" class="ghost small-btn" id="re-eval-btn">Re-evaluate AI</button>
        </div>
        <div class="comment-context-text">"${esc(cm.text)}"</div>
        <div class="muted small">Post context: ${esc(cm.post_caption || "")}</div>
      </div>

      <!-- Tier & Bullet Reasoning Summary -->
      <div class="reasoning-summary">
        <div><strong>${esc(ev.tier_label)}</strong></div>
        <ul class="reasoning-bullets">
          ${(ev.reasoning_bullets || []).map((b) => `<li>${esc(b)}</li>`).join("")}
        </ul>
        <div class="muted small">Confidence ${esc(ev.confidence)}% · Data: ${esc(ev.data_quality)} · Code-first prompt-injection isolation</div>
      </div>

      <!-- 12-Row Multi-Label Probability Bars with [✓] / [✕] Human Calibration -->
      <div class="rubric-section">
        <div class="rubric-head">
          <span>Label (Nhãn)</span>
          <span style="text-align:right">Prob.</span>
          <span>Probability Distribution</span>
          <span style="text-align:right">You see</span>
        </div>
        ${(ev.label_scores || []).map((lbl) => {
          const p = Math.max(0, Math.min(100, Number(lbl.probability || 0)));
          const pText = p < 1 ? "<1%" : `${p}%`;
          const barCls = lbl.polarity === "negative"
            ? (p >= 45 ? "neg-high" : "pos-mid")
            : (p >= 60 ? "pos-high" : "pos-mid");
          const yesCls = lbl.human_agreed === true ? "active-yes" : "";
          const noCls = lbl.human_agreed === false ? "active-no" : "";
          return `
            <div class="rubric-row">
              <div class="rubric-label-name">${esc(lbl.label_vi)} <span class="muted small">· ${esc(lbl.label_en)}</span></div>
              <div class="rubric-prob">${esc(pText)}</div>
              <div class="rubric-bar-track">
                <div class="rubric-bar-fill ${barCls}" style="width: ${Math.max(2, p)}%"></div>
              </div>
              <div class="rubric-feedback-btns">
                <button type="button" class="fb-btn ${yesCls}" data-fb-label="${esc(lbl.key)}" data-fb-agreed="1" title="Agree with AI score">✓</button>
                <button type="button" class="fb-btn ${noCls}" data-fb-label="${esc(lbl.key)}" data-fb-agreed="0" title="Disagree with AI score">✕</button>
              </div>
            </div>
          `;
        }).join("")}
      </div>

      <!-- Consultation Reasoning & Reply Studio (Evaluate → Reason → Consult) -->
      <div class="consultation-studio">
        <div class="strategy-card">
          <div><strong>AI Consultation Strategy (Suy luận tư vấn):</strong> ${esc(strat.objective || "")}</div>
          <div class="muted small"><strong>Tone:</strong> ${esc(strat.tone || "")} · <strong>CTA:</strong> ${esc(strat.next_step_cta || "")}</div>
        </div>
        <div class="draft-editors-grid">
          <label>Public Comment Reply Draft
            <textarea id="draft-public-text">${esc(publicDraft.text)}</textarea>
          </label>
          <label>Private DM Consultation Draft
            <textarea id="draft-private-text">${esc(privateDraft.text)}</textarea>
          </label>
        </div>
      </div>
    </div>

    <!-- Sticky Bottom Quick-Decision & Action Bar -->
    <div class="triage-bottom-bar">
      <div class="quick-decision-bar">
        <button type="button" class="decision-btn ${cm.human_decision === 1 ? "active" : ""}" data-decision="1">
          <span>Want to consult</span> <span class="kbd-badge">1</span>
        </button>
        <button type="button" class="decision-btn ${cm.human_decision === 2 ? "active" : ""}" data-decision="2">
          <span>Unsure / Hold</span> <span class="kbd-badge">2</span>
        </button>
        <button type="button" class="decision-btn ${cm.human_decision === 3 ? "active" : ""}" data-decision="3">
          <span>Skip / Ignore</span> <span class="kbd-badge">3</span>
        </button>
      </div>
      <div class="bottom-cta-row">
        <button type="button" class="danger-soft" id="btn-reject-hide">✕ Reject / Hide</button>
        <button type="button" class="ghost" id="btn-capture-evidence">Seal Forensic Evidence</button>
        <button type="button" class="dark-cta" id="btn-approve-consult">✓ Approve Consultation</button>
      </div>
    </div>
  `;

  // Wire Re-evaluate button
  document.getElementById("re-eval-btn").onclick = async () => {
    await api(`/api/admin/comments/${cm.id}/evaluate`, { method: "POST", body: {} });
    banner("AI rubric evaluation refreshed");
    await loadInbox();
  };

  // Wire [✓] / [✕] label calibration buttons
  pane.querySelectorAll("[data-fb-label]").forEach((btn) => {
    btn.onclick = async () => {
      const label = btn.dataset.fbLabel;
      const agreed = btn.dataset.fbAgreed === "1";
      await api(`/api/admin/comments/${cm.id}/feedback`, {
        method: "POST",
        body: { label, agreed }
      });
      banner(`Saved rubric calibration for "${label}"`);
      await loadInbox();
    };
  });

  // Wire 1 / 2 / 3 quick decision pills
  pane.querySelectorAll("[data-decision]").forEach((btn) => {
    btn.onclick = async () => {
      const dec = Number(btn.dataset.decision);
      await api(`/api/admin/comments/${cm.id}/feedback`, {
        method: "POST",
        body: { label: "_decision", agreed: dec === 1, human_decision: dec }
      });
      banner(`Recorded decision [${dec}]`);
      await loadInbox();
    };
  });

  // Wire Reject / Hide
  document.getElementById("btn-reject-hide").onclick = async () => {
    await api(`/api/admin/comments/${cm.id}/state`, {
      method: "POST",
      body: { status: "hidden", bucket: "spam_clone" }
    });
    banner("Comment marked hidden");
    await loadInbox();
  };

  // Wire Capture Forensic Evidence ("Lập vi bằng số")
  document.getElementById("btn-capture-evidence").onclick = async () => {
    const res = await api("/api/admin/evidence/capture", {
      method: "POST",
      body: {
        comment_id: cm.id,
        target_url: cm.post_permalink || `https://www.facebook.com/comment/${cm.external_id}`,
        title: `Forensic Case · ${cm.author_name} (UID ${cm.author_external_id || "unknown"})`
      }
    });
    banner(`Sealed 5-Layer Forensic Evidence #${res.case_id} (SHA-256: ${res.manifest_sha256.slice(0, 12)}...)`);
    await refreshOverview();
  };

  // Wire Approve Consultation
  document.getElementById("btn-approve-consult").onclick = async () => {
    const pubText = document.getElementById("draft-public-text").value.trim();
    const privText = document.getElementById("draft-private-text").value.trim();
    if (pubText) {
      await api(`/api/admin/comments/${cm.id}/drafts`, {
        method: "POST",
        body: { text: pubText, kind: "public", status: "approved", strategy_summary: strat.objective || "" }
      });
    }
    if (privText) {
      await api(`/api/admin/comments/${cm.id}/drafts`, {
        method: "POST",
        body: { text: privText, kind: "private_dm", status: "approved", strategy_summary: strat.objective || "" }
      });
    }
    banner("Approved Public Reply & Private Consultation DM drafts");
    await loadInbox();
  };
}

/* ==========================================================================
   2. POSTS, SNAPSHOT SERIES & ARCHIVES
   ========================================================================== */
async function loadPosts() {
  const q = state.shopId ? `?shop_id=${encodeURIComponent(state.shopId)}` : "";
  const data = await api(`/api/admin/posts${q}`);
  state.posts = data.posts || [];
  const tbody = document.querySelector("#posts-table tbody");
  tbody.innerHTML = state.posts.map((p) => {
    const snap = p.latest_snapshot || {};
    return `
      <tr data-post-row="${p.id}" style="cursor:pointer">
        <td><strong>${esc(p.channel_name)}</strong><br><span class="muted small">${esc(p.provider)}</span></td>
        <td><span class="badge">${esc(p.kind)}</span></td>
        <td>${esc((p.caption || "").slice(0, 80))}...</td>
        <td>${snap.reactions ?? 0}</td>
        <td>${snap.comments_count ?? 0}</td>
        <td>${(p.archives || []).length} files</td>
        <td><button type="button" class="ghost small-btn" data-archive-post="${p.id}">Archive</button></td>
      </tr>
    `;
  }).join("") || `<tr><td colspan="7" class="muted">No posts ingested yet.</td></tr>`;

  tbody.querySelectorAll("[data-post-row]").forEach((row) => {
    row.onclick = (ev) => {
      if (ev.target.closest("[data-archive-post]")) return;
      inspectPost(Number(row.dataset.postRow));
    };
  });

  tbody.querySelectorAll("[data-archive-post]").forEach((btn) => {
    btn.onclick = async (ev) => {
      ev.stopPropagation();
      const pid = Number(btn.dataset.archivePost);
      await api(`/api/admin/posts/${pid}/archive`, { method: "POST" });
      banner(`Archived media & screenshot for post #${pid}`);
      await loadPosts();
      await inspectPost(pid);
    };
  });

  if (state.posts.length && !state.selectedPostId) {
    inspectPost(state.posts[0].id);
  }
}

async function inspectPost(postId) {
  state.selectedPostId = postId;
  const data = await api(`/api/admin/posts/${postId}`);
  const p = data.post;
  const snaps = p.snapshots || [];
  const maxImp = Math.max(100, ...snaps.map((s) => s.impressions || 0));
  const points = snaps.map((s, idx) => {
    const x = 30 + (idx * 240) / Math.max(1, snaps.length - 1);
    const y = 95 - ((s.impressions || 0) / maxImp) * 75;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");

  const box = document.getElementById("post-detail-content");
  box.innerHTML = `
    <div class="stack-sm">
      <div><strong>${esc(p.channel_name)}</strong> · <a href="${esc(p.permalink)}" target="_blank" rel="noreferrer">${esc(p.external_id)}</a></div>
      <div>${esc(p.caption)}</div>
      <div style="background:var(--panel-2);border:1px solid var(--border);border-radius:8px;padding:10px">
        <div class="muted small">5-Day Impressions Trend</div>
        <svg viewBox="0 0 300 110" style="width:100%;height:110px">
          <polyline fill="none" stroke="var(--accent)" stroke-width="3" points="${points}"/>
        </svg>
        <div class="muted small" style="display:flex;justify-content:space-between">
          ${snaps.map((s) => `<span>${esc(s.snapshot_date.slice(5))}: <strong>${s.impressions}</strong></span>`).join("")}
        </div>
      </div>
      <div>
        <strong>Archived Artifacts (${(p.archives || []).length}):</strong>
        <ul class="reasoning-bullets">
          ${(p.archives || []).map((a) => `<li><code>${esc(a.kind)}</code> — <code>${esc(a.path)}</code> (SHA-256: <code>${esc((a.sha256 || "").slice(0, 14))}...</code>)</li>`).join("") || `<li class="muted">Click "Archive" to capture media and screenshot.</li>`}
        </ul>
      </div>
    </div>
  `;
}

/* ==========================================================================
   3. EVIDENCE VAULT (LẬP VI BẰNG SỐ)
   ========================================================================== */
async function loadEvidence() {
  const data = await api("/api/admin/evidence");
  const tbody = document.querySelector("#evidence-table tbody");
  tbody.innerHTML = (data.cases || []).map((c) => {
    const item = (c.items || [])[0] || {};
    return `
      <tr>
        <td><code>#${c.id}</code></td>
        <td><strong>${esc(c.title)}</strong><br><span class="muted small">${esc((item.captured_text || "").slice(0, 90))}</span></td>
        <td>${esc(c.subject_name)}<br><code>UID: ${esc(c.subject_uid)}</code></td>
        <td><a href="${esc(item.target_url || "#")}" target="_blank" rel="noreferrer">${esc((item.target_url || "").slice(0, 42))}...</a></td>
        <td><code title="${esc(c.bundle_sha256)}">${esc((c.bundle_sha256 || "").slice(0, 16))}...</code></td>
        <td><span class="badge good">${esc(item.alive_status || "alive")} (+6h/+24h/+72h)</span></td>
        <td><code>${esc(c.bundle_zip_path)}</code></td>
      </tr>
    `;
  }).join("") || `<tr><td colspan="7" class="muted">No forensic evidence cases sealed yet.</td></tr>`;
}

/* ==========================================================================
   4. MULTI-ACCOUNT FLEET (VEILBROWSER + ORBINE + GRAPH API)
   ========================================================================== */
async function loadFleet() {
  const data = await api("/api/admin/fleet");
  const tbody = document.querySelector("#fleet-table tbody");
  tbody.innerHTML = (data.runtimes || []).map((r) => `
    <tr>
      <td><code>#${r.id}</code></td>
      <td><strong>${esc(r.label)}</strong></td>
      <td>${esc(r.platform)}</td>
      <td><span class="badge ${r.account_role === "personal_main" ? "warn" : ""}">${esc(r.account_role)}</span></td>
      <td><code>${esc(r.adapter)}</code></td>
      <td><code>${esc(r.runtime_profile_id)}</code></td>
      <td><code>${esc(r.expected_exit_ip || "Direct")}</code> (${esc(r.expected_country)})</td>
      <td><span class="badge ${r.health_status === "healthy" ? "good" : "bad"}">${esc(r.health_status)}</span></td>
      <td>${r.reads_today}/${r.daily_read_budget} R · ${r.writes_today}/${r.daily_write_budget} W</td>
    </tr>
  `).join("") || `<tr><td colspan="9" class="muted">No account runtimes registered yet.</td></tr>`;
}

/* ==========================================================================
   5. CHANNELS, RULES, CONNECTOR, AUDIT & SETTINGS
   ========================================================================== */
function renderChannelsView() {
  const o = state.overview;
  if (!o) return;
  const hub = o.agent_hub || {};
  const br = o.bridge || {};
  const gw = o.mcp_gateway || {};
  const hubSummaryEl = document.getElementById("hub-sync-summary");
  if (hubSummaryEl) {
    hubSummaryEl.innerHTML = `
      <div><strong>Vault Mode:</strong> <code>${esc(hub.mode || "standalone_local_vault")}</code>
      · <strong>Agent Hub:</strong> <code>${esc(hub.url || "not set")}</code> (${hub.reachable ? "reachable" : "offline"})
      · <strong>LNC Ads LAN Bridge:</strong> <code>${esc(br.ads_internal_url || "not set")}</code> (${hub.bridge_fallback_ready ? "ready" : (br.enabled ? "configured" : "disabled")})
      · <strong>MCP Gateway:</strong> <code>${esc(gw.gateway_url || "not set")}</code></div>
    `;
  }
  const sharedShopInput = document.getElementById("shared-oauth-shop");
  if (sharedShopInput && !sharedShopInput.value && o.shops.length) {
    const selectedShop = o.shops.find((s) => String(s.id) === String(state.shopId)) || o.shops[0];
    sharedShopInput.value = selectedShop.name;
  }

  const provider = document.getElementById("app-provider").value || "meta";
  const appCfg = o.integrations.apps[provider] || {};
  const appForm = document.getElementById("app-form");
  appForm.client_id.value = appCfg.client_id || "";
  appForm.webhook_verify_token.value = appCfg.webhook_verify_token || "";
  appForm.client_secret.value = appCfg.configured ? "********" : "";
  appForm.dataset.revision = appCfg.revision || 0;

  document.querySelector("#connections-table tbody").innerHTML = o.integrations.connections.map((c) => `
    <tr>
      <td>${c.id}</td>
      <td>${esc(c.provider)}</td>
      <td>${esc(c.label)}</td>
      <td><span class="badge ${c.state === "verified" ? "good" : "warn"}">${esc(c.state)}</span></td>
      <td>
        <button type="button" class="ghost small-btn" data-act="authorize" data-id="${c.id}">Authorize</button>
        <button type="button" class="ghost small-btn" data-act="discover" data-id="${c.id}">Discover</button>
        <button type="button" class="ghost small-btn" data-act="disconnect" data-id="${c.id}">Disconnect</button>
      </td>
    </tr>
  `).join("") || `<tr><td colspan="5" class="muted">No OAuth connections configured yet.</td></tr>`;

  document.querySelectorAll("#connections-table button").forEach((btn) => {
    btn.onclick = async () => {
      const id = Number(btn.dataset.id);
      const act = btn.dataset.act;
      try {
        if (act === "authorize") {
          const r = await api(`/api/admin/connections/${id}/authorize`, { method: "POST" });
          banner(`OAuth started: ${r.authorization_url}`);
        } else if (act === "discover") {
          const r = await api(`/api/admin/connections/${id}/discover`, { method: "POST" });
          state.discovered[id] = r.channels;
          banner(`Discovered ${r.channels.length} channels`);
        } else if (act === "disconnect") {
          await api(`/api/admin/connections/${id}/disconnect`, { method: "POST" });
          banner("Disconnected");
        }
        await refreshOverview();
      } catch (err) {
        banner(err.message, "error");
      }
    };
  });

  const rows = [...o.channels];
  Object.entries(state.discovered).forEach(([connectionId, list]) => {
    list.forEach((d) => {
      if (!rows.some((r) => r.external_id === d.external_id)) {
        rows.push({ ...d, connection_id: Number(connectionId), approved: false, reply_policy: "draft_only", auto_suggest_threshold: 80 });
      }
    });
  });

  const shopOptions = o.shops.map((s) => `<option value="${s.id}">${esc(s.name)}</option>`).join("");
  document.querySelector("#channels-table tbody").innerHTML = rows.map((ch) => `
    <tr>
      <td><strong>${esc(ch.name)}</strong><br><span class="muted small">${esc(ch.handle || ch.external_id)}</span></td>
      <td>${esc(ch.provider || "meta")}</td>
      <td>${esc(ch.kind)}</td>
      <td><code>${esc(ch.adapter || "meta_api")}</code></td>
      <td>${esc(ch.reply_policy || "draft_only")}</td>
      <td>${ch.auto_suggest_threshold || 80}</td>
      <td>${ch.approved ? `<span class="badge good">Approved</span>` : `<span class="badge warn">Pending</span>`}</td>
      <td>
        ${ch.connection_id && o.shops.length && !ch.approved ? `
          <select data-shop-for="${esc(ch.external_id)}">${shopOptions}</select>
          <button type="button" class="primary small-btn" data-approve="${esc(ch.external_id)}" data-conn="${ch.connection_id}">Approve</button>
        ` : (ch.id && ch.adapter === "meta_api" ? `<button type="button" class="ghost small-btn" data-sync-channel="${ch.id}">Sync Now</button>` : `<span class="muted small">Ready</span>`)}
      </td>
    </tr>
  `).join("") || `<tr><td colspan="8" class="muted">No channels discovered yet.</td></tr>`;

  document.querySelectorAll("[data-approve]").forEach((btn) => {
    btn.onclick = async () => {
      const ext = btn.dataset.approve;
      const connId = Number(btn.dataset.conn);
      const sel = document.querySelector(`[data-shop-for="${CSS.escape(ext)}"]`);
      await api(`/api/admin/connections/${connId}/channels/approve`, {
        method: "POST",
        body: { external_id: ext, shop_id: Number(sel.value), reply_policy: "draft_only" }
      });
      banner(`Approved channel ${ext}`);
      await refreshOverview();
    };
  });

  document.querySelectorAll("[data-sync-channel]").forEach((btn) => {
    btn.onclick = async () => {
      const cid = Number(btn.dataset.syncChannel);
      const r = await api(`/api/admin/channels/${cid}/sync`, { method: "POST" });
      banner(`Synced ${r.posts} posts & ${r.comments} comments`);
      await refreshOverview();
    };
  });
}

async function loadRules() {
  const data = await api("/api/admin/rules");
  document.querySelector("#rules-table tbody").innerHTML = (data.rules || []).map((r) => `
    <tr>
      <td><strong>${esc(r.name)}</strong></td>
      <td><code>${esc(r.match_kind)}</code></td>
      <td><code>${esc(r.pattern)}</code></td>
      <td><span class="badge">${esc(r.auto_bucket)}</span></td>
      <td>${esc(r.auto_status)}</td>
    </tr>
  `).join("") || `<tr><td colspan="5" class="muted">No custom rules yet.</td></tr>`;
}

async function loadConnector() {
  const c = await api("/api/admin/connector");
  document.getElementById("connector-details").innerHTML = `
    <p><strong>Audience:</strong> <code>${esc(c.audience)}</code> · <strong>Namespace:</strong> <code>${esc(c.namespace)}</code> · <strong>Endpoint:</strong> <code>${esc(c.endpoint || "/mcp")}</code></p>
    <p><strong>Bearer configured:</strong> ${c.bearer_configured} · <strong>Delegation secret configured:</strong> ${c.delegation_secret_configured} · <strong>Require delegation:</strong> ${c.require_delegation}</p>
    <p><strong>Max scopes:</strong> <code>${esc(c.max_scopes.join(", "))}</code></p>
  `;
  document.querySelector("#tools-table tbody").innerHTML = Object.entries(c.tools).map(([tool, scopes]) =>
    `<tr><td><code>care__${esc(tool)}</code></td><td><code>${esc(scopes.join(", "))}</code></td></tr>`
  ).join("");
}

async function loadAudit() {
  const a = await api("/api/admin/audit");
  const badge = document.getElementById("audit-verify");
  badge.textContent = a.valid ? `Chain verified (${a.checked} events)` : `Chain broken at #${a.broken_sequence}`;
  badge.className = `badge ${a.valid ? "good" : "bad"}`;
  document.querySelector("#audit-table tbody").innerHTML = a.events.map((e) => `
    <tr>
      <td>${e.sequence}</td>
      <td><code>${esc(e.created_at)}</code></td>
      <td>${esc(e.actor)}</td>
      <td><code>${esc(e.action)}</code></td>
      <td>${esc(e.subject)}</td>
      <td><code>${esc(JSON.stringify(e.details))}</code></td>
    </tr>
  `).join("");
}

async function loadSettings() {
  const s = await api("/api/settings");
  const form = document.getElementById("settings-form");
  form.public_base_url.value = s.values.public_base_url;
  form.allowed_hosts.value = s.values.allowed_hosts.join(", ");
  form.mcp_max_scopes.value = s.values.mcp_max_scopes.join(", ");
  form.archive_retention_days.value = s.values.archive_retention_days;
  Object.entries(s.sources).forEach(([k, src]) => {
    const el = document.getElementById(`src-${k}`);
    if (el) el.textContent = `(${src})`;
  });
}

async function refreshOverview() {
  const q = state.shopId ? `?shop_id=${encodeURIComponent(state.shopId)}` : "";
  state.overview = await api(`/api/admin/overview${q}`);
  renderOverview();
}

async function triggerSeedDemo() {
  const res = await api("/api/admin/seed-demo", { method: "POST" });
  banner(`Loaded Demo Workspace (${res.channels} channels, ${res.comments} evaluated comments, Evidence Vault & Fleet)`);
  await refreshOverview();
  await loadInbox();
}

window.addEventListener("hashchange", setView);

// Keyboard shortcuts 1 / 2 / 3 in Triage Inbox when not typing in inputs
window.addEventListener("keydown", (ev) => {
  if (["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName)) return;
  const view = (location.hash || "#inbox").slice(1) || "inbox";
  if (view !== "inbox" || !state.selectedCommentId) return;
  if (["1", "2", "3"].includes(ev.key)) {
    const btn = document.querySelector(`[data-decision="${ev.key}"]`);
    if (btn) btn.click();
  }
});

document.getElementById("theme-toggle").onclick = () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  localStorage.setItem("lnc-care-theme", next);
};

document.getElementById("seed-demo-btn").onclick = () => {
  triggerSeedDemo().catch((e) => banner(e.message, "error"));
};

document.getElementById("logout").onclick = async () => {
  await api("/api/auth/logout", { method: "POST" });
  location.replace("/login.html");
};

document.getElementById("shop-select").onchange = async (e) => {
  state.shopId = e.target.value || null;
  await refreshOverview();
  setView();
};

document.getElementById("inbox-channel-filter").onchange = (e) => {
  state.selectedChannelId = e.target.value || "";
  loadInbox().catch((err) => banner(err.message, "error"));
};

document.getElementById("inbox-search").oninput = (e) => {
  state.searchQuery = e.target.value.trim();
  clearTimeout(state._searchTimer);
  state._searchTimer = setTimeout(() => {
    loadInbox().catch((err) => banner(err.message, "error"));
  }, 220);
};

document.getElementById("app-provider").onchange = renderChannelsView;

document.getElementById("shop-form").onsubmit = async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  await api("/api/admin/shops", { method: "POST", body: { name: fd.get("name") } });
  e.target.reset();
  banner("Shop created");
  await refreshOverview();
};

document.getElementById("evidence-form").onsubmit = async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const cmId = fd.get("comment_id");
  const res = await api("/api/admin/evidence/capture", {
    method: "POST",
    body: {
      title: fd.get("title"),
      target_url: fd.get("target_url"),
      comment_id: cmId ? Number(cmId) : null
    }
  });
  e.target.reset();
  banner(`Sealed Forensic Case #${res.case_id} (SHA-256: ${res.manifest_sha256.slice(0, 12)}...)`);
  await loadEvidence();
  await refreshOverview();
};

document.getElementById("fleet-form").onsubmit = async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  await api("/api/admin/fleet", {
    method: "POST",
    body: {
      label: fd.get("label"),
      platform: fd.get("platform"),
      account_role: fd.get("account_role"),
      adapter: fd.get("adapter"),
      runtime_profile_id: fd.get("runtime_profile_id"),
      expected_exit_ip: fd.get("expected_exit_ip")
    }
  });
  e.target.reset();
  banner("Saved account runtime profile");
  await loadFleet();
  await refreshOverview();
};

document.getElementById("app-form").onsubmit = async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const provider = fd.get("provider");
  try {
    await api(`/api/admin/integrations/${provider}`, {
      method: "POST",
      body: {
        client_id: fd.get("client_id"),
        client_secret: fd.get("client_secret"),
        webhook_verify_token: fd.get("webhook_verify_token"),
        confirm_replace: fd.get("confirm_replace") === "on",
        revision: Number(e.target.dataset.revision || 0)
      }
    });
    banner(`Saved ${provider} credentials`);
    await refreshOverview();
  } catch (err) {
    banner(err.message, "error");
  }
};

document.getElementById("connection-form").onsubmit = async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  await api("/api/admin/connections", {
    method: "POST",
    body: { provider: fd.get("provider"), label: fd.get("label") }
  });
  e.target.reset();
  banner("Connection added");
  await refreshOverview();
};

const hubSyncBtn = document.getElementById("hub-sync-btn");
if (hubSyncBtn) {
  hubSyncBtn.onclick = async () => {
    try {
      hubSyncBtn.disabled = true;
      const res = await api("/api/admin/hub/sync", { method: "POST" });
      banner(`Synced via ${res.source}: +${res.pulled_shops} shops, +${res.pulled_connections} connections, +${res.pulled_channels || 0} channels`);
      await refreshOverview();
    } catch (err) {
      banner(err.message, "error");
    } finally {
      hubSyncBtn.disabled = false;
    }
  };
}

const sharedOauthForm = document.getElementById("shared-oauth-form");
if (sharedOauthForm) {
  sharedOauthForm.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      const res = await api("/api/admin/oauth/shared/start", {
        method: "POST",
        body: {
          provider: fd.get("provider"),
          shop: fd.get("shop"),
          label: fd.get("label")
        }
      });
      if (res.authorization_url) {
        location.assign(res.authorization_url);
      } else {
        banner("Shared OAuth started");
      }
    } catch (err) {
      banner(err.message, "error");
    }
  };
}

document.getElementById("rule-form").onsubmit = async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  await api("/api/admin/rules", {
    method: "POST",
    body: {
      name: fd.get("name"),
      pattern: fd.get("pattern"),
      match_kind: fd.get("match_kind"),
      auto_bucket: fd.get("auto_bucket")
    }
  });
  e.target.reset();
  banner("Triage rule saved");
  await loadRules();
};

document.getElementById("settings-form").onsubmit = async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  try {
    await api("/api/settings", {
      method: "POST",
      body: {
        public_base_url: fd.get("public_base_url"),
        allowed_hosts: String(fd.get("allowed_hosts")).split(",").map((s) => s.trim()).filter(Boolean),
        mcp_max_scopes: String(fd.get("mcp_max_scopes")).split(",").map((s) => s.trim()).filter(Boolean),
        archive_retention_days: Number(fd.get("archive_retention_days"))
      }
    });
    banner("Settings saved");
    await loadSettings();
  } catch (err) {
    banner(err.message, "error");
  }
};

(async () => {
  const auth = await fetch("/api/auth/status", { credentials: "same-origin" }).then((r) => r.json());
  if (!auth.authenticated) {
    location.replace("/login.html");
    return;
  }
  state.csrf = auth.csrf;
  await refreshOverview();
  setView();
})();
