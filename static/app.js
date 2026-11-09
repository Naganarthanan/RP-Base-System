"use strict";
const root = document.getElementById("app");
const dialog = document.getElementById("dialog");
let session = { user: null, csrf: null, dev_accounts: [], env: "" };

// Each registry is mounted under its own path (/conventional, /bloom); the landing
// page and security check live at the site root. BASE prefixes every API call and link.
const SYSTEMS = ["conventional", "bloom"];
const SYSTEM_LABELS = { conventional: "Conventional system", bloom: "Bloom filter system" };
const firstSegment = location.pathname.split("/")[1];
const BASE = SYSTEMS.includes(firstSegment) ? "/" + firstSegment : "";

// ---- light / dark theme ---------------------------------------------------
const THEME_ICONS = {
  // Shown icon is the mode you switch TO.
  dark: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>',
  light: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4.5"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4"/></svg>',
};
const currentTheme = () => document.documentElement.dataset.theme || "light";
function applyTheme(mode) {
  document.documentElement.dataset.theme = mode;
  const markup = mode === "dark" ? THEME_ICONS.light : THEME_ICONS.dark;
  ["theme-toggle", "theme-top"].forEach((id) => {
    const btn = document.getElementById(id);
    if (btn) {
      btn.innerHTML = markup;
      btn.title = mode === "dark" ? "Switch to light mode" : "Switch to dark mode";
    }
  });
}
function toggleTheme() {
  const mode = currentTheme() === "dark" ? "light" : "dark";
  try { localStorage.setItem("theme", mode); } catch (_) { /* private mode */ }
  applyTheme(mode);
}
function setupTheme() {
  let stored = null;
  try { stored = localStorage.getItem("theme"); } catch (_) { /* private mode */ }
  applyTheme(stored || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));
  const btn = document.getElementById("theme-toggle");
  if (btn) btn.onclick = toggleTheme;
}
setupTheme();

// ---- utilities ------------------------------------------------------------
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const dash = (v) => (v === null || v === undefined || v === "" ? "–" : esc(v));
const enc = encodeURIComponent;
const when = (iso) => (iso ? new Date(iso).toLocaleString() : "–");

async function api(path, method = "GET", body) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (session.csrf) headers["X-CSRF-Token"] = session.csrf;
  const res = await fetch(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && session.user) { session.user = null; route(); }
    throw new Error(data.error || "Something went wrong");
  }
  return data;
}

function toast(message, kind = "") {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.className = kind;
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { el.hidden = true; }, 3500);
}

function table(columns, rows, emptyText = "Nothing here yet.") {
  if (!rows.length) return `<p class="empty">${esc(emptyText)}</p>`;
  const head = columns.map((c) => `<th class="${c.num ? "num" : ""}">${esc(c.label)}</th>`).join("");
  const body = rows.map((r) => `<tr>${columns.map((c) => `<td class="${c.num ? "num" : ""}">${c.html ? c.html(r) : dash(r[c.key])}</td>`).join("")}</tr>`).join("");
  return `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}

const searchBox = (label) => `<input class="search no-print" type="search" data-search placeholder="${esc(label)}" aria-label="${esc(label)}">`;

/* Each search box filters the rows of the table in its own card. */
function bindSearch() {
  root.querySelectorAll("[data-search]").forEach((input) => {
    const card = input.closest(".card");
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = "No matches found.";
    empty.hidden = true;
    card.append(empty);
    input.oninput = () => {
      const term = input.value.trim().toLowerCase();
      let shown = 0;
      card.querySelectorAll("tbody tr").forEach((tr) => {
        const match = tr.textContent.toLowerCase().includes(term);
        tr.hidden = !match;
        if (match) shown += 1;
      });
      empty.hidden = shown > 0 || !card.querySelector("tbody");
    };
  });
}

const statusBadge = (s) => {
  const type = { active: "ok", valid: "ok", graduated: "", inactive: "warn", revoked: "bad" }[s] ?? "";
  return `<span class="badge ${type}">${esc(s)}</span>`;
};

/* Opens a form dialog. fields: [{name,label,type,value,options,required,hint}] */
function formDialog({ title, intro, fields, submit = "Save", wide = false, onSubmit }) {
  dialog.className = wide ? "wide" : "";
  const inputs = fields.map((f) => {
    const attrs = `name="${esc(f.name)}" ${f.required ? "required" : ""}`;
    let control;
    if (f.type === "select") {
      control = `<select ${attrs}>${f.options.map((o) => `<option value="${esc(o.value)}" ${String(o.value) === String(f.value ?? "") ? "selected" : ""}>${esc(o.label)}</option>`).join("")}</select>`;
    } else if (f.type === "textarea") {
      control = `<textarea ${attrs}>${esc(f.value)}</textarea>`;
    } else {
      control = `<input ${attrs} type="${esc(f.type || "text")}" value="${esc(f.value)}" ${f.extra || ""}>`;
    }
    return `<label class="field">${esc(f.label)}${control}${f.hint ? `<span class="small muted">${esc(f.hint)}</span>` : ""}</label>`;
  }).join("");
  dialog.innerHTML = `<form method="dialog">
    <h2>${esc(title)}</h2>${intro ? `<p class="muted small">${esc(intro)}</p>` : ""}
    <div class="form-grid ${wide ? "two" : ""}">${inputs}</div><p class="form-error" role="alert"></p>
    <div class="row spread"><button type="button" class="btn" data-close>Cancel</button><button class="btn primary" type="submit">${esc(submit)}</button></div></form>`;
  const form = dialog.querySelector("form");
  dialog.querySelector("[data-close]").onclick = () => dialog.close();
  form.onsubmit = async (e) => {
    e.preventDefault();
    const button = form.querySelector("[type=submit]");
    button.disabled = true;
    try {
      const keep = await onSubmit(Object.fromEntries(new FormData(form)));
      if (keep !== "keep-open") dialog.close();
    } catch (err) {
      form.querySelector(".form-error").textContent = err.message;
    } finally { button.disabled = false; }
  };
  dialog.showModal();
}

function infoDialog(title, intro, bodyHtml) {
  if (dialog.open) dialog.close();
  dialog.className = "wide";
  dialog.innerHTML = `<form method="dialog"><h2>${esc(title)}</h2>${intro ? `<p class="muted small">${esc(intro)}</p>` : ""}
    ${bodyHtml}<div class="row spread"><span></span><button class="btn primary">Close</button></div></form>`;
  dialog.showModal();
}

function showCredentials(title, username, password) {
  if (dialog.open) dialog.close();
  dialog.className = "";
  dialog.innerHTML = `<form method="dialog"><h2>${esc(title)}</h2>
    <p>Share these sign-in details securely. The password is shown only once, and the user should change it after signing in.</p>
    <div class="credentials">Username: ${esc(username)}<br>Password: ${esc(password)}</div>
    <div class="row spread"><span></span><button class="btn primary">Done</button></div></form>`;
  dialog.showModal();
}

function changePassword() {
  formDialog({
    title: "Change password", submit: "Update password",
    fields: [
      { name: "current", label: "Current password", type: "password", required: true },
      { name: "new", label: "New password", type: "password", required: true, hint: "At least 10 characters, with letters and numbers." },
    ],
    onSubmit: async (v) => {
      await api("/api/password", "POST", v);
      session.user.must_change = 0;
      toast("Password updated");
      route();
    },
  });
}

const ICONS = {
  overview: '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
  students: '<path d="M22 10 12 5 2 10l10 5 10-5Z"/><path d="M6 12v5c3 2 9 2 12 0v-5"/>',
  faculty: '<circle cx="12" cy="8" r="4"/><path d="M4 21c1-5 4-7 8-7s7 2 8 7"/>',
  courses: '<path d="M4 5a2 2 0 0 1 2-2h14v16H6a2 2 0 0 0-2 2V5Z"/><path d="M4 19a2 2 0 0 1 2-2h14"/>',
  reports: '<path d="M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8l-5-5Z"/><path d="M14 3v5h5M9 13h6M9 17h6"/>',
  certificates: '<circle cx="12" cy="9" r="6"/><path d="m8.5 14-1.5 8 5-3 5 3-1.5-8"/>',
  award: '<circle cx="12" cy="9" r="6"/><path d="m8.5 14-1.5 8 5-3 5 3-1.5-8"/>',
  chain: '<path d="M10 14a4 4 0 0 0 6 0l3-3a4 4 0 0 0-6-6l-1 1"/><path d="M14 10a4 4 0 0 0-6 0l-3 3a4 4 0 0 0 6 6l1-1"/>',
  results: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
  profile: '<circle cx="12" cy="8" r="4"/><path d="M4 21c1-5 4-7 8-7s7 2 8 7"/>',
  lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  shield: '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6l-8-3Z"/><path d="m9 12 2 2 4-4"/>',
  theme: '<circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 1 0 18Z" fill="currentColor" stroke="none"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/>',
  grid: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  chevron: '<path d="m6 9 6 6 6-6"/>',
};
const icon = (name) => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ""}</svg>`;

// ---- sign in and public verification -----------------------------------------
function renderLogin(error = "") {
  document.documentElement.classList.remove("app-shell");
  const quick = session.dev_accounts.length ? `<section class="card stack">
      <div class="row spread"><h2>Quick login</h2><span class="dev-tag">DEV ONLY</span></div>
      <div class="quick">${session.dev_accounts.map((a) => `<button class="btn" data-dev="${esc(a.username)}"><span>${esc(a.label)}</span><span class="mono">${esc(a.username)} / ${esc(a.password)}</span></button>`).join("")}</div>
    </section>` : "";
  const label = session.system_label || SYSTEM_LABELS[firstSegment] || "Academic Registry";
  root.innerHTML = `<div class="auth-split"><aside class="auth-side">
      <div class="brand"><span class="brand-mark">${icon("shield")}</span><span>CertChain<small>${esc(label)}</small></span></div>
      <h1>All university records in one secure place</h1>
      <ul class="auth-points">
        <li>${icon("lock")}<span>Every record is anchored on the chain and checked for tampering</span></li>
        <li>${icon("chain")}<span>Every change is added as a linked, signed block</span></li>
        <li>${icon("award")}<span>Certificates can be verified publicly with their ID and code</span></li>
      </ul>
    </aside><main class="auth"><div class="auth-box">
    <div class="title"><h2>Sign in</h2><p class="muted">Use your university account.</p></div>
    <form class="card stack" id="login">
      <label class="field">Username<input name="username" autocomplete="username" required autofocus></label>
      <label class="field">Password<input name="password" type="password" autocomplete="current-password" required></label>
      ${error ? `<p class="form-error" role="alert">${esc(error)}</p>` : ""}
      <button class="btn primary" type="submit">Sign in</button>
    </form>${quick}
    <div class="auth-links">
      <a class="btn" href="${BASE}/verify">${icon("award")}<span>Verify a certificate</span></a>
      <a class="btn" href="/">${icon("grid")}<span>All systems</span></a>
    </div>
  </div></main></div>`;
  root.querySelector("#login").onsubmit = async (e) => {
    e.preventDefault();
    try { session = await api("/api/login", "POST", Object.fromEntries(new FormData(e.target))); location.hash = ""; route(); }
    catch (err) { renderLogin(err.message); }
  };
  root.querySelectorAll("[data-dev]").forEach((b) => {
    b.onclick = async () => {
      try { session = await api("/api/dev-login", "POST", { username: b.dataset.dev }); location.hash = ""; route(); }
      catch (err) { renderLogin(err.message); }
    };
  });
}

function renderVerify() {
  document.documentElement.classList.remove("app-shell");
  const params = new URLSearchParams(location.hash.slice(1));
  root.innerHTML = `<main class="auth"><div class="auth-box">
    <div class="title"><h1>Verify a certificate</h1><p class="muted">Enter the ID and verification code printed on the certificate.</p></div>
    <form class="card stack" id="verify">
      <label class="field">Certificate ID<input name="id" required value="${esc(params.get("id"))}"></label>
      <label class="field">Verification code<input name="code" required value="${esc(params.get("code"))}"></label>
      <button class="btn primary" type="submit">Verify</button>
    </form>
    <div id="verify-result" aria-live="polite"></div>
    <div class="auth-links">
      <a class="btn" href="${BASE}/">${icon("logout")}<span>Back to sign in</span></a>
      <a class="btn" href="/">${icon("grid")}<span>All systems</span></a>
    </div>
  </div></main>`;
  const form = root.querySelector("#verify");
  const out = root.querySelector("#verify-result");
  form.onsubmit = async (e) => {
    e.preventDefault();
    try {
      const r = await api("/api/public/verify", "POST", Object.fromEntries(new FormData(form)));
      if (r.result === "not_found") { out.innerHTML = `<div class="card stack"><span class="row"><span class="badge bad">Not verified</span></span><p>No certificate matches this ID and code.</p></div>`; return; }
      if (r.result === "tampered") { out.innerHTML = `<div class="card stack"><span class="row"><span class="badge bad">Tampered</span></span><p>This certificate's record no longer matches its entry on the blockchain, so it cannot be trusted.</p></div>`; return; }
      const c = r.certificate;
      out.innerHTML = `<div class="card stack">${r.result === "valid" ? `<span class="row"><span class="badge ok">Verified</span></span>` : `<span class="row"><span class="badge bad">Revoked</span></span>`}
        <dl class="kv"><dt>Holder</dt><dd>${esc(c.holder)}</dd><dt>Award</dt><dd>${esc(c.title)}</dd><dt>Programme</dt><dd>${esc(c.programme)}</dd><dt>Issued</dt><dd>${esc(c.issued_on)}</dd><dt>ID</dt><dd>${esc(c.id)}</dd></dl></div>`;
    } catch (err) { out.innerHTML = `<div class="card form-error">${esc(err.message)}</div>`; }
  };
  if (params.get("id") && params.get("code")) form.requestSubmit();
}

// ---- landing page and security check -----------------------------------------
function renderLanding() {
  document.documentElement.classList.remove("app-shell");
  if (location.pathname.replace(/\/+$/, "").endsWith("/security")) { renderSecurity(); return; }
  const card = (href, ic, title, desc, tag) => `<a class="home-card" href="${href}">
      <span class="home-ic">${icon(ic)}</span>
      <span class="home-body"><strong>${esc(title)}</strong><span class="muted small">${esc(desc)}</span>
        ${tag ? `<span class="badge">${esc(tag)}</span>` : ""}</span></a>`;
  root.innerHTML = `<main class="home">
    <header class="home-head">
      <div class="brand"><span class="brand-mark">${icon("shield")}</span><span>CertChain<small>Academic Registry</small></span></div>
      <h1>A blockchain academic registry, in two designs</h1>
      <p class="muted">The same university records system, built two ways, so the two can be compared under the same attacks.</p>
    </header>
    <div class="home-grid">
      ${card("/conventional/", "chain", "Conventional system", "Records anchored on-chain with plain SHA-256 hashing.", "Hashing")}
      ${card("/bloom/", "lock", "Bloom filter system", "Records anchored with keyed Bloom filters over hashing.", "Hashing + Bloom filter")}
      ${card("/security", "shield", "Security check", "Run the manipulation and inference checks across both systems. No sign-in needed.", "")}
    </div>
    <p class="small muted home-foot">Each system has its own sign-in. Use the quick-login buttons in development.</p>
  </main>`;
}

// The two checks, each with its attack and defence strategies. Strategies are UI
// scaffolding: each is a separate component to be wired to its own backend later.
const SECURITY = {
  manipulation: {
    title: "Manipulation", icon: "chain",
    question: "Can a forged record be made to pass on-chain verification?",
    target: "conventional", targetLabel: "Conventional system",
    attacks: [
      { id: "asset", name: "Asset substitution", desc: "Swap the logo, seal or signature on a certificate." },
      { id: "field", name: "Field rewrite", desc: "Edit a record field and recompute its hash." },
      { id: "node", name: "Node copy rewrite", desc: "A compromised organisation rewrites its own chain copy." },
      { id: "qr", name: "QR / metadata swap", desc: "Repoint the QR code or alter the file metadata." },
    ],
    defenses: [
      { id: "vertical", name: "Vertical partitioning", desc: "Split anchors across linked blocks (inter-block)." },
      { id: "forensic", name: "OCR / forensic asset check", desc: "Verify the logo, seal and signature images." },
      { id: "consensus", name: "Consensus threshold", desc: "Require more nodes to agree before accepting." },
      { id: "keyed", name: "Keyed anchor (HMAC)", desc: "Sign each anchor with a secret key." },
    ],
  },
  inference: {
    title: "Inference", icon: "lock",
    question: "Can someone holding the chain confirm a guessed value without the key?",
    target: "bloom", targetLabel: "Bloom filter system",
    attacks: [
      { id: "collusion", name: "Collusion among organisations", desc: "Node organisations pool their key shares to reconstruct the Bloom key.", live: true },
      { id: "dictionary", name: "Dictionary attack", desc: "Hash candidate values and match them to the chain." },
      { id: "fieldmatch", name: "Per-field match leak", desc: "Read which field differs from a verify response." },
      { id: "frequency", name: "Frequency analysis", desc: "Count repeated hashes to rank likely values." },
      { id: "rainbow", name: "Rainbow table", desc: "Look up precomputed hashes of common values." },
    ],
    defenses: [
      { id: "keyedbloom", name: "Keyed Bloom filter", desc: "Derive bit positions from HMAC under a secret key." },
      { id: "salt", name: "Salted hashing", desc: "Add a per-record salt before hashing each field." },
      { id: "horizontal", name: "Horizontal partitioning", desc: "Split fields across records (intra-block)." },
      { id: "padding", name: "Field padding / k-anonymity", desc: "Pad the filter so field counts do not leak." },
    ],
  },
};

let securityTab = "manipulation";

function picklist(kind, items) {
  return items.map((s) => `<label class="pick">
      <input type="checkbox" data-kind="${kind}" value="${esc(s.id)}">
      <span class="pick-body"><strong>${esc(s.name)}</strong><span class="small muted">${esc(s.desc)}</span></span></label>`).join("");
}

function renderSecurity() {
  document.documentElement.classList.remove("app-shell");
  const c = SECURITY[securityTab];
  const tabs = Object.entries(SECURITY).map(([key, v]) =>
    `<button class="seg-btn ${key === securityTab ? "active" : ""}" data-tab="${key}">${icon(v.icon)}<span>${esc(v.title)}</span></button>`).join("");
  root.innerHTML = `<main class="home security">
    <header class="home-head">
      <a class="btn back-btn" href="/">${icon("grid")}<span>All systems</span></a>
      <h1>Security check</h1>
      <p class="muted">Pick a check, then choose attack and defence strategies and run. Run with no defence selected first to see the system as it is. Nothing here recovers real personal details.</p>
    </header>
    <div class="seg" role="tablist">${tabs}</div>
    <section class="card stack">
      <div class="row spread"><div><h2>${esc(c.title)}</h2><p class="small muted">${esc(c.question)}</p></div>
        <span class="badge">Analysed on the ${esc(c.targetLabel)}</span></div>
      <div class="panes">
        <div class="pane attack"><div class="pane-head"><h3>Attack strategies</h3><span class="tag-red">Red team</span></div>${picklist("attack", c.attacks)}</div>
        <div class="pane defense"><div class="pane-head"><h3>Defence strategies</h3><span class="tag-green">Blue team</span></div>${picklist("defense", c.defenses)}</div>
      </div>
      <div class="row spread">
        <span class="small muted" id="sec-summary">No defence selected — baseline run.</span>
        <button class="btn primary" id="sec-run">Run ${esc(c.title.toLowerCase())} check</button>
      </div>
    </section>
    <section id="sec-out" class="stack" aria-live="polite"></section>
  </main>`;

  const out = root.querySelector("#sec-out");
  const summary = root.querySelector("#sec-summary");
  const picked = (kind) => [...root.querySelectorAll(`input[data-kind="${kind}"]:checked`)];
  const nameOf = (kind, id) => (kind === "attack" ? c.attacks : c.defenses).find((s) => s.id === id).name;

  const updateSummary = () => {
    const d = picked("defense").map((i) => i.value);
    summary.textContent = d.length
      ? `${d.length} defence${d.length === 1 ? "" : "s"} selected — scaffold run.`
      : "No defence selected — baseline run.";
  };
  root.querySelectorAll('input[type="checkbox"]').forEach((i) => { i.onchange = updateSummary; });

  root.querySelectorAll("[data-tab]").forEach((b) => {
    b.onclick = () => { securityTab = b.dataset.tab; renderSecurity(); };
  });

  root.querySelector("#sec-run").onclick = async (e) => {
    const button = e.currentTarget;
    const attacks = picked("attack").map((i) => i.value);
    const defenses = picked("defense").map((i) => i.value);
    const chips = (kind, ids) => ids.length
      ? ids.map((id) => `<span class="badge">${esc(nameOf(kind, id))}</span>`).join(" ")
      : `<span class="small muted">none</span>`;
    const selection = `<div class="card stack"><div class="row spread"><h3>${esc(c.title)} run · ${esc(c.targetLabel)}</h3></div>
      <div class="sel-row"><span class="small muted">Attack</span><div class="row">${chips("attack", attacks)}</div></div>
      <div class="sel-row"><span class="small muted">Defence</span><div class="row">${chips("defense", defenses)}</div></div></div>`;

    if (defenses.length) {
      // Defences are not wired to a backend yet: show the selection as a scaffold.
      out.innerHTML = selection + `<div class="card stack"><div class="row"><span class="badge warn">Not connected yet</span></div>
        <p>These strategies are placeholder components. Connect each one to its backend and return its result here. The baseline (no defence) run already works below.</p></div>`;
      out.scrollIntoView({ behavior: "smooth", block: "nearest" });
      return;
    }

    // Collusion inference attack: live component, Bloom filter system only.
    if (securityTab === "inference" && attacks.includes("collusion")) {
      button.disabled = true;
      const original = button.textContent;
      button.textContent = "Running…";
      try {
        const data = await api("/api/security/collusion", "POST", {});
        const matrix = data.matrix.map((m) => `<tr>
            <td>${m.colluding} of ${data.nodes}</td>
            <td>${m.key_reconstructed ? `<span class="badge bad">Reconstructed</span>` : `<span class="badge ok">Safe</span>`}</td>
            <td class="num">${m.blocks_exposed} / ${data.total_blocks}</td></tr>`).join("");
        out.innerHTML = selection + `<div class="card stack"><div class="row spread"><h3>Collusion attack · ${esc(c.targetLabel)}</h3><span class="badge bad">${data.blocks_exposed} of ${data.total_blocks} blocks exposed</span></div>
          <p class="small muted">${esc(data.scenario)} The key is reconstructed once ${data.threshold} of ${data.nodes} organisations collude.</p>
          <div class="table-wrap"><table><thead><tr><th>Colluding organisations</th><th>Bloom key</th><th class="num">Blocks exposed</th></tr></thead><tbody>${matrix}</tbody></table></div></div>
          <div class="card"><strong>Conclusion.</strong> ${esc(data.conclusion)}</div>`;
        out.scrollIntoView({ behavior: "smooth", block: "nearest" });
      } catch (err) {
        out.innerHTML = `<div class="card form-error">${esc(err.message)}</div>`;
      } finally { button.disabled = false; button.textContent = original; }
      return;
    }

    button.disabled = true;
    const original = button.textContent;
    button.textContent = "Running…";
    try {
      const data = await api(`/api/security/${securityTab}`, "POST", {});
      const row = data.rows.find((r) => r.system === c.target) || data.rows[0];
      const kind = { resisted: "ok", resists: "ok", vulnerable: "bad", leaks: "bad" }[row.verdict] || "";
      out.innerHTML = selection + `<div class="card stack"><div class="row spread"><h3>Baseline result · ${esc(c.targetLabel)}</h3><span class="badge ${kind}">${esc(row.verdict)}</span></div>
        <p class="small muted">${esc(data.scenario)}</p>
        ${securityTab === "inference" ? `<p class="small muted">Confirmed ${row.confirmed} of ${row.guesses} guesses without the key.</p>` : ""}
        <p>${esc(row.detail)}</p></div>
        <div class="card"><strong>Conclusion.</strong> ${esc(data.conclusion)}</div>`;
      out.scrollIntoView({ behavior: "smooth", block: "nearest" });
    } catch (err) {
      out.innerHTML = `<div class="card form-error">${esc(err.message)}</div>`;
    } finally { button.disabled = false; button.textContent = original; }
  };
}

// ---- application shell -----------------------------------------------------
const NAV = {
  admin: [["overview", "Overview"], ["students", "Students"], ["faculty", "Faculty"], ["courses", "Courses"], ["reports", "Reports"], ["certificates", "Certificates"], ["chain", "Blockchain"]],
  faculty: [["overview", "Overview"], ["courses", "My courses"], ["reports", "Reports"], ["profile", "My profile"]],
  student: [["overview", "Overview"], ["results", "Results"], ["reports", "Reports"], ["certificates", "Certificates"], ["profile", "My profile"]],
};

function shell(page, content) {
  document.documentElement.classList.add("app-shell");
  const u = session.user;
  const items = NAV[u.role].map(([key, label]) => `<a href="#/${key}" class="${page === key ? "active" : ""}" ${page === key ? 'aria-current="page"' : ""}>${icon(key)}<span>${esc(label)}</span></a>`).join("");
  const section = (NAV[u.role].find(([k]) => k === page) || [])[1] || (page ? page[0].toUpperCase() + page.slice(1) : "");
  root.innerHTML = `<div class="shell">
    <aside class="sidebar"><div class="brand"><span class="brand-mark">${icon("shield")}</span><span>CertChain<small>${esc(session.system_label || "Academic Registry")}</small></span></div>
      <nav class="nav" aria-label="Main">${items}</nav>
    </aside>
    <div class="content">
      <header class="topbar">
        <span class="crumb">${esc(section || "")}</span>
        <div class="topbar-right">
          <button class="icon-btn" id="theme-top" type="button" aria-label="Switch theme" title="Switch theme"></button>
          <div class="usermenu" id="usermenu">
            <button class="usermenu-btn" id="usermenu-btn" aria-haspopup="true" aria-expanded="false">
              <span class="avatar sm">${esc(u.username.slice(0, 1))}</span>
              <span class="um-meta"><strong title="${esc(u.username)}">${esc(u.username)}</strong><span class="role-tag">${esc(u.role)}</span></span>
              ${icon("chevron")}
            </button>
            <div class="menu" role="menu">
              <a class="menu-item" href="#/profile" id="to-profile" role="menuitem">${icon("profile")}<span>Profile</span></a>
              <a class="menu-item" href="/" role="menuitem">${icon("grid")}<span>All systems</span></a>
              <button class="menu-item" id="logout" role="menuitem">${icon("logout")}<span>Sign out</span></button>
            </div>
          </div>
        </div>
      </header>
      <main class="main" id="main">${u.must_change ? `<div class="banner"><span>You are using a temporary password.</span><button class="btn small" id="pw-banner">Change password</button></div>` : ""}${content}</main>
    </div>
  </div>`;

  const menu = root.querySelector("#usermenu");
  const menuBtn = root.querySelector("#usermenu-btn");
  const setOpen = (open) => { menu.classList.toggle("open", open); menuBtn.setAttribute("aria-expanded", String(open)); };
  menuBtn.onclick = (e) => { e.stopPropagation(); setOpen(!menu.classList.contains("open")); };
  if (shell._closeMenu) document.removeEventListener("click", shell._closeMenu);
  shell._closeMenu = (e) => { const m = document.querySelector("#usermenu"); if (m && !m.contains(e.target)) m.classList.remove("open"); };
  document.addEventListener("click", shell._closeMenu);

  root.querySelector("#theme-top").onclick = toggleTheme;
  applyTheme(currentTheme());  // paint the header toggle's icon for this render
  root.querySelector("#to-profile").onclick = () => setOpen(false);
  const bannerButton = root.querySelector("#pw-banner");
  if (bannerButton) bannerButton.onclick = changePassword;
  const nav = root.querySelector(".nav");
  const activeLink = nav.querySelector(".active");
  if (activeLink) nav.scrollLeft = activeLink.offsetLeft - nav.offsetLeft - 16;
  bindSearch();
  root.querySelector("#logout").onclick = async () => {
    setOpen(false);
    await api("/api/logout", "POST", {});
    clearTimeout(toast.timer);
    document.getElementById("toast").hidden = true;
    session = await api("/api/session");
    location.hash = "";
    route();
  };
}

const pageHead = (title, sub, actions = "") => `<div class="row spread"><div><h1>${esc(title)}</h1>${sub ? `<p class="muted">${esc(sub)}</p>` : ""}</div><div class="row no-print">${actions}</div></div>`;
const statCard = (value, label, href) => (href
  ? `<a class="card stat" href="${esc(href)}"><strong>${dash(value)}</strong><span>${esc(label)}</span></a>`
  : `<div class="card stat"><strong>${dash(value)}</strong><span>${esc(label)}</span></div>`);
const backLink = (href, label) => `<a class="back" href="${esc(href)}">← ${esc(label)}</a>`;

// ---- shared result views -----------------------------------------------------
function resultsTable(courses) {
  return table([
    { label: "Code", key: "code" }, { label: "Course", key: "title" }, { label: "Semester", key: "semester" },
    { label: "Credits", key: "credits", num: true }, { label: "Coursework", key: "coursework", num: true },
    { label: "Exam", key: "exam", num: true }, { label: "Total", key: "total", num: true },
    { label: "Grade", html: (r) => (r.grade ? `<span class="badge">${esc(r.grade)}</span>` : `<span class="muted small">Pending</span>`) },
  ], courses, "No courses yet.");
}

const reportsList = (reports) => (reports.length ? reports.map((r) => `<article class="card stack">
    <div class="row spread"><h3>${esc(r.title)}</h3><span class="small muted">${esc(r.semester)} · ${esc(when(r.at))}</span></div>
    ${r.student_name ? `<p class="small muted">${esc(r.student_name)} (${esc(r.student_id)})</p>` : ""}
    <p>${esc(r.body)}</p><p class="small muted">Written by ${esc(r.by)}</p></article>`).join("") : `<p class="empty">No reports yet.</p>`);

function certTable(certs, withStudent) {
  const cols = [{ label: "ID", key: "id" }];
  if (withStudent) cols.push({ label: "Student", key: "student_name" });
  cols.push({ label: "Award", key: "title" }, { label: "Issued", key: "issued_on" }, { label: "Status", html: (c) => statusBadge(c.status) },
    { label: "", html: (c) => `<div class="row"><a class="btn small" href="#/certificate/${enc(c.id)}">View</a>${withStudent && c.status === "valid" ? `<button class="btn small danger" data-revoke="${esc(c.id)}">Revoke</button>` : ""}</div>` });
  return table(cols, certs, "No certificates yet.");
}

// ---- pages ---------------------------------------------------------------------
const CHAIN_PAGE = 15;
let chainOffset = 0;

const pages = {
  async overview() {
    const role = session.user.role;
    const d = await api("/api/dashboard");
    if (role === "admin") {
      shell("overview", `${pageHead("University overview", "Live totals from the blockchain.")}
        ${d.chain.healthy ? "" : `<div class="banner bad">A blockchain node has failed its integrity check. <a href="#/chain">Review it</a>.</div>`}
        <div class="stats">${statCard(d.students, "Students", "#/students")}${statCard(d.faculty, "Faculty", "#/faculty")}${statCard(d.courses, "Courses", "#/courses")}${statCard(d.marks, "Results recorded")}${statCard(d.certificates, "Certificates", "#/certificates")}${statCard(d.chain.height, "Blocks on chain", "#/chain")}</div>
        <section class="card row spread"><div><h2>Blockchain status</h2><p class="muted">${d.chain.nodes} nodes each hold a full copy of the chain of anchors.</p></div>
        ${d.chain.healthy ? `<span class="badge ok">All nodes in consensus</span>` : `<span class="badge bad">Attention needed</span>`}</section>`);
    } else if (role === "faculty") {
      const rows = d.courses;
      shell("overview", `${pageHead(`Welcome, ${d.profile.name}`, `${d.profile.title}, ${d.profile.department}`)}
        <div class="stats">${statCard(rows.length, "Courses")}${statCard(rows.reduce((n, c) => n + c.enrolled, 0), "Enrolments")}${statCard(rows.reduce((n, c) => n + c.enrolled - c.marked, 0), "Marks pending")}</div>
        <section class="card stack"><h2>My courses</h2>${table([
          { label: "Code", html: (c) => `<a href="#/course/${enc(c.code)}">${esc(c.code)}</a>` }, { label: "Course", key: "title" }, { label: "Semester", key: "semester" },
          { label: "Enrolled", key: "enrolled", num: true }, { label: "Marked", key: "marked", num: true }], rows, "No courses are assigned to you.")}</section>`);
    } else {
      shell("overview", `${pageHead(`Welcome, ${d.student.name}`, `${d.student.id} · ${d.student.programme}`)}
        <div class="stats">${statCard(d.gpa, "GPA")}${statCard(d.credits_earned, "Credits earned")}${statCard(d.courses.length, "Courses")}${statCard(d.certificates.length, "Certificates")}</div>
        <section class="card stack"><h2>Results</h2>${resultsTable(d.courses)}</section>`);
    }
  },

  async students() {
    const rows = await api("/api/students");
    shell("students", `${pageHead("Students", `${rows.length} records`, `<button class="btn primary" id="add">Add student</button>`)}
      <section class="card stack">${searchBox("Search by name, ID or programme")}${table([
        { label: "ID", html: (s) => `<a href="#/student/${enc(s.id)}">${esc(s.id)}</a>` }, { label: "Name", key: "name" }, { label: "Programme", key: "programme" },
        { label: "Courses", key: "courses", num: true }, { label: "GPA", key: "gpa", num: true }, { label: "Status", html: (s) => statusBadge(s.status) }], rows)}</section>`);
    root.querySelector("#add").onclick = () => studentForm();
  },

  async student(id) {
    const r = await api(`/api/students/${enc(id)}/record`);
    const s = r.student;
    shell("students", `${backLink("#/students", "All students")}${pageHead(s.name, `${s.id} · ${s.programme}`, `<button class="btn" id="edit">Edit</button><button class="btn" id="enrol">Enrol</button><button class="btn" id="report">Add report</button><button class="btn primary" id="cert">Issue certificate</button>`)}
      <div class="grid-2">
        <section class="card stack"><h2>Personal details</h2><dl class="kv"><dt>Status</dt><dd>${statusBadge(s.status)}</dd><dt>Email</dt><dd>${dash(s.email)}</dd><dt>Phone</dt><dd>${dash(s.phone)}</dd><dt>NIC</dt><dd>${dash(s.nic)}</dd><dt>Date of birth</dt><dd>${dash(s.dob)}</dd><dt>Address</dt><dd>${dash(s.address)}</dd><dt>Intake</dt><dd>${dash(s.intake)}</dd></dl></section>
        <div class="stats">${statCard(r.gpa, "GPA")}${statCard(r.credits_earned, "Credits earned")}</div>
      </div>
      <section class="card stack"><h2>Results</h2>${resultsTable(r.courses)}</section>
      <section class="card stack"><h2>Certificates</h2>${certTable(r.certificates.map((c) => ({ ...c, student_name: s.name })), true)}</section>
      <section class="stack"><h2>Reports</h2>${reportsList(r.reports)}</section>`);
    root.querySelector("#edit").onclick = () => studentForm(s);
    root.querySelector("#enrol").onclick = async () => {
      const courses = await api("/api/courses");
      const taken = new Set(r.courses.map((c) => c.code));
      const open = courses.filter((c) => !taken.has(c.code));
      if (!open.length) { toast("This student is already enrolled in every course"); return; }
      formDialog({
        title: `Enrol ${s.name}`, submit: "Enrol",
        fields: [{ name: "course_code", label: "Course", type: "select", required: true, options: open.map((c) => ({ value: c.code, label: `${c.code} – ${c.title}` })) }],
        onSubmit: async (v) => { await api("/api/enrollments", "POST", { student_id: s.id, ...v }); toast("Enrolment added to the blockchain"); route(); },
      });
    };
    root.querySelector("#report").onclick = () => reportForm(s.id);
    root.querySelector("#cert").onclick = () => formDialog({
      title: `Issue certificate to ${s.name}`, submit: "Issue certificate",
      fields: [{ name: "title", label: "Award title", required: true }, { name: "issued_on", label: "Issue date", type: "date", value: new Date().toISOString().slice(0, 10) }],
      onSubmit: async (v) => { await api("/api/certificates", "POST", { student_id: s.id, ...v }); toast("Certificate issued on the blockchain"); route(); },
    });
    bindRevoke();
  },

  async faculty() {
    const rows = await api("/api/faculty");
    shell("faculty", `${pageHead("Faculty", `${rows.length} members`, `<button class="btn primary" id="add">Add faculty member</button>`)}
      <section class="card stack">${searchBox("Search faculty")}${table([
        { label: "ID", key: "id" }, { label: "Name", key: "name" }, { label: "Title", key: "title" }, { label: "Department", key: "department" }, { label: "Email", key: "email" },
        { label: "Courses", key: "courses", num: true }, { label: "Status", html: (f) => statusBadge(f.status) },
        { label: "", html: (f) => `<button class="btn small" data-edit="${esc(f.id)}">Edit</button>` }], rows)}</section>`);
    root.querySelector("#add").onclick = () => facultyForm();
    root.querySelectorAll("[data-edit]").forEach((b) => { b.onclick = () => facultyForm(rows.find((f) => f.id === b.dataset.edit)); });
  },

  async courses() {
    const admin = session.user.role === "admin";
    const rows = await api("/api/courses");
    shell("courses", `${pageHead(admin ? "Courses" : "My courses", `${rows.length} courses`, admin ? `<button class="btn primary" id="add">Add course</button>` : "")}
      <section class="card stack">${searchBox("Search courses")}${table([
        { label: "Code", html: (c) => `<a href="#/course/${enc(c.code)}">${esc(c.code)}</a>` }, { label: "Title", key: "title" }, { label: "Semester", key: "semester" },
        { label: "Credits", key: "credits", num: true }, { label: "Lecturer", key: "lecturer" }, { label: "Enrolled", key: "enrolled", num: true }, { label: "Marked", key: "marked", num: true },
        ...(admin ? [{ label: "", html: (c) => `<button class="btn small" data-edit="${esc(c.code)}">Edit</button>` }] : [])], rows)}</section>`);
    if (admin) {
      root.querySelector("#add").onclick = () => courseForm();
      root.querySelectorAll("[data-edit]").forEach((b) => { b.onclick = () => courseForm(rows.find((c) => c.code === b.dataset.edit)); });
    }
  },

  async course(code) {
    const d = await api(`/api/courses/${enc(code)}/roster`);
    const c = d.course;
    const rows = d.rows.map((r) => ({ ...r, id: r.student.id }));
    const inputAttrs = 'type="number" min="0" max="100" step="0.5"';
    const pending = '<span class="muted small">Pending</span>';
    shell("courses", `${backLink("#/courses", "Back to courses")}${pageHead(`${c.code} ${c.title}`, `${c.semester} · ${c.credits} credits · ${c.lecturer || "No lecturer assigned"}`, rows.length ? `<button class="btn primary" id="save-marks" disabled>Save changes</button>` : "")}
      <section class="card stack"><div class="row spread"><div><h2>Marks</h2><p class="small muted">Total = coursework ${Math.round(d.weights.coursework * 100)}% + exam ${Math.round(d.weights.exam * 100)}%. Each saved result adds a block, and earlier marks stay on the chain as history.</p></div>${searchBox("Search students")}</div>
      ${table([
        { label: "Student", html: (r) => `${esc(r.student.name)}<div class="small muted">${esc(r.student.id)}</div>` },
        { label: "Coursework", num: true, html: (r) => `<input aria-label="Coursework for ${esc(r.student.name)}" ${inputAttrs} data-cw data-orig="${esc(r.coursework)}" value="${esc(r.coursework)}">` },
        { label: "Exam", num: true, html: (r) => `<input aria-label="Exam for ${esc(r.student.name)}" ${inputAttrs} data-ex data-orig="${esc(r.exam)}" value="${esc(r.exam)}">` },
        { label: "Total", num: true, html: (r) => `<span data-total>${dash(r.total)}</span>` },
        { label: "Grade", html: (r) => `<span data-grade>${r.grade ? `<span class="badge">${esc(r.grade)}</span>` : pending}</span>` },
        { label: "Versions", num: true, html: (r) => esc(r.history.length) },
        { label: "", html: (r) => (session.user.role === "faculty" ? `<button class="btn small" data-report="${esc(r.id)}">Add report</button>` : `<a class="btn small" href="#/student/${enc(r.id)}">Open</a>`) }], rows, "No students are enrolled yet.")}</section>`);
    root.querySelectorAll("tbody tr").forEach((tr, i) => { tr.dataset.student = rows[i].id; });

    const dirtyRows = () => [...root.querySelectorAll("tbody tr.dirty")];
    const refresh = () => {
      const button = root.querySelector("#save-marks");
      if (!button) return;
      const n = dirtyRows().length;
      button.disabled = n === 0;
      button.textContent = n ? `Save ${n} ${n === 1 ? "change" : "changes"}` : "Save changes";
    };
    const preview = (tr) => {
      const cw = tr.querySelector("[data-cw]");
      const ex = tr.querySelector("[data-ex]");
      tr.classList.toggle("dirty", cw.value !== cw.dataset.orig || ex.value !== ex.dataset.orig);
      const inRange = (v) => v !== "" && Number(v) >= 0 && Number(v) <= 100;
      if (inRange(cw.value) && inRange(ex.value)) {
        const total = Number(cw.value) * d.weights.coursework + Number(ex.value) * d.weights.exam;
        const band = d.scale.find((s) => total >= s.from);
        tr.querySelector("[data-total]").textContent = total.toFixed(1);
        tr.querySelector("[data-grade]").innerHTML = `<span class="badge">${esc(band.grade)}</span>`;
      } else {
        tr.querySelector("[data-total]").textContent = "–";
        tr.querySelector("[data-grade]").innerHTML = pending;
      }
      refresh();
    };
    root.querySelectorAll("[data-cw], [data-ex]").forEach((input) => {
      input.oninput = () => preview(input.closest("tr"));
    });
    const saveButton = root.querySelector("#save-marks");
    if (saveButton) saveButton.onclick = async () => {
      saveButton.disabled = true;
      let saved = 0;
      for (const tr of dirtyRows()) {
        const cw = tr.querySelector("[data-cw]");
        const ex = tr.querySelector("[data-ex]");
        try {
          await api("/api/marks", "PUT", { student_id: tr.dataset.student, course_code: code, coursework: cw.value, exam: ex.value });
          cw.dataset.orig = cw.value;
          ex.dataset.orig = ex.value;
          tr.classList.remove("dirty");
          saved += 1;
        } catch (err) {
          const prefix = saved ? `${saved} saved. ` : "";
          toast(`${prefix}${tr.dataset.student}: ${err.message}`, "error");
          refresh();
          return;
        }
      }
      toast(`${saved} ${saved === 1 ? "result" : "results"} saved to the blockchain`);
      route();
    };
    root.querySelectorAll("[data-report]").forEach((b) => { b.onclick = () => reportForm(b.dataset.report); });
  },

  async reports() {
    if (session.user.role === "student") {
      const d = await api("/api/dashboard");
      shell("reports", `${pageHead("My reports")}${reportsList(d.reports)}`);
      return;
    }
    const rows = await api("/api/reports");
    shell("reports", `${pageHead("Reports", `${rows.length} reports`)}${reportsList(rows)}`);
  },

  async results() {
    const d = await api("/api/dashboard");
    shell("results", `${pageHead("Academic transcript", `${d.student.name} · ${d.student.id}`, `<button class="btn" id="print">Print</button>`)}
      <div class="stats">${statCard(d.gpa, "GPA")}${statCard(d.credits_earned, "Credits earned")}</div>
      <section class="card">${resultsTable(d.courses)}</section>`);
    root.querySelector("#print").onclick = () => window.print();
  },

  async certificates() {
    if (session.user.role === "student") {
      const d = await api("/api/dashboard");
      shell("certificates", `${pageHead("My certificates")}<section class="card">${certTable(d.certificates, false)}</section>`);
      return;
    }
    const rows = await api("/api/certificates");
    shell("certificates", `${pageHead("Certificates", `${rows.length} issued. Issue a new one from a student's page.`)}<section class="card stack">${searchBox("Search certificates")}${certTable(rows, true)}</section>`);
    bindRevoke();
  },

  async certificate(id) {
    const c = await api(`/api/certificates/${enc(id)}`);
    shell("certificates", `${backLink("#/certificates", "All certificates")}${pageHead("Certificate", c.id, `<a class="btn" href="${BASE}/verify#id=${enc(c.id)}&code=${enc(c.code)}">Open public check</a><button class="btn" id="print">Print</button>`)}
      ${c.status === "revoked" ? `<div class="banner bad">Revoked: ${esc(c.revoked_reason)}</div>` : ""}
      <section class="certificate"><p class="muted">SLIIT Northern Uni certifies that</p><p class="holder">${esc(c.student_name)}</p>
        <p class="muted">has been awarded</p><h2>${esc(c.title)}</h2><p>${esc(c.programme)}</p><p class="muted">Issued ${esc(c.issued_on)}</p>
        <img src="/api/certificates/${enc(c.id)}/qr.svg" alt="QR code linking to this certificate's verification page">
        <p class="small">ID ${esc(c.id)} · Verification code <span class="mono">${esc(c.code)}</span></p></section>`);
    root.querySelector("#print").onclick = () => window.print();
  },

  async profile() {
    const role = session.user.role;
    const security = `<section class="card stack"><div class="row spread"><div><h2>Security</h2><p class="small muted">Change the password you use to sign in.</p></div>
      <button class="btn" id="pw-profile">Change password</button></div></section>`;
    if (role === "admin") {
      shell("profile", `${pageHead("My profile", "Your administrator account.")}
        <div class="grid-2">
          <section class="card stack"><h2>Account</h2><dl class="kv"><dt>Username</dt><dd>${esc(session.user.username)}</dd><dt>Role</dt><dd>Administrator</dd><dt>System</dt><dd>${esc(session.system_label || "")}</dd></dl></section>
          ${security}
        </div>`);
    } else {
      const p = await api("/api/profile");
      const labels = role === "faculty"
        ? [["ID", "id"], ["Name", "name"], ["Title", "title"], ["Department", "department"], ["Email", "email"], ["Phone", "phone"]]
        : [["ID", "id"], ["Name", "name"], ["Programme", "programme"], ["Intake", "intake"], ["Email", "email"], ["Phone", "phone"], ["NIC", "nic"], ["Date of birth", "dob"], ["Address", "address"]];
      shell("profile", `${pageHead("My profile", "To correct your details, contact the registry.")}
        <div class="grid-2">
          <section class="card stack"><h2>My details</h2><dl class="kv">${labels.map(([l, k]) => `<dt>${esc(l)}</dt><dd>${dash(p[k])}</dd>`).join("")}</dl></section>
          ${security}
        </div>`);
    }
    root.querySelector("#pw-profile").onclick = changePassword;
  },

  async chain() {
    const [status, list] = await Promise.all([api("/api/chain/status"), api(`/api/chain/blocks?limit=${CHAIN_PAGE}&offset=${chainOffset}`)]);
    const bloom = list.system === "bloom";
    const anchorName = bloom ? "Bloom filter" : "Field hashes";
    const anchorIntro = bloom
      ? "Each block stores a keyed Bloom filter. Its bits reveal nothing about the record without the secret key. The full record is kept off-chain."
      : "Each block stores an unsalted SHA-256 hash of the record and of each field. The full record is kept off-chain.";
    shell("chain", `${pageHead("Blockchain", `${status.height} blocks · ${list.system === "bloom" ? "Bloom filter anchors" : "SHA-256 hash anchors"}.`, `${status.healthy ? "" : `<button class="btn primary" id="repair">Repair from majority</button>`}${list.dev ? `<button class="btn danger" id="tamper">Simulate tampering</button>` : ""}`)}
      ${status.healthy ? "" : `<div class="banner bad">${status.has_majority ? "A node is out of consensus. Records are still served from the majority chain." : "No majority of nodes agrees on a valid chain. New writes are blocked."}</div>`}
      ${status.rejected ? `<div class="banner bad">${status.rejected} off-chain record${status.rejected === 1 ? "" : "s"} did not match ${status.rejected === 1 ? "its" : "their"} on-chain anchor and ${status.rejected === 1 ? "was" : "were"} left out.</div>` : ""}
      <section class="card">${table([
        { label: "Node", key: "node" }, { label: "Blocks", key: "height", num: true },
        { label: "Head hash", html: (n) => `<span class="hash">${esc((n.head || "").slice(0, 20))}…</span>` },
        { label: "Integrity", html: (n) => (n.valid ? `<span class="badge ok">Valid</span>` : `<span class="badge bad">Broken at block ${esc(n.bad_block)}</span>`) },
        { label: "Consensus", html: (n) => (n.in_consensus ? `<span class="badge ok">In consensus</span>` : `<span class="badge bad">Out of consensus</span>`) }], status.nodes)}</section>
      <section class="card stack"><div><h2>Latest blocks</h2><p class="small muted">${esc(anchorIntro)}</p></div>
      ${table([
        { label: "#", key: "idx", num: true }, { label: "Time", html: (b) => `<span class="nowrap small">${esc(when(b.ts))}</span>` },
        { label: "Hash", html: (b) => `<span class="hash">${esc(b.hash.slice(0, 16))}…</span>` },
        { label: "Previous", html: (b) => `<span class="hash">${esc(b.prev_hash.slice(0, 16))}…</span>` },
        { label: anchorName, html: (b) => `<span class="hash">${esc(b.anchor.slice(0, 26))}…</span>` },
        { label: "", html: (b) => `<button class="btn small" data-view="${esc(b.idx)}">View</button>` }], list.blocks)}
      <div class="row pager"><span class="small muted">Showing ${chainOffset + 1}–${Math.min(chainOffset + CHAIN_PAGE, status.height)} of ${status.height}</span>
        <button class="btn small" id="newer" ${chainOffset === 0 ? "disabled" : ""}>Newer</button>
        <button class="btn small" id="older" ${chainOffset + CHAIN_PAGE >= status.height ? "disabled" : ""}>Older</button></div></section>`);
    root.querySelector("#newer").onclick = () => { chainOffset = Math.max(chainOffset - CHAIN_PAGE, 0); route(); };
    root.querySelector("#older").onclick = () => { chainOffset += CHAIN_PAGE; route(); };
    root.querySelectorAll("[data-view]").forEach((b) => {
      b.onclick = async () => {
        try {
          const d = await api(`/api/chain/blocks/${enc(b.dataset.view)}`);
          const verified = d.verified ? `<span class="badge ok">Record matches anchor</span>` : `<span class="badge bad">Record does not match anchor</span>`;
          infoDialog(`Block ${b.dataset.view}`, "The anchor is stored on every node. The record is held off-chain and checked against the anchor.", `<div class="stack"><div class="row">${verified}</div>
            <div><h3>On-chain anchor</h3><pre class="json">${esc(JSON.stringify(d.anchor, null, 2))}</pre></div>
            <div><h3>Off-chain record</h3><pre class="json">${esc(JSON.stringify(d.record, null, 2))}</pre></div></div>`);
        } catch (err) { toast(err.message, "error"); }
      };
    });
    const repair = root.querySelector("#repair");
    if (repair) repair.onclick = async () => {
      try { const r = await api("/api/chain/repair", "POST", {}); toast(`Repaired: ${r.repaired.join(", ")}`); route(); } catch (err) { toast(err.message, "error"); }
    };
    const tamper = root.querySelector("#tamper");
    if (tamper) tamper.onclick = () => formDialog({
      title: "Simulate tampering", submit: "Alter block 1",
      intro: "Development only. This corrupts block 1 on Audit-Office-Node so you can see detection and repair working.",
      fields: [],
      onSubmit: async () => { await api("/api/dev/tamper", "POST", { node: "Audit-Office-Node", idx: 1 }); toast("Block 1 was altered on Audit-Office-Node"); route(); },
    });
  },
};

// ---- forms ---------------------------------------------------------------------
function studentForm(s) {
  formDialog({
    title: s ? `Edit ${s.name}` : "Add student", submit: s ? "Save to blockchain" : "Add student", wide: true,
    intro: "These details are stored off-chain and anchored on the chain so any change is detected.",
    fields: [
      { name: "name", label: "Full name", required: true, value: s?.name },
      { name: "email", label: "Email", type: "email", required: true, value: s?.email },
      { name: "phone", label: "Phone", value: s?.phone },
      { name: "nic", label: "NIC", value: s?.nic },
      { name: "dob", label: "Date of birth", type: "date", value: s?.dob },
      { name: "address", label: "Address", value: s?.address },
      { name: "programme", label: "Programme", required: true, value: s?.programme },
      { name: "intake", label: "Intake", required: true, value: s?.intake },
      { name: "status", label: "Status", type: "select", value: s?.status || "active", options: ["active", "inactive", "graduated"].map((v) => ({ value: v, label: v })) },
    ],
    onSubmit: async (v) => {
      if (s) { await api(`/api/students/${enc(s.id)}`, "PUT", v); toast("Student updated on the blockchain"); route(); return undefined; }
      const r = await api("/api/students", "POST", v);
      await route();
      showCredentials(`${r.student.name} added`, r.username, r.temp_password);
      return "keep-open";
    },
  });
}

function facultyForm(f) {
  formDialog({
    title: f ? `Edit ${f.name}` : "Add faculty member", submit: f ? "Save to blockchain" : "Add faculty member", wide: true,
    fields: [
      { name: "name", label: "Full name", required: true, value: f?.name },
      { name: "title", label: "Title", required: true, value: f?.title },
      { name: "department", label: "Department", required: true, value: f?.department },
      { name: "email", label: "Email", type: "email", required: true, value: f?.email },
      { name: "phone", label: "Phone", value: f?.phone },
      { name: "status", label: "Status", type: "select", value: f?.status || "active", options: ["active", "inactive"].map((v) => ({ value: v, label: v })) },
    ],
    onSubmit: async (v) => {
      if (f) { await api(`/api/faculty/${enc(f.id)}`, "PUT", v); toast("Faculty member updated on the blockchain"); route(); return undefined; }
      const r = await api("/api/faculty", "POST", v);
      await route();
      showCredentials(`${r.faculty.name} added`, r.username, r.temp_password);
      return "keep-open";
    },
  });
}

async function courseForm(c) {
  const staff = await api("/api/faculty");
  formDialog({
    title: c ? `Edit ${c.code}` : "Add course", submit: c ? "Save to blockchain" : "Add course",
    fields: [
      ...(c ? [] : [{ name: "code", label: "Course code", required: true, hint: "For example IT2010." }]),
      { name: "title", label: "Title", required: true, value: c?.title },
      { name: "semester", label: "Semester", required: true, value: c?.semester, hint: "For example Y1S1." },
      { name: "credits", label: "Credits", type: "number", required: true, value: c?.credits ?? 3, extra: 'min="1" max="30"' },
      { name: "faculty_id", label: "Lecturer", type: "select", value: c?.faculty_id || "", options: [{ value: "", label: "Not assigned" }, ...staff.map((f) => ({ value: f.id, label: f.name }))] },
    ],
    onSubmit: async (v) => {
      await (c ? api(`/api/courses/${enc(c.code)}`, "PUT", v) : api("/api/courses", "POST", v));
      toast("Course saved to the blockchain");
      route();
    },
  });
}

function reportForm(studentId) {
  formDialog({
    title: `Report for ${studentId}`, submit: "Add report",
    intro: "Reports are permanent. Each one stays on the chain.",
    fields: [
      { name: "title", label: "Title", required: true },
      { name: "semester", label: "Semester", required: true, hint: "For example Y1S1." },
      { name: "body", label: "Report", type: "textarea", required: true },
    ],
    onSubmit: async (v) => { await api("/api/reports", "POST", { student_id: studentId, ...v }); toast("Report added to the blockchain"); route(); },
  });
}

function bindRevoke() {
  root.querySelectorAll("[data-revoke]").forEach((b) => {
    b.onclick = () => formDialog({
      title: `Revoke ${b.dataset.revoke}`, submit: "Revoke certificate",
      intro: "The certificate stays on the chain but will fail public verification.",
      fields: [{ name: "reason", label: "Reason", required: true }],
      onSubmit: async (v) => { await api(`/api/certificates/${enc(b.dataset.revoke)}/revoke`, "POST", v); toast("Certificate revoked"); route(); },
    });
  });
}

// ---- router --------------------------------------------------------------------
let routing = false;
let routeAgain = false;

/* Runs one render at a time, so a slow page can't overwrite a newer one. */
async function route() {
  if (routing) { routeAgain = true; return; }
  routing = true;
  try {
    do {
      routeAgain = false;
      await renderRoute();
    } while (routeAgain);
  } finally { routing = false; }
}

async function renderRoute() {
  if (BASE === "") { renderLanding(); return; }
  if (location.pathname.endsWith("/verify")) { renderVerify(); return; }
  if (!session.user) { renderLogin(); return; }
  root.querySelector("#main")?.classList.add("is-loading");
  const [name = "overview", arg] = location.hash.replace(/^#\/?/, "").split("/");
  const allowedExtra = { admin: ["student", "course", "certificate", "profile"], faculty: ["course"], student: ["certificate"] }[session.user.role];
  const allowed = NAV[session.user.role].some(([k]) => k === name) || allowedExtra.includes(name);
  const page = allowed && pages[name] ? name : "overview";
  try {
    await pages[page](arg ? decodeURIComponent(arg) : undefined);
    window.scrollTo(0, 0);
  } catch (err) {
    if (!session.user) return;
    shell(page, `<div class="banner bad">${esc(err.message)}</div>`);
  }
}

window.addEventListener("hashchange", route);
if (BASE === "") {
  // Landing page / security check: no registry session to load.
  renderLanding();
} else {
  api("/api/session").then((s) => { session = s; route(); }).catch((err) => {
    root.innerHTML = `<main class="auth"><div class="banner bad">Could not reach the server: ${esc(err.message)}</div></main>`;
  });
}
