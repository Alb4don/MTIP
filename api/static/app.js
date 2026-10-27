const TOKEN = document.querySelector('meta[name="mtip-token"]').content;
const view = document.getElementById("view");
const titleEl = document.getElementById("view-title");
const drawer = document.getElementById("drawer");
const drawerBody = document.getElementById("drawer-body");
const drawerTitle = document.getElementById("drawer-title");
const toastEl = document.getElementById("toast");
const runBtn = document.getElementById("run-btn");
const runStatus = document.getElementById("run-status");

const REL_LABEL = {
  "inferred-indicates": "Inferred attribution",
  "conflicts-with-documented": "Conflicts with source",
  "shares-infrastructure-with": "Shares infrastructure",
  "shares-ttp-profile-with": "Shares TTP profile",
  "possible-alias-or-variant": "Possible alias or variant",
};
const ABLATION_LABEL = {
  root_only: "Registered domain only",
  context: "+ context features",
  context_temporal: "+ context + time",
};

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "on") for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
    else if (k === "style") el.style.cssText = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function toast(message, isError) {
  toastEl.textContent = message;
  toastEl.className = "toast show" + (isError ? " error" : "");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (toastEl.className = "toast"), 4200);
}

async function api(path, options = {}) {
  const opts = { method: "GET", headers: {}, ...options };
  if (opts.method !== "GET") opts.headers["X-MTIP-Token"] = TOKEN;
  if (opts.json !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.json);
    delete opts.json;
  }
  let res;
  try {
    res = await fetch("/api/v1" + path, opts);
  } catch {
    throw new Error("The application is not responding. Check that it is still running.");
  }
  let data = null;
  try { data = await res.json(); } catch { data = null; }
  if (!res.ok) throw new Error((data && data.error) || `Request failed (${res.status})`);
  return data;
}

const fmtPct = (v) => {
  if (v === null || v === undefined) return "–";
  const p = v * 100;
  if (p > 0 && p < 0.1) return "<0.1%";
  return (p < 10 && p !== 0 ? p.toFixed(2) : p.toFixed(1)) + "%";
};
const fmtNum = (v) => (v === null || v === undefined ? "–" : Number(v).toLocaleString());
const fmtScore = (v) => (v === null || v === undefined ? "–" : Number(v).toFixed(3));
const fmtQ = (v) => (v === null || v === undefined ? "" : v < 0.001 ? v.toExponential(1) : v.toFixed(3));

function empty(title, text, action) {
  return h("div", { class: "empty" }, h("strong", {}, title), text, action ? h("div", { style: "margin-top:12px" }, action) : null);
}

function relBadge(rel) {
  const cls = rel === "conflicts-with-documented" ? "conflict" : "inferred";
  return h("span", { class: `badge ${cls}` }, REL_LABEL[rel] || rel);
}

function openDrawer(title, content) {
  drawerTitle.textContent = title;
  drawerBody.replaceChildren(content);
  drawer.classList.add("open");
  drawer.setAttribute("aria-hidden", "false");
  document.getElementById("drawer-close").focus();
}
function closeDrawer() {
  drawer.classList.remove("open");
  drawer.setAttribute("aria-hidden", "true");
}
document.getElementById("drawer-close").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

async function sendFeedback(item, verdict, after) {
  try {
    await api("/feedback", { method: "POST", json: {
      src_type: item.src_type, src_id: item.src_id, dst_type: item.dst_type, dst_id: item.dst_id,
      relation: item.relation, verdict,
    } });
    toast(verdict === "confirm" ? "Confirmed. It now counts as documented by the analyst." : "Rejected. It will not be inferred again.");
    if (after) after();
  } catch (err) { toast(err.message, true); }
}

function feedbackButtons(item, after) {
  if (item.verdict) return h("span", { class: `badge ${item.verdict === "confirm" ? "ok" : "conflict"}` }, item.verdict === "confirm" ? "Confirmed" : "Rejected");
  return h("span", {},
    h("button", { class: "btn small confirm", type: "button", on: { click: (e) => { e.stopPropagation(); sendFeedback(item, "confirm", after); } } }, "Confirm"),
    " ",
    h("button", { class: "btn small reject", type: "button", on: { click: (e) => { e.stopPropagation(); sendFeedback(item, "reject", after); } } }, "Reject"));
}

function basisText(item) {
  const b = item.basis || {};
  if (b.via_indicator) {
    const reasons = (b.reasons || []).map((r) => r.replace(/_/g, " ")).join(", ") || "pairwise model";
    return h("span", { class: "basis" }, "via ", h("code", {}, b.via_indicator.value), ` · ${reasons} · ${b.support} supporting indicator${b.support === 1 ? "" : "s"}`);
  }
  if (b.method && b.method.startsWith("hypergeometric")) {
    return h("span", { class: "basis" }, `${b.shared} shared of ${b.set_a} and ${b.set_b} (universe ${b.universe}) · q = ${fmtQ(item.q_value)}`);
  }
  if (b.names) return h("span", { class: "basis" }, `name similarity: ${b.names.join(" ↔ ")}`);
  return h("span", { class: "basis" }, b.method || "");
}

const views = {};

views.overview = async () => {
  const data = await api("/overview");
  const m = data.metrics;
  const ev = data.evaluation;
  const nodes = [];
  if (!m.duplicates.observations) {
    return empty("No intelligence loaded yet", "Import a STIX 2.1 bundle or pull a TAXII 2.1 collection to start.",
      h("a", { class: "btn primary", href: "#import" }, "Import data"));
  }
  if (ev && ev.status === "ok") {
    const ab = ev.ablations;
    const maxF1 = Math.max(...Object.values(ab).map((a) => a.f1.mean), 0.01);
    const ctxLift = ev.lift_context_over_root_f1;
    const tLift = ev.lift_temporal_over_context_f1;
    const ctxSd = Math.max(ab.context.f1.sd, ab.root_only.f1.sd);
    let verdict;
    const ctxPart = Math.abs(ctxLift) <= 2 * ctxSd
      ? `Context features change F1 by ${ctxLift >= 0 ? "+" : ""}${ctxLift.toFixed(3)}, within run-to-run variation.`
      : `Context features change F1 by ${ctxLift >= 0 ? "+" : ""}${ctxLift.toFixed(3)} over registered-domain matching alone.`;
    const tPart = ev.temporal_coverage < 0.05
      ? `Time cannot be tested yet: only ${fmtPct(ev.temporal_coverage)} of indicators carry usable timestamps; bulk-export dates are excluded.`
      : `Adding time changes F1 by ${tLift >= 0 ? "+" : ""}${tLift.toFixed(3)} with ${fmtPct(ev.temporal_coverage)} timestamp coverage.`;
    verdict = `${ctxPart} ${tPart}`;
    nodes.push(h("section", { class: "answer", "aria-labelledby": "q-title" },
      h("h2", { id: "q-title" }, "Does temporal and contextual correlation improve attribution?"),
      h("p", { class: "verdict" }, verdict),
      h("div", { class: "bars" }, Object.entries(ab).map(([name, a]) =>
        h("div", { class: "bar-row" },
          h("span", {}, ABLATION_LABEL[name] || name),
          h("div", { class: "bar-track", role: "img", "aria-label": `F1 ${a.f1.mean}` },
            h("div", { class: `bar-fill ${name === "context" ? "context" : name === "context_temporal" ? "temporal" : ""}`, style: `width:${(a.f1.mean / maxF1) * 100}%` })),
          h("span", { class: "bar-num" }, `F1 ${a.f1.mean.toFixed(3)} ± ${a.f1.sd.toFixed(3)} · P ${a.precision.mean.toFixed(3)}`)))),
      h("p", { class: "lede", style: "margin:14px 0 0" },
        `Hold-out test: ${Math.round(ev.fraction * 100)}% of ${fmtNum(ev.eligible)} documented attributions hidden, ${ev.reps} repetitions. Recall is bounded by indicators that share no structure with any other indicator.`)));
  } else {
    nodes.push(h("section", { class: "answer" }, h("h2", {}, "Does temporal and contextual correlation improve attribution?"),
      h("p", { class: "verdict" }, "Run a correlation to measure it on your data.")));
  }
  const inferredTotal = Object.values(m.associations.inferred || {}).reduce((s, v) => s + v, 0);
  const docTotal = m.associations.documented;
  const total = Math.max(1, docTotal + inferredTotal);
  nodes.push(h("div", { class: "readouts" },
    h("div", { class: "readout" }, h("div", { class: "k" }, "Duplicates eliminated"), h("div", { class: "v" }, fmtNum(m.duplicates.eliminated)),
      h("div", { class: "note" }, `${fmtPct(m.duplicates.elimination_rate)} of ${fmtNum(m.duplicates.observations)} observations`)),
    h("div", { class: "readout" }, h("div", { class: "k" }, "Source coverage"), h("div", { class: "v" }, fmtPct(m.coverage.multi_source_share)),
      h("div", { class: "note" }, `${fmtNum(m.coverage.indicators_in_multiple_sources)} indicators seen by 2+ of ${m.coverage.sources} sources`)),
    h("div", { class: "readout" }, h("div", { class: "k" }, "Confirmed indicators"), h("div", { class: "v" }, fmtPct(m.confirmation.confirmed_share)),
      h("div", { class: "note" }, `${fmtNum(m.confirmation.confirmed)} by two sources or an analyst`)),
    h("div", { class: "readout" }, h("div", { class: "k" }, "Correlation accuracy"), h("div", { class: "v" }, m.accuracy.holdout_precision === null ? "–" : fmtPct(m.accuracy.holdout_precision)),
      h("div", { class: "note" }, m.accuracy.analyst_precision === null ? "hold-out precision" : `hold-out · analyst ${fmtPct(m.accuracy.analyst_precision)}`))));
  nodes.push(h("h2", {}, "Associations"),
    h("div", { class: "ledger", role: "img", "aria-label": `${docTotal} documented, ${inferredTotal} inferred` },
      h("div", { class: "doc", style: `width:${(docTotal / total) * 100}%` }),
      h("div", { class: "inf", style: `width:${(inferredTotal / total) * 100}%` })),
    h("div", { class: "ledger-caption" }, h("span", {}, `${fmtNum(docTotal)} documented by sources`), h("span", {}, `${fmtNum(inferredTotal)} statistical inferences`)));
  const infRows = Object.entries(m.associations.inferred || {});
  const kindRows = Object.entries(data.counts.indicators_by_kind);
  const model = data.model;
  nodes.push(h("div", { class: "cols" },
    h("div", {}, h("h2", {}, "Inferences in the active run"),
      infRows.length ? h("table", {}, h("tbody", {}, infRows.map(([k, v]) => h("tr", {}, h("td", {}, relBadge(k)), h("td", { class: "num" }, fmtNum(v))))))
        : h("p", { class: "muted" }, "None. Inference needs unattributed indicators or entities with overlapping evidence."),
      h("h2", {}, "Indicators by type"),
      h("table", {}, h("tbody", {}, kindRows.map(([k, v]) => h("tr", {}, h("td", {}, k.replace(/_/g, " ")), h("td", { class: "num" }, fmtNum(v))))))),
    h("div", {}, h("h2", {}, "Pairwise evidence model"),
      model ? h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Feature"), h("th", { class: "num" }, "Log-odds weight"))),
        h("tbody", {}, Object.entries(model.weights).map(([k, v]) => h("tr", {}, h("td", {}, k.replace(/_/g, " ")), h("td", { class: "num" }, v.toFixed(3)))),
          h("tr", {}, h("td", {}, "intercept"), h("td", { class: "num" }, model.bias.toFixed(3)))))
        : h("p", { class: "muted" }, "Not trained yet."),
      model ? h("p", { class: "lede", style: "margin-top:10px" }, `Fitted on ${fmtNum(model.trained_on)} candidate pairs labelled by documented attributions and analyst feedback.`) : null)));
  return nodes;
};

const indState = { kind: "", status: "", search: "", offset: 0, limit: 50 };
views.indicators = async () => {
  const kinds = ["", "domain", "url", "app_id", "sha256", "sha1", "md5", "cert_sha256", "ipv4", "ipv6", "email", "file_path", "file_name", "process_name", "android_property", "other"];
  const statuses = [["", "Any"], ["documented", "Documented"], ["inferred", "Inferred only"], ["conflict", "Conflicts with source"], ["unattributed", "Unattributed"], ["confirmed", "Confirmed"]];
  const q = new URLSearchParams({ offset: indState.offset, limit: indState.limit });
  if (indState.kind) q.set("kind", indState.kind);
  if (indState.status) q.set("status", indState.status);
  if (indState.search) q.set("search", indState.search);
  const data = await api("/indicators?" + q);
  const search = h("input", { type: "search", value: indState.search, placeholder: "Value contains…", "aria-label": "Search indicators" });
  const kindSel = h("select", { "aria-label": "Type" }, kinds.map((k) => h("option", { value: k, selected: k === indState.kind }, k ? k.replace(/_/g, " ") : "Any type")));
  const statusSel = h("select", { "aria-label": "Association" }, statuses.map(([v, l]) => h("option", { value: v, selected: v === indState.status }, l)));
  const apply = () => { indState.search = search.value.trim(); indState.kind = kindSel.value; indState.status = statusSel.value; indState.offset = 0; render(); };
  search.addEventListener("keydown", (e) => { if (e.key === "Enter") apply(); });
  kindSel.addEventListener("change", apply);
  statusSel.addEventListener("change", apply);
  const rows = data.items.map((it) => h("tr", { class: "clickable", tabindex: "0", on: {
      click: () => showIndicator(it.id), keydown: (e) => { if (e.key === "Enter") showIndicator(it.id); } } },
    h("td", { class: "value" }, it.value),
    h("td", {}, it.kind.replace(/_/g, " ")),
    h("td", {}, it.documented.map((d) => h("span", { class: "badge documented" }, d)),
      it.inferred ? h("span", { class: `badge ${it.inferred.relation === "conflicts-with-documented" ? "conflict" : "inferred"}` }, `${it.inferred.entity} ${fmtScore(it.inferred.score)}`) : null,
      !it.documented.length && !it.inferred ? h("span", { class: "badge muted" }, "unattributed") : null),
    h("td", { class: "num" }, it.sources),
    h("td", {}, it.confirmed ? h("span", { class: "badge ok" }, "confirmed") : "")));
  return [
    h("p", { class: "lede" }, "Canonical indicators after refanging, case folding, IDNA and URL normalisation. Each value appears once, however many sources reported it."),
    h("div", { class: "filters" }, h("label", { class: "field" }, "Search", search), h("label", { class: "field" }, "Type", kindSel),
      h("label", { class: "field" }, "Association", statusSel), h("button", { class: "btn", type: "button", on: { click: apply } }, "Apply")),
    data.items.length ? h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Value"), h("th", {}, "Type"), h("th", {}, "Association"), h("th", { class: "num" }, "Sources"), h("th", {}, ""))),
      h("tbody", {}, rows)) : empty("No indicators match", "Clear a filter or import another source."),
    pager(data, (off) => { indState.offset = off; render(); }),
  ];
};

function pager(data, go) {
  const end = Math.min(data.offset + data.limit, data.total);
  return h("div", { class: "pager" },
    h("button", { class: "btn small", type: "button", disabled: data.offset === 0, on: { click: () => go(Math.max(0, data.offset - data.limit)) } }, "Previous"),
    h("span", {}, data.total ? `${fmtNum(data.offset + 1)}–${fmtNum(end)} of ${fmtNum(data.total)}` : "0 results"),
    h("button", { class: "btn small", type: "button", disabled: end >= data.total, on: { click: () => go(data.offset + data.limit) } }, "Next"));
}

async function showIndicator(id) {
  try {
    const d = await api(`/indicators/${id}`);
    const ind = d.indicator;
    const content = h("div", {},
      h("dl", { class: "kv" },
        h("dt", {}, "Value"), h("dd", { class: "value" }, ind.value),
        h("dt", {}, "Type"), h("dd", {}, ind.kind),
        h("dt", {}, "Registered domain"), h("dd", {}, ind.root ? `${ind.root}${ind.shared_root ? " (shared hosting, excluded from correlation)" : ""}` : "–"),
        h("dt", {}, "First seen"), h("dd", {}, ind.first_seen || "–"),
        h("dt", {}, "Analyst verdict"), h("dd", {}, ind.analyst_verdict || "–")),
      h("h3", {}, "Documented associations"),
      d.documented.length ? h("table", {}, h("tbody", {}, d.documented.map((x) => h("tr", {},
        h("td", {}, h("span", { class: "badge documented" }, x.rel_type)), h("td", {}, x.target), h("td", { class: "muted" }, x.source))))) : h("p", { class: "muted" }, "None."),
      h("h3", {}, "Statistical inferences"),
      d.inferred.length ? h("table", {}, h("tbody", {}, d.inferred.map((x) => {
        const item = { src_type: "indicator", src_id: ind.id, dst_type: x.target_type, dst_id: x.target_id, relation: x.relation, basis: x.basis };
        return h("tr", {}, h("td", {}, relBadge(x.relation)), h("td", {}, x.target, h("div", {}, basisText(item))),
          h("td", { class: "num" }, fmtScore(x.score)), h("td", {}, feedbackButtons(item, () => showIndicator(id))));
      }))) : h("p", { class: "muted" }, "None in the active run."),
      h("h3", {}, "Source history"),
      h("table", {}, h("tbody", {}, d.observations.map((o) => h("tr", {}, h("td", {}, o.source), h("td", { class: "muted" }, o.observed_at || "–"),
        h("td", {}, h("span", { class: "badge muted" }, o.timestamp_quality)), h("td", { class: "value" }, o.raw_value !== ind.value ? o.raw_value : ""))))),
      d.same_root.length ? [h("h3", {}, `Same registered domain (${d.same_root.length} shown)`),
        h("div", { class: "feat-list" }, d.same_root.map((s) => h("a", { href: "#", class: "value", on: { click: (e) => { e.preventDefault(); showIndicator(s.id); } } }, s.value)))] : null);
    openDrawer("Indicator", content);
  } catch (err) { toast(err.message, true); }
}

const infState = { relation: "", min: "0", offset: 0, limit: 50 };
views.inferences = async () => {
  const q = new URLSearchParams({ offset: infState.offset, limit: infState.limit, min_score: infState.min });
  if (infState.relation) q.set("relation", infState.relation);
  const data = await api("/inferences?" + q);
  const relSel = h("select", { "aria-label": "Relation" }, h("option", { value: "" }, "All relations"),
    Object.entries(REL_LABEL).map(([k, v]) => h("option", { value: k, selected: k === infState.relation }, v)));
  const minIn = h("input", { type: "number", min: "0", max: "1", step: "0.05", value: infState.min, "aria-label": "Minimum score", style: "width:90px" });
  const apply = () => { infState.relation = relSel.value; const v = parseFloat(minIn.value); infState.min = isNaN(v) ? "0" : String(Math.min(1, Math.max(0, v))); infState.offset = 0; render(); };
  relSel.addEventListener("change", apply);
  minIn.addEventListener("change", apply);
  return [
    h("p", { class: "lede" }, "Everything on this page was derived by the platform, not asserted by a source. Confirming an inference records it as documented by the analyst and retrains the model on the next run; rejecting it suppresses it permanently."),
    h("div", { class: "filters" }, h("label", { class: "field" }, "Relation", relSel), h("label", { class: "field" }, "Minimum score", minIn)),
    data.items.length ? h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Relation"), h("th", {}, "From"), h("th", {}, "To"), h("th", {}, "Evidence"), h("th", { class: "num" }, "Score"), h("th", {}, ""))),
      h("tbody", {}, data.items.map((it) => h("tr", {},
        h("td", {}, relBadge(it.relation)),
        h("td", { class: it.src_type === "indicator" ? "value" : "" }, it.src),
        h("td", {}, it.dst), h("td", {}, basisText(it)), h("td", { class: "num" }, fmtScore(it.score)),
        h("td", { class: "actions" }, feedbackButtons(it, render))))))
      : empty("No inferences", "Either no correlation has run yet, or every indicator is already attributed by a source. Import unattributed indicators to see attributions."),
    pager(data, (off) => { infState.offset = off; render(); }),
  ];
};

const graphState = { focus: "", inferred: true };
views.graph = async () => {
  const q = new URLSearchParams({ inferred: graphState.inferred, max_nodes: 300 });
  if (graphState.focus) q.set("focus", graphState.focus);
  const [data, ents] = await Promise.all([api("/graph?" + q), api("/entities?limit=1000")]);
  const focusSel = h("select", { "aria-label": "Focus entity" }, h("option", { value: "" }, "Whole graph"),
    ents.map((e) => h("option", { value: e.id, selected: String(e.id) === String(graphState.focus) }, `${e.display_name} (${e.etype}, ${e.indicators})`)));
  const infToggle = h("input", { type: "checkbox", checked: graphState.inferred });
  focusSel.addEventListener("change", () => { graphState.focus = focusSel.value; render(); });
  infToggle.addEventListener("change", () => { graphState.inferred = infToggle.checked; render(); });
  const canvas = h("canvas", { id: "graph-canvas", role: "img", "aria-label": "Campaign graph" });
  const wrap = h("div", { class: "graph-wrap" }, canvas, h("div", { class: "graph-meta" }, `${data.nodes.length} nodes · ${data.edges.length} edges · ${data.communities} communities`));
  requestAnimationFrame(() => drawGraph(canvas, data));
  return [
    h("p", { class: "lede" }, "Families, campaigns and shared registered domains. Communities come from Louvain modularity on documented and inferred links; node size follows PageRank. Drag to pan, scroll to zoom, click a node to inspect it."),
    h("div", { class: "filters" }, h("label", { class: "field" }, "Focus", focusSel),
      h("label", { class: "field", style: "flex-direction:row;display:flex;gap:6px;align-items:center" }, infToggle, "Show inferences")),
    data.nodes.length ? wrap : empty("Nothing to draw", "Import sources with relationships between families, or run a correlation."),
  ];
};

function drawGraph(canvas, data) {
  const css = getComputedStyle(document.documentElement);
  const color = (v) => css.getPropertyValue(v).trim();
  const palette = ["#6fa8dc", "#93c47d", "#c27ba0", "#76a5af", "#b4a7d6", "#e6b8af", "#a2c4c9", "#d5a6bd", "#b6d7a8", "#9fc5e8"];
  const dpr = window.devicePixelRatio || 1;
  const nodes = data.nodes.map((n) => ({ ...n }));
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const maxRank = Math.max(...nodes.map((n) => n.rank), 1e-9);
  let scale = 1, ox = 0, oy = 0, drag = null, hover = null;
  function resize() {
    const r = canvas.getBoundingClientRect();
    canvas.width = r.width * dpr; canvas.height = r.height * dpr;
    draw();
  }
  function project(n) {
    const r = canvas.getBoundingClientRect();
    const pad = 40;
    return [(pad + ((n.x + 1) / 2) * (r.width - 2 * pad)) * scale + ox, (pad + ((n.y + 1) / 2) * (r.height - 2 * pad)) * scale + oy];
  }
  const radius = (n) => (n.type === "infrastructure" ? 3.5 : 4 + 14 * Math.sqrt(n.rank / maxRank));
  function draw() {
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const r = canvas.getBoundingClientRect();
    ctx.clearRect(0, 0, r.width, r.height);
    for (const e of data.edges) {
      const a = byId.get(e.source), b = byId.get(e.target);
      if (!a || !b) continue;
      const [x1, y1] = project(a), [x2, y2] = project(b);
      ctx.beginPath();
      ctx.lineWidth = e.kind === "documented" ? 1.6 : 1.8;
      ctx.setLineDash(e.kind === "documented" ? [] : [5, 4]);
      ctx.strokeStyle = e.kind === "documented" ? color("--documented") : color("--inferred");
      ctx.globalAlpha = hover && hover !== a && hover !== b ? 0.15 : 0.85;
      ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();
    }
    ctx.setLineDash([]); ctx.globalAlpha = 1;
    for (const n of nodes) {
      const [x, y] = project(n);
      ctx.beginPath();
      ctx.fillStyle = n.type === "infrastructure" ? color("--muted") : palette[n.community % palette.length];
      ctx.globalAlpha = hover && hover !== n ? 0.45 : 1;
      if (n.type === "campaign" || n.type === "intrusion-set") ctx.rect(x - radius(n), y - radius(n), radius(n) * 2, radius(n) * 2);
      else ctx.arc(x, y, radius(n), 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.globalAlpha = 1;
    ctx.fillStyle = color("--text");
    ctx.font = "12px " + css.getPropertyValue("--sans");
    const placed = [];
    const ordered = [...nodes].sort((a, b) => b.rank - a.rank);
    if (hover) ordered.unshift(hover);
    for (const n of ordered) {
      const [x, y] = project(n);
      const w = ctx.measureText(n.label).width;
      const box = [x + radius(n) + 3, y - 8, x + radius(n) + 3 + w, y + 6];
      if (n !== hover && placed.some((p) => box[0] < p[2] && box[2] > p[0] && box[1] < p[3] && box[3] > p[1])) continue;
      placed.push(box);
      ctx.fillText(n.label, box[0], y + 4);
      if (placed.length > 120) break;
    }
  }
  function pick(ev) {
    const r = canvas.getBoundingClientRect();
    const mx = ev.clientX - r.left, my = ev.clientY - r.top;
    let best = null, bestD = 14;
    for (const n of nodes) { const [x, y] = project(n); const d = Math.hypot(x - mx, y - my); if (d < Math.max(bestD, radius(n) + 2)) { best = n; bestD = d; } }
    return best;
  }
  canvas.addEventListener("mousedown", (e) => { drag = { x: e.clientX, y: e.clientY, ox, oy, moved: false }; canvas.classList.add("dragging"); });
  window.addEventListener("mouseup", (e) => {
    if (drag && !drag.moved) {
      const n = pick(e);
      if (n && n.type !== "infrastructure") { graphState.focus = String(n.ref); render(); }
      else if (n) { indState.search = n.ref; indState.offset = 0; location.hash = "#indicators"; }
    }
    drag = null; canvas.classList.remove("dragging");
  }, { once: false });
  canvas.addEventListener("mousemove", (e) => {
    if (drag) { const dx = e.clientX - drag.x, dy = e.clientY - drag.y; if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true; ox = drag.ox + dx; oy = drag.oy + dy; draw(); return; }
    const n = pick(e); if (n !== hover) { hover = n; draw(); }
  });
  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    const r = canvas.getBoundingClientRect();
    const mx = e.clientX - r.left, my = e.clientY - r.top;
    const f = e.deltaY < 0 ? 1.15 : 1 / 1.15;
    ox = mx - (mx - ox) * f; oy = my - (my - oy) * f; scale *= f; draw();
  }, { passive: false });
  new ResizeObserver(resize).observe(canvas);
}

views.sources = async () => {
  const data = await api("/sources");
  if (!data.length) return empty("No sources yet", "Every import creates or updates a source.", h("a", { class: "btn primary", href: "#import" }, "Import data"));
  return [
    h("p", { class: "lede" }, "Reliability is a Beta posterior: it starts at Beta(2,1) and moves with every analyst confirmation or rejection of evidence that came from the source. Timestamp quality decides whether a source's dates are allowed into temporal correlation."),
    h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Source"), h("th", { class: "num" }, "Indicators"), h("th", { class: "num" }, "Exclusive"), h("th", { class: "num" }, "Entities"),
      h("th", {}, "Reliability (95% interval)"), h("th", {}, "Timestamps"), h("th", { class: "num" }, "Imports"), h("th", {}, "Last import"))),
      h("tbody", {}, data.map((s) => h("tr", { class: "clickable", tabindex: "0", on: { click: () => showSource(s), keydown: (e) => { if (e.key === "Enter") showSource(s); } } },
        h("td", {}, s.name, s.kind === "analyst" ? h("span", { class: "badge muted", style: "margin-left:6px" }, "analyst") : null),
        h("td", { class: "num" }, fmtNum(s.indicators)), h("td", { class: "num" }, fmtPct(s.exclusive_share)), h("td", { class: "num" }, fmtNum(s.entities)),
        h("td", {}, h("span", { class: "ci", title: `${s.reliability_ci[0]}–${s.reliability_ci[1]}` },
          h("span", { style: `left:${s.reliability_ci[0] * 100}%;right:${100 - s.reliability_ci[1] * 100}%` }), h("i", { style: `left:${s.reliability * 100}%` })), " ", s.reliability.toFixed(2)),
        h("td", {}, h("span", { class: `badge ${s.timestamp_quality === "bulk-export" || s.timestamp_quality === "unknown" ? "muted" : "ok"}` }, s.timestamp_quality)),
        h("td", { class: "num" }, s.imports), h("td", { class: "muted" }, s.last_import_at ? s.last_import_at.slice(0, 16).replace("T", " ") : "–"))))),
  ];
};

function showSource(s) {
  openDrawer(s.name, h("div", {},
    h("dl", { class: "kv" }, h("dt", {}, "Coverage"), h("dd", {}, fmtPct(s.coverage)), h("dt", {}, "Exclusive share"), h("dd", {}, fmtPct(s.exclusive_share)),
      h("dt", {}, "Reliability"), h("dd", {}, `${s.reliability.toFixed(3)} (${s.reliability_ci[0]}–${s.reliability_ci[1]})`), h("dt", {}, "Timestamps"), h("dd", {}, s.timestamp_quality)),
    h("h3", {}, "Import history"),
    s.history.length ? h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Received"), h("th", { class: "num" }, "Objects"), h("th", { class: "num" }, "Accepted"), h("th", { class: "num" }, "Rejected"), h("th", { class: "num" }, "Duplicates"))),
      h("tbody", {}, s.history.map((x) => h("tr", {}, h("td", {}, x.received_at.slice(0, 19).replace("T", " ")), h("td", { class: "num" }, fmtNum(x.objects_total)),
        h("td", { class: "num" }, fmtNum(x.accepted)), h("td", { class: "num" }, fmtNum(x.rejected)), h("td", { class: "num" }, fmtNum(x.duplicates)))))) : h("p", { class: "muted" }, "No imports."),
    h("p", { style: "margin-top:16px" }, h("a", { href: "#indicators", class: "btn", on: { click: () => { indState.search = ""; } } }, "Browse indicators"))));
}

async function watchJob(job, label) {
  for (let i = 0; i < 900; i++) {
    const j = await api(`/jobs/${job.id}`);
    if (j.status === "complete") return j;
    if (j.status === "failed") throw new Error(`${label} failed: ${j.error}`);
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`${label} is still running; check the jobs list.`);
}

views.import = async () => {
  const jobs = await api("/jobs");
  const nameIn = h("input", { type: "text", placeholder: "e.g. amnesty-pegasus", maxlength: "80", "aria-label": "Source name", required: true });
  const fileIn = h("input", { type: "file", accept: ".json,.stix2,.stix,application/json", style: "display:none" });
  const drop = h("div", { class: "drop", tabindex: "0", role: "button", "aria-label": "Choose a STIX file" }, "Drop a STIX 2.1 bundle here, or press to choose a file (JSON, up to the configured size limit)");
  const upload = async (file) => {
    const name = nameIn.value.trim() || file.name.replace(/\.[^.]+$/, "").replace(/[^A-Za-z0-9 ._()-]/g, "-").slice(0, 80);
    if (!name) { toast("Give the source a name first.", true); return; }
    drop.textContent = `Uploading ${file.name}…`;
    try {
      const res = await api(`/imports/file?source=${encodeURIComponent(name)}`, { method: "POST", body: file, headers: { "Content-Type": "application/json" } });
      drop.textContent = `Importing ${file.name}…`;
      const j = await watchJob(res.job, "Import");
      const r = j.result;
      toast(r.status === "already-imported" ? "This file was already imported for that source." :
        `Imported ${fmtNum(r.indicators_new)} new indicators, ${fmtNum(r.duplicates)} duplicates merged, ${fmtNum(r.rejected)} objects rejected. Correlation queued.`);
      render();
    } catch (err) { toast(err.message, true); drop.textContent = "Drop a STIX 2.1 bundle here, or press to choose a file"; }
  };
  drop.addEventListener("click", () => fileIn.click());
  drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileIn.click(); } });
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); if (e.dataTransfer.files[0]) upload(e.dataTransfer.files[0]); });
  fileIn.addEventListener("change", () => { if (fileIn.files[0]) upload(fileIn.files[0]); });

  const urlIn = h("input", { type: "url", placeholder: "https://taxii.example.org/taxii2/", "aria-label": "TAXII server address" });
  const userIn = h("input", { type: "text", autocomplete: "off", "aria-label": "Username" });
  const passIn = h("input", { type: "password", autocomplete: "new-password", "aria-label": "Password" });
  const sinceIn = h("input", { type: "text", placeholder: "2026-01-01T00:00:00Z", "aria-label": "Added after" });
  const taxiiName = h("input", { type: "text", maxlength: "80", placeholder: "source name", "aria-label": "TAXII source name" });
  const collList = h("div", { class: "feat-list" });
  const creds = () => ({ username: userIn.value || null, password: passIn.value || null });
  const discoverBtn = h("button", { class: "btn", type: "button", on: { click: async () => {
    discoverBtn.disabled = true;
    try {
      const res = await api("/taxii/discover", { method: "POST", json: { url: urlIn.value.trim(), ...creds() } });
      collList.replaceChildren(...(res.collections.length ? res.collections.map((c) => h("div", { class: "row" },
        h("span", { style: "flex:1" }, c.title || c.id, h("span", { class: "muted" }, c.can_read ? "" : " (not readable)")),
        h("button", { class: "btn small", type: "button", disabled: !c.can_read, on: { click: async () => {
          const name = taxiiName.value.trim() || (c.title || "taxii").replace(/[^A-Za-z0-9 ._()-]/g, "-").slice(0, 80);
          try {
            const r = await api("/taxii/import", { method: "POST", json: { collection_url: c.url, source_name: name, added_after: sinceIn.value.trim() || null, ...creds() } });
            toast("Collection download started.");
            const j = await watchJob(r.job, "TAXII import");
            toast(`Imported ${fmtNum(j.result.indicators_new)} new indicators from ${name}.`);
            render();
          } catch (err) { toast(err.message, true); }
        } } }, "Import"))) : [h("p", { class: "muted" }, "The server lists no collections.")]));
    } catch (err) { toast(err.message, true); }
    discoverBtn.disabled = false;
  } } }, "Discover collections");

  return [
    h("h2", {}, "STIX file"),
    h("div", { class: "stack" }, h("label", { class: "field" }, "Source name (one per feed; re-importing the same file is ignored)", nameIn), drop, fileIn),
    h("h2", {}, "TAXII 2.1 server"),
    h("div", { class: "stack" },
      h("p", { class: "lede" }, "HTTPS only. Addresses that resolve to private or local networks are refused, and redirects are not followed. Credentials are used for this request only and never stored."),
      h("label", { class: "field" }, "Server address", urlIn),
      h("div", { class: "row" }, h("label", { class: "field" }, "Username", userIn), h("label", { class: "field" }, "Password", passIn)),
      h("div", { class: "row" }, h("label", { class: "field" }, "Source name", taxiiName), h("label", { class: "field" }, "Only objects added after", sinceIn)),
      h("div", {}, discoverBtn), collList),
    h("h2", {}, "Recent jobs"),
    jobs.length ? h("table", {}, h("tbody", {}, jobs.map((j) => h("tr", {}, h("td", {}, j.kind), h("td", {}, h("span", { class: `badge ${j.status === "failed" ? "conflict" : j.status === "complete" ? "ok" : "muted"}` }, j.status)),
      h("td", { class: "muted" }, j.created_at.slice(11, 19)), h("td", { class: "muted" }, j.error || ""))))) : h("p", { class: "muted" }, "No jobs in this session."),
  ];
};

views.reports = async () => {
  const [feats, history] = await Promise.all([api("/features"), api("/metrics/history?limit=20")]);
  return [
    h("p", { class: "lede" }, "Every report keeps documented associations and statistical inferences in separate sections. The STIX export contains only inferences, each marked with x_mtip_association = inferred, its score, q-value and evidence."),
    h("div", { class: "row" },
      h("a", { class: "btn primary", href: "/api/v1/reports/html", download: "mtip-report.html" }, "Download HTML report"),
      h("a", { class: "btn", href: "/api/v1/reports/json", download: "mtip-report.json" }, "Download JSON"),
      h("a", { class: "btn", href: "/api/v1/reports/stix", download: "mtip-inferences.stix.json" }, "Download STIX 2.1 inferences"),
      ...feats.filter((f) => f.name === "indicator_csv" && f.status === "loaded").map(() => h("a", { class: "btn", href: "/api/v1/features/indicator_csv/export", download: "mtip-indicators.csv" }, "Download indicator CSV"))),
    h("h2", {}, "Metric history"),
    history.length ? h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Run"), h("th", {}, "When"), h("th", { class: "num" }, "Hold-out F1"), h("th", { class: "num" }, "Hold-out precision"),
      h("th", { class: "num" }, "Analyst precision"), h("th", { class: "num" }, "Confirmed"), h("th", { class: "num" }, "Duplicates removed"))),
      h("tbody", {}, history.slice().reverse().map((r) => h("tr", {}, h("td", {}, r.run_id), h("td", { class: "muted" }, r.created_at.slice(0, 16).replace("T", " ")),
        h("td", { class: "num" }, fmtScore(r.holdout_f1)), h("td", { class: "num" }, fmtScore(r.holdout_precision)), h("td", { class: "num" }, r.analyst_precision === null ? "–" : fmtPct(r.analyst_precision)),
        h("td", { class: "num" }, fmtPct(r.confirmed_share)), h("td", { class: "num" }, fmtPct(r.elimination_rate)))))) : h("p", { class: "muted" }, "No correlation runs yet."),
    h("h2", {}, "Feature modules"),
    h("div", { class: "feat-list" }, feats.length ? feats.map((f) => h("div", {}, h("span", { class: `badge ${f.status === "loaded" ? "ok" : "conflict"}` }, f.status), f.name)) : h("span", { class: "muted" }, "None installed.")),
  ];
};

const TITLES = { overview: "Overview", indicators: "Indicators", inferences: "Inferences", graph: "Campaign graph", sources: "Sources", import: "Import", reports: "Reports" };
let renderSeq = 0;
async function render() {
  const name = (location.hash || "#overview").slice(1);
  const key = views[name] ? name : "overview";
  titleEl.textContent = TITLES[key];
  document.querySelectorAll(".rail a").forEach((a) => a.classList.toggle("active", a.dataset.view === key));
  const seq = ++renderSeq;
  try {
    const content = await views[key]();
    if (seq !== renderSeq) return;
    view.replaceChildren(...[content].flat().filter(Boolean));
  } catch (err) {
    if (seq !== renderSeq) return;
    view.replaceChildren(empty("This view could not load", err.message));
  }
}
window.addEventListener("hashchange", () => { closeDrawer(); render(); view.focus(); });

async function pollStatus() {
  try {
    const hstat = await api("/health");
    const eng = hstat.engine || {};
    const busy = eng.status === "running";
    runStatus.classList.toggle("busy", busy);
    runStatus.textContent = busy ? `Correlating: ${eng.stage || "working"}` : eng.status === "failed" ? "Last run failed; see the log" : eng.last_run ? `Run ${eng.last_run} active` : "Ready";
    runBtn.disabled = busy;
    if (pollStatus.wasBusy && !busy) render();
    pollStatus.wasBusy = busy;
  } catch { runStatus.textContent = "Not connected"; }
}
runBtn.addEventListener("click", async () => {
  runBtn.disabled = true;
  try {
    const res = await api("/correlation/run", { method: "POST", json: {} });
    toast("Correlation started.");
    pollStatus();
    const j = await watchJob(res.job, "Correlation");
    toast(j.result.status === "skipped" ? "A run was already in progress." : `Run ${j.result.run_id} complete in ${j.result.stats.duration_seconds}s.`);
    render();
  } catch (err) { toast(err.message, true); }
  pollStatus();
});

render();
pollStatus();
setInterval(pollStatus, 4000);
