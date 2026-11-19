/* Core: state, API, shell, router, drawer, toast, guided demo engine. */
const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const ST = { meta: null, plan: null, strategies: null, pct: 20, strategy: "ml_ilp", dt: 25, deps: true, ext: false,
  hindsight: false, notes: false, tour: null };
const STRAT = {
  random: { name: "Random", color: "#6f8f7b", desc: "Lower bound. Picks patches blindly until the budget is spent." },
  cvss_sorted: { name: "CVSS-sorted", color: "#ffb000", desc: "What most teams do today: highest CVSS severity first." },
  epss_sorted: { name: "EPSS-sorted", color: "#ff4fd8", desc: "Public exploit predictor (a competing baseline, never a feature)." },
  ml_greedy: { name: "ML + Greedy", color: "#00e5ff", desc: "Our risk model; ranks patches by benefit ÷ cost." },
  ml_ilp: { name: "ML + ILP", color: "#39ff14", desc: "Our risk model; exact optimum for the linear budget problem." },
  ml_nsga2: { name: "ML + NSGA-II", color: "#ff3b5c", desc: "Our risk model; genetic search, handles non-linear extensions." },
};
const ICON = {
  home: "M3 11l9-8 9 8v9a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z",
  flow: "M4 6h6v4H4zM14 14h6v4h-6zM10 8h4a2 2 0 0 1 2 2v4",
  db: "M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zM4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6",
  brain: "M9 4a3 3 0 0 0-3 3 3 3 0 0 0-2 5 3 3 0 0 0 3 5 3 3 0 0 0 5 1V5a3 3 0 0 0-3-1zM15 4a3 3 0 0 1 3 3 3 3 0 0 1 2 5 3 3 0 0 1-3 5 3 3 0 0 1-5 1",
  bug: "M8 8h8v8a4 4 0 0 1-8 0zM9 4l1.5 2M15 4l-1.5 2M4 10h4M16 10h4M4 16h4M16 16h4",
  net: "M12 4a2 2 0 1 0 0 .01zM5 19a2 2 0 1 0 0 .01zM19 19a2 2 0 1 0 0 .01zM12 6v6M12 12l-6 5M12 12l6 5",
  plan: "M9 11l3 3 8-8M4 12v7h14",
  gene: "M6 3c0 6 12 6 12 12M18 3c0 6-12 6-12 12M6 21c0-2 2-3 4-4M18 21c0-2-2-3-4-4",
  check: "M4 19V9M10 19V5M16 19v-7M22 19H2",
  bolt: "M13 2L4 14h7l-1 8 9-12h-7z",
  road: "M5 21V4M5 5h12l-2 4 2 4H5",
  sun: "M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M5.6 18.4L7 17M17 7l1.4-1.4M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z",
  moon: "M20 14.5A8 8 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z",
  play: "M7 4l13 8-13 8z", note: "M5 4h14v16H5zM8 9h8M8 13h8M8 17h5", db2: "M12 4v16M4 12h16",
};
const ic = (k, s = 18) => `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="${ICON[k]}"/></svg>`;

async function api(path, params = {}) {
  const u = new URL(path, location.origin);
  for (const k in params) u.searchParams.set(k, params[k]);
  const r = await fetch(u), j = await r.json();
  if (j.error) throw new Error(j.error);
  return j;
}
const planParams = () => ({ strategy: ST.strategy, pct: ST.pct, dt: ST.dt, deps: ST.deps ? 1 : 0, ext: ST.ext ? 1 : 0 });
const debounce = (f, ms = 250) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => f(...a), ms); }; };
const pc = (v, d = 1) => nf(v, d) + "%";
function toast(msg) { const t = $("#toast"); t.textContent = msg; t.classList.add("on"); clearTimeout(t._t); t._t = setTimeout(() => t.classList.remove("on"), 2600); }

/* ---------- shared UI blocks ---------- */
function head(p) {   // title only: no explanation boxes, you present the page yourself
  return `<div class="kick">${String(p.kick).replace(/^Step \d+ · /, "")}</div><h1 class="title">${p.title}</h1>`;
}
const kpi = (label, value, sub = "", cls = "", extra = "") => `<div class="card kpi ${cls}"><div class="v">${value}</div><div class="l">${label}</div><div class="s">${sub}</div>${extra}</div>`;
function openDrawer(kick, title, html) {
  $("#dk").textContent = kick; $("#dt").textContent = title; $("#db").innerHTML = html;
  $("#drawer").classList.add("open"); $("#scrim").classList.add("on");
}
function closeDrawer() { $("#side").classList.remove("open"); $("#drawer").classList.remove("open"); $("#scrim").classList.remove("on"); $("#modal").classList.remove("on"); }
function table(host, rows, cols, o = {}) {
  /* cols: {k,label,num,fmt,sort}; o:{pageSize,onRow,selKey,sortKey,desc,empty} */
  let sortKey = o.sortKey || cols[0].k, desc = o.desc ?? true, page = 0; const size = o.pageSize || 12;
  const draw = () => {
    const c = cols.find(c => c.k === sortKey) || cols[0];
    const sorted = [...rows].sort((a, b) => { const x = a[sortKey], y = b[sortKey]; return (typeof x === "string" ? x.localeCompare(y) : x - y) * (desc ? -1 : 1); });
    const pages = Math.max(1, Math.ceil(sorted.length / size)); page = Math.min(page, pages - 1);
    const part = sorted.slice(page * size, page * size + size);
    host.innerHTML = `<div class="tw"><table><thead><tr>${cols.map(c => `<th class="${c.num ? "num" : ""} ${c.k === sortKey ? "sorted" : ""}" data-k="${c.k}">${c.label}${c.k === sortKey ? (desc ? " ↓" : " ↑") : ""}</th>`).join("")}</tr></thead>
    <tbody>${part.length ? part.map((r, i) => `<tr class="${o.onRow ? "click" : ""} ${o.selKey && r[o.selKey.k] === o.selKey.v ? "sel" : ""}" data-i="${rows.indexOf(r)}">${cols.map(c => `<td class="${c.num ? "num" : ""}">${c.fmt ? c.fmt(r[c.k], r) : esc(r[c.k])}</td>`).join("")}</tr>`).join("") : `<tr><td colspan="${cols.length}" class="mut">${o.empty || "No rows"}</td></tr>`}</tbody></table></div>
    <div class="pager"><span>${sorted.length} rows</span><button class="btn ghost sm" data-p="-1" ${page === 0 ? "disabled" : ""}>‹ Prev</button><span>${page + 1} / ${pages}</span><button class="btn ghost sm" data-p="1" ${page >= pages - 1 ? "disabled" : ""}>Next ›</button></div>`;
    $$("th", host).forEach(th => th.onclick = () => { const k = th.dataset.k; if (k === sortKey) desc = !desc; else { sortKey = k; desc = true; } draw(); });
    $$("[data-p]", host).forEach(b => b.onclick = () => { page += +b.dataset.p; draw(); });
    if (o.onRow) $$("tbody tr.click", host).forEach(tr => tr.onclick = () => o.onRow(rows[+tr.dataset.i]));
  };
  draw();
}
function setBusy(el, on) { el && el.classList.toggle("busy", on); }

/* ---------- shell ---------- */
function buildShell() {
  const groups = {};
  NAV.filter(p => !p.hidden).forEach(p => (groups[p.group] ||= []).push(p));
  $("#side").innerHTML = `<div class="brand"><div class="mark">${ic("bolt", 20)}</div><div><b>Exploit-Aware<br>Patch Prioritization</b><span>IS353IA · AIML Lab</span></div></div>` +
    Object.entries(groups).map(([g, ps]) => `<div class="navgroup">${g}</div>` + ps.map(p => `<a class="nav" data-id="${p.id}" href="#/${p.id}"><span class="n">${p.n}</span>${esc(p.nav)}</a>`).join("")).join("") +
    `<div class="sidefoot">Prototype · all data is <b>synthetic</b></div>`;
  $("#top").innerHTML = `<button class="iconbtn menubtn" id="menu" aria-label="Menu">☰</button><span class="pill syn"><i></i>Synthetic data · prototype</span><span class="pill" id="invpill" style="cursor:pointer" title="Generate a new random network inventory"></span><span class="grow"></span>`;
  $("#invpill").onclick = openInventoryModal;
  $("#menu").onclick = () => { $("#side").classList.add("open"); $("#scrim").classList.add("on"); };
  $("#dx").onclick = closeDrawer; $("#scrim").onclick = closeDrawer;
  document.addEventListener("keydown", e => {
    if (e.target.matches("input,select,textarea")) return;
    if (e.key === "Escape") closeDrawer();
  });
}
function updatePill() {
  const m = ST.meta;
  $("#invpill").innerHTML = m.source === "upload"
    ? `${ic("net", 14)} <b style="color:var(--acc)">uploaded</b> ${esc(m.name)} · ${m.hosts} hosts · ${m.patches} patches`
    : `${ic("net", 14)} synthetic network · ${m.hosts} hosts · ${m.patches} patches`;
}
function openInventoryModal() {
  const m = $("#modal");
  m.innerHTML = `<h2>New network inventory</h2><p class="sub">Generates a fresh random network (hosts, exposure, criticality, installed products, dependencies) from the same CVE pool. Every optimizer re-runs on it.</p>
  <label class="f">Random seed</label><input type="number" id="m-seed" value="${Math.floor(Math.random() * 900 + 100)}">
  <label class="f">Number of hosts (200–500)</label><input type="number" id="m-hosts" value="300" min="200" max="500">
  <div style="display:flex;gap:10px;margin-top:20px"><button class="btn" id="m-go">Generate</button><button class="btn ghost" id="m-x">Cancel</button></div>`;
  m.classList.add("on"); $("#scrim").classList.add("on");
  $("#m-x").onclick = closeDrawer;
  $("#m-go").onclick = async () => {
    $("#m-go").disabled = true; $("#m-go").textContent = "Generating…";
    try { ST.meta = await api("/api/inventory", { seed: $("#m-seed").value, hosts: $("#m-hosts").value }); ST.plan = null; ST.strategies = null; updatePill(); closeDrawer(); toast(`New inventory: ${ST.meta.hosts} hosts, ${ST.meta.patches} patches`); route(true); }
    catch (e) { toast("Error: " + e.message); closeDrawer(); }
  };
}

/* ---------- router ---------- */
let _routeToken = 0;
async function route(force) {
  const id = (location.hash.replace(/^#\//, "") || "home").split("?")[0];
  const page = PAGES[id] || PAGES.home, tok = ++_routeToken;
  $$(".nav").forEach(n => n.classList.toggle("on", n.dataset.id === page.id)); closeDrawer();
  const v = $("#view"); v.style.animation = "none"; void v.offsetWidth; v.style.animation = "";
  v.innerHTML = `<div class="card"><div class="skel" style="width:40%;margin-bottom:12px"></div><div class="skel" style="width:80%;margin-bottom:8px"></div><div class="skel" style="width:65%"></div></div>`;
  try { const html = await page.render(v, tok); if (tok !== _routeToken) return; }
  catch (e) { if (tok === _routeToken) v.innerHTML = `<div class="card"><h2>Something went wrong</h2><p class="mut">${esc(e.message)}</p></div>`; console.error(e); }
  if (!force) scrollTo({ top: 0 });
  // pages that are not tabs: a back button; the Planner gets buttons that open them
  const t = $("#view .title");
  if (t && !$("#view .pagelinks")) {
    const links = page.hidden ? [["planner", "← Planner"]] : page.id === "planner" ?
      [["upload", "Upload your data"], ["network", "Network view"], ["pareto", "Optimizer lab"], ["evidence", "Backtest results"]] : [];
    if (links.length) t.insertAdjacentHTML("afterend", `<div class="pagelinks">${links.map(([id, l]) => `<a class="btn ghost sm" href="#/${id}">${l}</a>`).join("")}</div>`);
  }
}
window.addEventListener("hashchange", () => route());

/* ---------- boot ---------- */
async function boot() {
  document.documentElement.dataset.theme = "dark";  // single radium-on-black terminal theme
  buildShell();
  try { ST.meta = await api("/api/meta"); ST.dt = Math.round(ST.meta.downtime_default); updatePill(); }
  catch (e) { $("#view").innerHTML = `<div class="card"><h2>Server not reachable</h2><p>${esc(e.message)}</p></div>`; return; }
  route();
}
