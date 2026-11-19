/* Pages 6-11: network, planner, optimizer lab, evidence, extensions, roadmap. */
const expTag = e => `<span class="tag ${e === "internet" ? "bad" : e === "dmz" ? "amb" : ""}">${e}</span>`;
async function ensurePlan() { if (!ST.plan || ST.plan.strategy !== ST.strategy || ST.plan.pct !== ST.pct) ST.plan = await api("/api/plan", planParams()); return ST.plan; }

/* ============================== 6. NETWORK & RISK ============================== */
PAGES.network.render = async (v, token) => {
  const plan = await ensurePlan(), w = ST.meta.weights;
  if (token !== _routeToken) return;
  v.innerHTML = head({ kick: "Step 6 · Network & risk model", title: "Turning CVE probabilities into host-level risk", lede: "A simulated enterprise network: every host has an exposure level and a business criticality. A patch updates one product on one host and removes every CVE of that product there.",
    explain: { what: "The simulated network drawn as internet → DMZ → internal tiers. Colour shows how much risk a host still carries after the current patch plan; a ring means the host receives a patch.", why: "The same CVE is far more dangerous on an internet-facing, critical server than on an isolated internal one. Optimising patches means optimising where risk sits, not just which CVEs exist.", say: "Switch colour to 'before patching', then back to 'after'. Click a red internet-facing host to show what its patches are worth. The formula below is the heart of the risk model." } }) +
    `<div class="grid g21"><div class="card"><div class="head"><div class="grow"><div class="seg" id="n-mode"><button class="on" data-m="residual">Risk after plan</button><button data-m="initial">Risk before patching</button></div></div><div class="chips" id="n-ex"><span class="chip on" data-e="internet">internet</span><span class="chip on" data-e="dmz">DMZ</span><span class="chip on" data-e="internal">internal</span></div></div>
      <svg class="net" id="n-svg" viewBox="0 0 1000 560"></svg><p class="caption">Inner to outer contours: internal, DMZ, internet. Circle size indicates criticality. Filled red circles exceed half the highest initial host risk. A blue tick marks a selected patch. Dotted lines connect the selected host to adjacent hosts.</p></div>
    <div class="card" id="n-panel"><h3>Select a host</h3><p class="sub">Click any node to see its products, patch values and position in the topology.</p></div></div>
    <div class="grid g2 mt"><div class="card"><h3>Risk of a CVE on a host</h3><div class="formula"><em>risk</em>(CVE, host) = <u>p_exploit</u> × impact(C,I,A) × criticality × exposure_weight</div><p class="sub" style="margin-top:10px">Exposure weights: internet <b class="mono">${w.internet}</b> · DMZ <b class="mono">${w.dmz}</b> · internal <b class="mono">${w.internal}</b>. Impact is the CVSS confidentiality / integrity / availability triple scaled to 0–1. <u style="text-decoration:none;color:var(--acc2)">p_exploit</u> is the calibrated model output — the only place ML enters.</p></div>
    <div class="card"><h3>Benefit and cost of a patch</h3><div class="formula"><em>benefit</em> = Σ risk of every CVE the patch removes<br><em>cost</em> = base effort hours (by software type) + downtime penalty × criticality</div><p class="sub" style="margin-top:10px">Dependencies: an application patch may require the host's OS patch first. Totals for this inventory: <b>${ST.meta.patches}</b> candidate patches, <b>${ST.meta.dependencies}</b> with a prerequisite, total effort <b>${nf(ST.meta.total_cost)} h</b>.</p></div></div>`;
  let mode = "residual", sel = null; const on = new Set(["internet", "dmz", "internal"]);
  const tiers = [["internal",0,.64],["dmz",.64,.84],["internet",.84,1]];
  const locations = new Map();
  const point = (r,a) => {
    const contour = 1 + .025*Math.cos(4*a) + .045*Math.sin(3*a);
    return [500+450*r*contour*Math.cos(a),280+245*r*contour*Math.sin(a)];
  };
  for(const [tier,inner,outer] of tiers) {
    const hosts = plan.hosts.filter(h=>h.exposure===tier);
    hosts.forEach((h,i)=>{
      const radius = Math.sqrt(inner**2 + (outer**2-inner**2)*(i+.5)/hosts.length);
      locations.set(h.i,point(radius,i*2.39996));
    });
  }
  const px = h => locations.get(h.i)[0], py = h=>locations.get(h.i)[1];
  const draw = () => {
    const svg = $("#n-svg"); svg.innerHTML = ""; const hs = plan.hosts, mx = Math.max(...hs.map(h => h.initial)) || 1;
    tiers.forEach(([, ,outer])=>{
      const pts = Array.from({length:160},(_,i)=>point(outer,i*Math.PI/80).join(",")).join(" ");
      S("polygon",{points:pts,fill:"none",stroke:"var(--line2)","stroke-width":1.5},svg);
    });
    if (sel && on.has(sel.exposure)) {
      hs.filter(h => on.has(h.exposure) && (h.parent===sel.i || h.i===sel.parent)).forEach(h=>{
        S("line",{x1:px(sel),y1:py(sel),x2:px(h),y2:py(h),stroke:"var(--ink2)","stroke-dasharray":"3 4"},svg);
      });
    }
    hs.filter(h => on.has(h.exposure)).forEach(h => {
      const high = h[mode] > mx / 2;
      const c = S("circle",{cx:px(h),cy:py(h),r:3+h.crit,fill:high?"var(--bad)":"var(--bg)",stroke:sel?.i===h.i?"var(--acc)":"var(--ink2)","stroke-width":sel?.i===h.i?3:1.3,style:"cursor:pointer"},svg);
      if (h.patched) S("path",{d:`M${px(h)-3} ${py(h)}l3 3 7 -9`,fill:"none",stroke:"var(--acc)","stroke-width":2.8,"pointer-events":"none"},svg);
      c.addEventListener("mousemove", ev => TT.show(`<b>${esc(h.host)}</b> · ${h.exposure}<br>criticality ${h.crit}<br>risk before: ${nf(h.initial, 1)}<br>risk after plan: ${nf(h.residual, 1)}<br>${h.patched ? "receives a patch" : "no patch selected"}`, ev.clientX, ev.clientY));
      c.addEventListener("mouseleave", () => TT.hide()); c.addEventListener("click", () => { sel = h; draw(); panel(h); });
    });
    // Labels sit stacked in the empty top-left corner, with a leader line to the middle of each band.
    [...tiers].reverse().forEach(([tier,inner,outer], k) => {
      const [bx,by] = point((inner+outer)/2,-2.3), ty = 26 + k*28;
      const t = S("text",{x:14,y:ty,class:"tier-label","pointer-events":"none"},svg); t.textContent = tier.toUpperCase();
      const tx = 14 + t.getComputedTextLength() + 6;
      S("polyline",{points:`${tx},${ty-5} ${tx+12},${ty-5} ${bx},${by}`,fill:"none",stroke:"var(--ink)","stroke-width":1,"pointer-events":"none"},svg);
      S("circle",{cx:bx,cy:by,r:2.5,fill:"var(--ink)","pointer-events":"none"},svg);
    });
  };
  const panel = async h => {
    const d = await api("/api/host", { host: h.host }), chosen = new Set(plan.plan.map(p => p.patch_id));
    if (!$("#n-panel") || sel?.i !== h.i) return;
    $("#n-panel").innerHTML = `<div class="kick" style="margin-bottom:4px">${expTag(d.exposure)} criticality ${d.criticality}</div><h2 class="mono">${esc(d.host)}</h2><div class="sub">${d.parent ? `Reached via <b>${esc(d.parent)}</b> · ` : "Edge host · "}${d.children} host${d.children === 1 ? "" : "s"} behind it</div>
      <div class="grid g2" style="gap:10px"><div class="card flat kpi"><div class="v">${nf(h.initial, 1)}</div><div class="l">risk before</div></div><div class="card flat kpi acc"><div class="v"><mark>${nf(h.residual, 1)}</mark></div><div class="l">risk after plan</div></div></div>
      <h3 class="mt">Candidate patches on this host</h3><div class="tw" style="max-height:300px"><table><thead><tr><th>Product</th><th class="num">Benefit</th><th class="num">Cost h</th><th></th></tr></thead><tbody>${d.patches.map(p => `<tr><td>${esc(p.product)}${p.requires >= 0 ? ' <span class="tag">dep</span>' : ""}</td><td class="num">${nf(p.benefit, 1)}</td><td class="num">${nf(p.cost, 1)}</td><td>${chosen.has(p.patch_id) ? '<span class="tag good">selected</span>' : '<span class="tag">skipped</span>'}</td></tr>`).join("")}</tbody></table></div>`;
  };
  $$("#n-mode button").forEach(b => b.onclick = () => { mode = b.dataset.m; $$("#n-mode button").forEach(x => x.classList.toggle("on", x === b)); draw(); });
  $$("#n-ex .chip").forEach(c => c.onclick = () => { on.has(c.dataset.e) ? on.delete(c.dataset.e) : on.add(c.dataset.e); c.classList.toggle("on"); draw(); });
  draw();
  const top = [...plan.hosts].sort((a, b) => b.initial - a.initial)[0]; if (top) { sel = top; draw(); panel(top); }
};

/* ============================== 7. PATCH PLANNER ============================== */
PAGES.planner.render = async v => {
  v.innerHTML = head({ kick: "Step 8 · The live planner", title: "Give it a budget, get a justified patch list", lede: "Choose a patching budget, a strategy and the real-world limits. The planner returns the exact patches for the next maintenance window — with the reason for each one.",
    explain: { what: "Controls on the left; on the right, the selected patches, what they cost, how much modelled risk they remove, and how every strategy compares at the same budget.", why: "This is the deliverable an IT manager needs: a ranked list for the next window and a clear view of how much risk each extra hour buys.", say: "Start at 20 %. Drag the budget and watch the bars move. Flip 'Hindsight' to reveal which strategy actually protected against later-exploited CVEs. Open a patch row to show its reasoning." } }) +
    `<div class="grid g31"><aside><div class="card" id="pl-ctl" style="position:sticky;top:calc(var(--chrome-h,112px) + 14px)">
      <label class="f">Patching budget <span class="val"><span id="v-pct">${ST.pct}</span>% of total effort</span></label><input type="range" id="pct" min="5" max="40" value="${ST.pct}">
      <label class="f">Strategy</label><div id="strat">${Object.entries(STRAT).map(([k, s]) => `<div class="opt ${k === ST.strategy ? "on" : ""}" data-s="${k}"><i class="dot" style="background:${s.color}"></i><div><b>${s.name}</b><span>${s.desc}</span></div></div>`).join("")}</div>
      <label class="f">Downtime window <span class="val"><span id="v-dt">${ST.dt}</span>% of total</span></label><input type="range" id="dt" min="5" max="60" value="${ST.dt}">
      <div class="toggle ${ST.deps ? "on" : ""}" id="t-deps"><span>Respect dependencies<small>App patches need the host OS patch first</small></span><div class="sw"></div></div>
      <div class="toggle ${ST.ext ? "on" : ""}" id="t-ext"><span>Attack-path objective<small>Applies to NSGA-II · patching a gateway also lowers downstream risk</small></span><div class="sw"></div></div>
      <div class="toggle ${ST.hindsight ? "on" : ""}" id="t-hind"><span>Hindsight (reveal later KEV)<small>Backtest outcomes — hidden by default</small></span><div class="sw"></div></div></div></aside>
    <div id="pl-main" style="position:relative"></div></div>`;
  const planner = $("#pl-main");
  let seq = 0, filter = "", exps = new Set(["internet", "dmz", "internal"]);
  const rerender = () => { if (ST.plan) drawMain(); if (ST.strategies) drawCompare(); };
  const refresh = async () => {
    if (!planner.isConnected) return;
    const my = ++seq; setBusy($("#pl-main"), true);
    try { const plan = await api("/api/plan", planParams()); if (my !== seq || !planner.isConnected) return; ST.plan = plan; ST.strategies = null; drawMain(); setBusy($("#pl-main"), false);
      const st = await api("/api/strategies", planParams()); if (my !== seq || !planner.isConnected) return; ST.strategies = st; drawCompare(); }
    catch (e) { toast("Error: " + e.message); } finally { if (my === seq) setBusy($("#pl-main"), false); }
  };
  const drawMain = () => {
    const p = ST.plan;
    $("#pl-main").innerHTML = `<div class="grid g4" style="grid-template-columns:repeat(auto-fit,minmax(170px,1fr))">
      ${kpi("Patches selected", p.n_selected, `of ${ST.meta.patches} candidates · ${p.hosts_touched} hosts`)}
      ${kpi("Effort used", nf(p.cost_used) + " h", `budget ${nf(p.budget)} h`, "", `<div class="bar"><i style="width:${Math.min(100, p.cost_used / p.budget * 100)}%"></i></div>`)}
      ${kpi("Modelled risk removed", pc(p.risk_removed_pct, 1), ST.ext ? `attack-path-aware: ${pc(p.ext_removed_pct, 1)}` : "expected-exploitation weighted", "acc")}
      ${kpi("Later-exploited covered", ST.hindsight ? pc(p.coverage_pct, 1) : "· · ·", ST.hindsight ? `${p.exploited_covered} of ${p.total_exploited} host-CVE instances` : "hidden until hindsight is on", "amb")}
      ${kpi("Solve time", nf(p.runtime_s, 2) + " s", STRAT[p.strategy].name)}</div>
    <div class="card mt" id="cmpcard"><div class="head"><div class="grow"><h3>How every strategy does at this budget</h3><div class="sub">Same inventory, same ${p.pct}% budget. Computing the full set (NSGA-II included) takes a moment the first time.</div></div></div><div id="cmp-body"><div class="skel" style="width:70%"></div></div></div>
    <div class="card mt"><div class="head"><div class="grow"><h3>Recommended patches</h3><div class="sub">Sorted by benefit. Click a row for the reasoning behind it.</div></div><button class="btn ghost sm" id="csv">Download CSV</button></div>
    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px"><div style="flex:1;min-width:200px"><input type="text" id="pl-q" placeholder="Filter by host or product…" value="${esc(filter)}"></div><div class="chips" id="pl-ex">${["internet", "dmz", "internal"].map(e => `<span class="chip ${exps.has(e) ? "on" : ""}" data-e="${e}">${e}</span>`).join("")}</div></div><div id="pl-table"></div></div>`;
    drawTable();
    $("#pl-q").oninput = debounce(e => { filter = $("#pl-q").value.toLowerCase(); drawTable(); }, 150);
    $$("#pl-ex .chip").forEach(c => c.onclick = () => { exps.has(c.dataset.e) ? exps.delete(c.dataset.e) : exps.add(c.dataset.e); c.classList.toggle("on"); drawTable(); });
    $("#csv").onclick = () => { const cols = Object.keys(p.plan[0]); const csv = [cols.join(",")].concat(p.plan.map(r => cols.map(k => JSON.stringify(r[k])).join(","))).join("\n"); const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" })); a.download = "patch_plan.csv"; a.click(); };
    if (ST.strategies) drawCompare();
  };
  const drawTable = () => {
    const rows = ST.plan.plan.filter(r => exps.has(r.exposure) && (!filter || (r.host + " " + r.product).toLowerCase().includes(filter)));
    table($("#pl-table"), rows, [
      { k: "patch_id", label: "#", num: 1 }, { k: "host", label: "Host" }, { k: "product", label: "Product", fmt: (v, r) => esc(v) + (r.requires >= 0 ? ' <span class="tag">dep</span>' : "") },
      { k: "exposure", label: "Exposure", fmt: expTag }, { k: "criticality", label: "Crit", num: 1 }, { k: "n_cves", label: "CVEs", num: 1 },
      { k: "benefit", label: "Benefit", num: 1, fmt: v => `<b>${nf(v, 2)}</b>` }, { k: "cost", label: "Cost h", num: 1, fmt: v => nf(v, 1) }, { k: "ratio", label: "Benefit/cost", num: 1, fmt: v => nf(v, 2) },
      { k: "top_p", label: "Riskiest CVE", fmt: (v, r) => `<span class="mono small">${r.top_cve}</span> <span class="mut">p=${nf(v, 2)}</span>` },
      { k: "exploited", label: "Hindsight", num: 1, fmt: v => ST.hindsight ? (v ? `<span class="tag bad">${v} later KEV</span>` : '<span class="mut">–</span>') : '<span class="mut">·</span>' }],
      { sortKey: "benefit", pageSize: 10, onRow: r => openPatch(r), empty: "No patches match the filter." });
  };
  const drawCompare = () => {
    const c = $("#cmp-body"); if (!c) return; const st = ST.strategies;
    const rows = (k, f) => st.map(s => ({ label: STRAT[s.strategy].name, value: s[k], color: STRAT[s.strategy].color, hi: s.strategy === ST.strategy }));
    c.innerHTML = `<div class="grid ${ST.hindsight || ST.ext ? "g2" : ""}" style="gap:26px"><div><h3 style="font-size:18px">Modelled risk removed</h3><div id="cb1"></div></div>
      ${ST.hindsight ? `<div><h3 style="font-size:18px">Later-exploited CVEs covered <span class="tag amb">hindsight</span></h3><div id="cb2"></div></div>` : ""}${ST.ext ? `<div><h3 style="font-size:18px">Attack-path-aware risk removed</h3><div id="cb3"></div></div>` : ""}</div>
      <p class="small mut" style="margin:10px 0 0">${ST.hindsight ? "Hindsight on: the right-hand chart is the backtest metric — fraction of CVEs that really entered KEV later and were fixed by the plan." : "The model's own view of risk. Turn on Hindsight to check it against what attackers actually exploited."}</p>`;
    BarChart($("#cb1"), { max: 100, fmt: v => pc(v, 1), rows: rows("risk_removed_pct") });
    if (ST.hindsight) BarChart($("#cb2"), { max: 100, fmt: v => pc(v, 1), rows: rows("coverage_pct") });
    if (ST.ext) BarChart($("#cb3"), { max: 100, fmt: v => pc(v, 1), rows: rows("ext_removed_pct") });
  };
  const openPatch = async r => {
    openDrawer(`Patch #${r.patch_id} · ${r.exposure}`, `${r.product} on ${r.host}`, `<div class="skel" style="width:60%"></div>`);
    const d = await api("/api/patch", { id: r.patch_id }), p = d.patch;
    $("#db").innerHTML = `<div class="callout acc" style="margin-bottom:16px"><b>Why selected.</b> It removes <b>${d.n_total_cves}</b> CVEs for <b>${nf(p.cost, 1)} h</b>, a benefit-to-cost ratio of <b>${nf(r.ratio, 2)}</b> — ${r.ratio >= 1.5 ? "among the best value in the network" : "good value for the budget available"}${d.requires ? `. It <b>requires</b> the ${esc(d.requires.product)} patch (#${d.requires.patch_id}) on the same host, which is included in the plan.` : "."}</div>
      <div class="grid g3" style="gap:10px;margin-bottom:16px"><div class="card flat kpi"><div class="v">${nf(p.benefit, 1)}</div><div class="l">benefit</div></div><div class="card flat kpi"><div class="v">${nf(p.cost, 1)}</div><div class="l">cost (h)</div></div><div class="card flat kpi"><div class="v">${nf(p.downtime, 1)}</div><div class="l">downtime (h)</div></div></div>
      <div class="formula" style="font-size:15px">benefit = Σ p_exploit × impact × <em>${p.criticality}</em> × <em>${ST.meta.weights[p.exposure]}</em><br>= <b>${nf(d.formula.sum_risk, 2)}</b> over ${d.n_total_cves} CVEs (mean p ${nf(d.formula.p_mean, 3)})<br>cost = ${nf(p.cost, 1)} h = effort + downtime penalty × criticality ${p.criticality}</div>
      <h3 class="mt">Highest-risk CVEs removed</h3><div class="tw" style="max-height:340px"><table><thead><tr><th>CVE</th><th class="num">p</th><th class="num">CVSS</th><th class="num">EPSS</th><th class="num">risk</th>${ST.hindsight ? "<th>KEV later</th>" : ""}</tr></thead><tbody>${d.cves.map(c => `<tr><td class="mono small">${c.cve_id}</td><td class="num"><b>${nf(c.p_exploit, 2)}</b></td><td class="num">${nf(c.cvss, 1)}</td><td class="num">${nf(c.epss, 2)}</td><td class="num">${nf(c.risk, 2)}</td>${ST.hindsight ? `<td>${c.kev_later ? '<span class="tag bad">yes</span>' : '<span class="mut">–</span>'}</td>` : ""}</tr>`).join("")}</tbody></table></div>`;
  };
  const ch = f => () => { f(); debounced(); }; const debounced = debounce(refresh, 280);
  $("#pct").oninput = ch(() => { ST.pct = +$("#pct").value; $("#v-pct").textContent = ST.pct; });
  $("#dt").oninput = ch(() => { ST.dt = +$("#dt").value; $("#v-dt").textContent = ST.dt; });
  $$("#strat .opt").forEach(o => o.onclick = () => { ST.strategy = o.dataset.s; $$("#strat .opt").forEach(x => x.classList.toggle("on", x === o)); refresh(); });
  $("#t-deps").onclick = e => { ST.deps = !ST.deps; e.currentTarget.classList.toggle("on", ST.deps); refresh(); };
  $("#t-ext").onclick = e => { ST.ext = !ST.ext; e.currentTarget.classList.toggle("on", ST.ext); refresh(); };
  $("#t-hind").onclick = e => { ST.hindsight = !ST.hindsight; e.currentTarget.classList.toggle("on", ST.hindsight); rerender(); };
  refresh();
};

/* ============================== 8. OPTIMIZER LAB ============================== */
PAGES.pareto.render = async v => {
  v.innerHTML = head({ kick: "Step 9 · Optimizer lab", title: "Why a genetic algorithm when ILP is exact?", lede: "For the basic budgeted problem ILP is optimal — we say so openly. NSGA-II earns its place by returning the whole cost-vs-risk trade-off in a single run, and by handling objectives ILP cannot express.",
    explain: { what: "NSGA-II evolving a population of patch sets. Each generation the Pareto front — the best achievable risk reduction for every cost — moves up and fills out. The dashed line is the exact ILP optimum at your chosen budget.", why: "Managers ask 'what do I get for 10 more hours?'. The front answers that for every budget at once. And once risk depends on attack paths, ILP cannot follow but the GA can.", say: "Press Run and narrate the front climbing. Compare the final marker with the ILP line (gap ≈ 1–3 %). Then switch on the attack-path objective: ILP's line is no longer the optimum." } }) +
    `<div class="grid g31"><aside><div class="card"><label class="f">Budget to read off <span class="val"><span id="o-pct-v">${ST.pct}</span>%</span></label><input type="range" id="o-pct" min="5" max="40" value="${ST.pct}">
    <label class="f">Population <span class="val" id="o-pop-v">60</span></label><input type="range" id="o-pop" min="20" max="120" step="10" value="60">
    <label class="f">Generations <span class="val" id="o-gen-v">60</span></label><input type="range" id="o-gen" min="20" max="150" step="10" value="60">
    <div class="toggle" id="o-ext"><span>Attack-path objective<small>Non-linear — ILP cannot solve this exactly</small></span><div class="sw"></div></div>
    <button class="btn amb" id="o-run" style="width:100%;justify-content:center;margin-top:10px">${ic("play", 13)} Run NSGA-II</button><div id="o-status" class="small mut" style="margin-top:10px"></div></div>
    <div class="card mt flat"><h3>How NSGA-II works here</h3><ol class="small" style="color:var(--ink2);padding-left:18px;margin:0"><li>A chromosome is a yes/no vector over all candidate patches.</li><li>Two objectives: maximise risk removed, minimise effort.</li><li>Constraints (budget, downtime, dependencies) are enforced by repair + constraint-domination.</li><li>Selection by rank and crowding keeps the front spread out.</li></ol></div></aside>
    <div><div class="card"><div class="head"><div class="grow"><h3>Pareto front: effort vs modelled risk removed</h3><div class="sub" id="o-sub">Press Run to evolve the front live on the current network.</div></div></div><div id="o-chart"></div></div>
    <div class="grid g3 mt" id="o-kpis"></div></div></div>`;
  let ext = false;
  const upd = id => { $(`#${id}`).oninput = () => { const m = { "o-pct": "o-pct-v", "o-pop": "o-pop-v", "o-gen": "o-gen-v" }; $("#" + m[id]).textContent = $("#" + id).value + (id === "o-pct" ? "" : ""); }; };
  ["o-pct", "o-pop", "o-gen"].forEach(upd);
  $("#o-ext").onclick = e => { ext = !ext; e.currentTarget.classList.toggle("on", ext); };

  LineChart($("#o-chart"), { height: 340, xlabel: "Effort (% of total patch cost)", ylabel: "Modelled risk removed", xmax: 40, ymax: ST.meta.total_risk, series: [{ name: "front", color: "var(--acc)", pts: [[0, 0]] }], legend: false });
  $("#o-run").onclick = async () => {
    const pct = +$("#o-pct").value, btn = $("#o-run"); btn.disabled = true; btn.textContent = "Evolving…"; $("#o-status").textContent = "Running NSGA-II on the server…";
    try {
      const d = await api("/api/pareto", { pct, pop: $("#o-pop").value, gens: $("#o-gen").value, ext: ext ? 1 : 0 });
      let i = matchMedia("(prefers-reduced-motion: reduce)").matches ? d.snapshots.length-1 : 0; const total = d.total;
      const step = () => { if (!btn.isConnected) return; const s = d.snapshots[i], last = i === d.snapshots.length - 1;
        LineChart($("#o-chart"), { height: 340, xlabel: "Effort (% of total patch cost)", ylabel: ext ? "Attack-path-aware risk removed" : "Modelled risk removed", xmax: 40, ymax: total, legend: false,
          scatter: d.snapshots.slice(0,i).flatMap(prev=>prev.cost_pct.map((c,k)=>[c,prev.risk[k]])).filter(([x,y])=>s.cost_pct.some((c,k)=>c<=x && s.risk[k]>=y && (c<x || s.risk[k]>y))),
          series: [{ name: "Pareto front", color: "var(--acc)", dots: true, width: 2.6, pts: s.cost_pct.map((c, k) => [c, s.risk[k]]) }],
          hlines: last ? [{ y: d.ilp, label: `ILP (linear) at ${pct}% budget: ${nf(d.ilp, 0)}`, color: "var(--acc2)" }] : [], marks: last ? [{ x: d.selected_cost_pct ?? (s.cost_pct[s.risk.findIndex(r => Math.abs(r-d.selected)<.006)] || 0), y: d.selected, label: `NSGA-II: ${nf(d.selected, 0)}`, color: "var(--bad)" }] : [] });
        $("#o-sub").textContent = `Generation ${s.gen} of ${d.gens} · ${s.risk.length} non-dominated solutions`;
        if (!last) { i++; setTimeout(step, 70); } else finish(); };
      const finish = () => { $("#o-kpis").innerHTML = kpi("Runtime", nf(d.runtime_s, 1) + " s", `pop ${d.pop} × ${d.gens} generations`) + kpi(`NSGA-II @ ${pct}%`, nf(d.selected, 0), "risk removed", "acc") + kpi(d.gap_pct >= 0 ? "Gap to ILP" : "Beats ILP by", nf(Math.abs(d.gap_pct), 2) + "%", ext ? "ILP optimises the linear objective only" : "target: within 2–5 %", d.gap_pct < 0 ? "amb" : "");
        $("#o-status").textContent = ext ? "Attack-path objective: ILP's linear plan is no longer optimal — the GA can exceed it." : "Done."; btn.disabled = false; btn.innerHTML = `${ic("play", 13)} Run again`; };
      step();
    } catch (e) { toast("Error: " + e.message); btn.disabled = false; btn.textContent = "Run NSGA-II"; }
  };
};

/* ============================== 9. BACKTEST EVIDENCE ============================== */
PAGES.evidence.render = async (v, token) => {
  const [cmp, mod, whatif] = await Promise.all([api("/api/compare"), api("/api/model"), api("/api/whatif")]);
  const order = ["random", "cvss_sorted", "epss_sorted", "ml_greedy", "ml_ilp", "ml_nsga2"], M = mod.metrics, n = cmp.n_inventories;
  const at = (s, b) => cmp.summary.find(r => r.strategy === s && Math.abs(r.budget_frac - b) < 1e-6);
  const budgets = [0.1, 0.2, 0.3];
  if (token !== _routeToken) return;
  v.innerHTML = head({ kick: "Backtest results", title: "Which strategy covers the most later-exploited CVEs?", lede: "At each patch budget, the same strategies are tested against later KEV labels across independently simulated inventories. Whiskers show variation between networks." }) +
    `<div class="card"><div class="head"><div class="grow"><h3>Coverage of later-exploited CVEs</h3><div class="sub">Mean ± std over ${n} inventories</div></div><div class="seg" id="e-b">${budgets.map((b, i) => `<button class="${b === 0.2 ? "on" : ""}" data-b="${b}">${b * 100}% budget</button>`).join("")}</div></div>
    <p id="e-finding" class="finding"></p><div class="grid g2" style="gap:30px"><div><h3 style="font-size:18px">% of later-KEV CVEs covered</h3><div id="e-cov"></div></div><div><h3 style="font-size:18px">Residual modelled risk (lower is better)</h3><div id="e-res"></div></div></div>
    <div class="grid g2 mt" style="gap:30px"><div><h3 style="font-size:18px">Optimality gap vs ILP (% of risk removed)</h3><div id="e-gap"></div></div><div><h3 style="font-size:18px">Runtime per solve (seconds)</h3><div id="e-rt"></div></div></div></div>
    <div class="grid g2 mt"><div class="card"><h3>Coverage as the budget grows</h3><p class="sub">First inventory, budget swept from 2 % to 40 %. Hover to compare.</p><div id="e-c1"></div></div><div class="card"><h3>Risk left as the budget grows</h3><p class="sub">Residual modelled risk — the lower the curve, the better.</p><div id="e-c2"></div></div></div>
    <section class="card mt"><h3>Success criteria</h3><ul id="criteria"></ul></section><div class="callout mt"><b>Reading it honestly.</b> The ML-based plans cover roughly twice as many later-exploited CVEs as CVSS-sorted at low budgets. The EPSS-sorted baseline is close behind (${nf(at("epss_sorted", 0.2).coverage_mean, 1)}% vs ${nf(at("ml_ilp", 0.2).coverage_mean, 1)}% at a 20% budget) because EPSS carries signals ours cannot see. Our plans keep a small edge by also weighing <i>cost and where each host sits</i> — but on this synthetic data the margin over EPSS is modest and should not be over-read. Greedy is close to ILP; NSGA-II is a little behind on this simple linear problem, as expected.</div>`;
  const draw = b => {
    const winner = order.reduce((a,s)=>at(s,b).coverage_mean > at(a,b).coverage_mean ? s : a);
    const extended = k => whatif.extended.find(r=>r.strategy===k).ext_pct_mean;
    const checks = [
      [M.random_forest.pr_auc > M.cvss_baseline.pr_auc && M.random_forest["recall@100"] > M.cvss_baseline["recall@100"],"Random Forest exceeds CVSS-only on PR-AUC and recall@100."],
      [order.slice(3).every(s=>at(s,b).coverage_mean > at("cvss_sorted",b).coverage_mean),"All ML strategies cover more later-exploited CVEs than CVSS-sorted at this budget."],
      [at("ml_nsga2",b).gap_mean <= 5 && extended("ml_nsga2_ext") >= extended("ml_greedy"),"NSGA-II falls within 5% of ILP on linear risk and matches or exceeds Greedy on extended risk."],
      [n>=20 && order.every(s=>Number.isFinite(at(s,b).coverage_std)), "Coverage includes a mean and standard deviation across at least 20 inventories."]
    ];
    $("#e-finding").innerHTML = `<b>${STRAT[winner].name}</b> covers <mark>${pc(at(winner,b).coverage_mean,1)}</mark> of later-exploited CVEs at a ${b*100}% budget.`;
    $("#criteria").innerHTML=checks.map(([ok,label])=>`<li><b>${ok?"✓":"✗"}</b> ${label}</li>`).join("");
    const rows = k => order.map(s => { const r = at(s, b); return { label: STRAT[s].name + (k==="coverage" && s===winner ? " · highest" : ""), value: r[k + "_mean"] ?? r[k], err: r[k + "_std"], color: STRAT[s].color, hi: k === "coverage" && s===winner }; });
    coverageGroups($("#e-cov"), budgets, order, at, b);
    BarChart($("#e-res"), { fmt: v => nf(v, 0), rows: rows("residual") });
    BarChart($("#e-gap"), { fmt: v => pc(v, 2), rows: ["ml_greedy", "ml_ilp", "ml_nsga2"].map(s => ({ label: STRAT[s].name, value: at(s, b).gap_mean, color: STRAT[s].color })) });
    BarChart($("#e-rt"), { fmt: v => nf(v, 2) + " s", rows: ["ml_greedy", "ml_ilp", "ml_nsga2"].map(s => ({ label: STRAT[s].name, value: at(s, b).runtime_mean, color: STRAT[s].color })) });
  };
  $$("#e-b button").forEach(bt => bt.onclick = () => { $$("#e-b button").forEach(x => x.classList.toggle("on", x === bt)); draw(+bt.dataset.b); }); draw(0.2);
  const ser = k => order.map((s,i) => ({ dash:["2 5","7 4","","2 4","","9 4"][i], name: STRAT[s].name, color: STRAT[s].color, width: s.startsWith("ml") ? 2.8 : 1.8, pts: cmp.curves.filter(r => r.strategy === s).map(r => [r.budget_pct, r[k]]) }));
  LineChart($("#e-c1"), { series: ser("coverage_pct"), xlabel: "Budget (% of total patch cost)", ylabel: "% covered", xmax: 40, ymax: 100, xfmt: v => nf(v, 0), yfmt: v => nf(v, 0) });
  LineChart($("#e-c2"), { series: ser("residual_risk"), xlabel: "Budget (% of total patch cost)", ylabel: "Residual risk", xmax: 40, xfmt: v => nf(v, 0) });
};

/* ============================== 10. EXTENSIONS ============================== */
PAGES.extend.render = async (v, token) => {
  const w = await api("/api/whatif"), ex = w.extended, rb = w.robust, g = w.gamma;
  const E = s => ex.find(r => r.strategy === s);
  if (token !== _routeToken) return;
  v.innerHTML = head({ kick: "Step 11 · Extensions", title: "Beyond the linear problem: attack paths and noisy costs", lede: "Two extensions from the synopsis: attack-path risk (patching a gateway also protects the hosts behind it) and robustness to errors in the cost estimates.",
    explain: { what: "Left: a non-linear objective where gateway patches reduce downstream risk. Right: what happens when the planner's cost estimates are wrong by 10–40 %.", why: "Real networks are not a sum of independent hosts, and real cost estimates are noisy. Showing both turns the GA from a curiosity into a justified choice.", say: "Draw the three-tier chain on the left, then show the bars: when risk depends on combinations of patches the linear ILP plan is no longer optimal, and NSGA-II edges past it (by a modest margin — say so)." } }) +
    `<div class="grid g2"><div class="card"><h3>Attack-path risk</h3><p class="sub">An attacker reaches internal hosts through the internet-facing and DMZ hosts in front of them.</p>
    <svg viewBox="0 0 520 130" width="100%"><g font-family="var(--sans)"><rect x="10" y="40" width="130" height="50" rx="1" fill="var(--surface2)" stroke="var(--bad)"/><text x="75" y="62" text-anchor="middle" style="fill:var(--ink);font-weight:600">Internet host</text><text x="75" y="80" text-anchor="middle">gateway</text>
    <rect x="195" y="40" width="130" height="50" rx="1" fill="var(--surface2)" stroke="var(--acc2)"/><text x="260" y="62" text-anchor="middle" style="fill:var(--ink);font-weight:600">DMZ host</text><text x="260" y="80" text-anchor="middle">pivot point</text>
    <rect x="380" y="40" width="130" height="50" rx="1" fill="var(--surface2)" stroke="var(--acc)"/><text x="445" y="62" text-anchor="middle" style="fill:var(--ink);font-weight:600">Internal host</text><text x="445" y="80" text-anchor="middle">crown jewels</text>
    <path d="M142 65h50M327 65h50" stroke="var(--ink2)" stroke-width="2"/><path d="M186 59l6 6-6 6M371 59l6 6-6 6" stroke="var(--ink2)" stroke-width="2" fill="none"/></g></svg>
    <div class="formula mt" style="font-size:15px">R(x) = Σ<sub>h</sub> residual<sub>h</sub>(x) · (1 + <em>γ</em> · pf<sub>h</sub>(x))<br>pf<sub>h</sub> = unpatched share of the upstream gateway's risk · γ = <b>${g}</b></div>
    <p class="small mut" style="margin:10px 0 0">Because pf depends on <i>which gateway patches were chosen</i>, the objective multiplies decisions together — it is no longer linear, so ILP can no longer return the exact optimum.</p></div>
    <div class="card"><h3>Attack-path-aware risk removed (20 % budget)</h3><p class="sub">Mean ± std over ${ex.length ? 20 : 0} inventories, all plans scored on the <b>attack-path</b> objective.</p><div id="x-ext"></div>
    <div class="callout acc small mt">NSGA-II optimises the attack-path objective directly; Greedy and ILP only see the linear benefit. Here NSGA-II removes <b>${nf(E("ml_nsga2_ext").ext_pct_mean - E("ml_ilp").ext_pct_mean, 2)}</b> points more than ILP and <b>${nf(E("ml_nsga2_ext").ext_pct_mean - E("ml_greedy").ext_pct_mean, 2)}</b> more than Greedy — a real but <b>modest</b> edge, because with γ = ${g} the linear benefit is already a good proxy. A stronger coupling between hosts would widen it (Phase 3).</div></div></div>
    <div class="grid g2 mt"><div class="card"><h3>Robustness to cost-estimate noise</h3><p class="sub">The planner sees costs multiplied by log-normal noise (σ); the plan is judged against true costs and the true budget.</p><div id="x-rb"></div></div>
    <div class="card"><h3>Budget overshoot</h3><p class="sub">How far the real effort exceeds the budget because the estimates were wrong.</p><div id="x-ov"></div><p class="small mut" style="margin:10px 0 0">Optimal plans sit exactly on the budget line, so any estimate error becomes an overshoot — a reason to keep a contingency margin in practice (Phase 3: chance-constrained planning).</p></div></div>`;
  BarChart($("#x-ext"), { max: 100, fmt: v => pc(v, 1), rows: [["ml_greedy", "ML + Greedy (linear)"], ["ml_ilp", "ML + ILP (linear)"], ["ml_nsga2_ext", "NSGA-II (attack-path)"]].map(([k, l]) => ({ label: l, value: E(k).ext_pct_mean, err: E(k).ext_pct_std, color: k === "ml_nsga2_ext" ? STRAT.ml_nsga2.color : STRAT[k].color, hi: k === "ml_nsga2_ext" })) });
  const ser = (k, s, c) => ({ dash:s==="Greedy"?"6 4":"", name: s, color: c, dots: 1, pts: rb.filter(r => r.strategy === (s === "Greedy" ? "ml_greedy" : "ml_ilp")).map(r => [r.sigma * 100, r[k]]) });
  LineChart($("#x-rb"), { series: [ser("coverage", "Greedy", STRAT.ml_greedy.color), ser("coverage", "ILP", STRAT.ml_ilp.color)], xlabel: "Cost-estimate noise σ (%)", ylabel: "% later-KEV covered", xmax: 40, xfmt: v => nf(v, 0), yfmt: v => nf(v, 1), ymin: 0 });
  LineChart($("#x-ov"), { series: [ser("overshoot", "Greedy", STRAT.ml_greedy.color), ser("overshoot", "ILP", STRAT.ml_ilp.color)], xlabel: "Cost-estimate noise σ (%)", ylabel: "Budget overshoot (%)", xmax: 40, xfmt: v => nf(v, 0), yfmt: v => nf(v, 1) });
};

/* ============================== 11. LIMITS & ROADMAP ============================== */
PAGES.roadmap.render = v => {
  const ph = (n, name, items) => `<div class="phase"><div><div class="mono" style="font-size:22px;color:var(--acc)">${n}</div><div class="small mut">${name}</div></div><ul>${items.map(([d, t]) => `<li class="${d}">${t}</li>`).join("")}</ul></div>`;
  v.innerHTML = head({ kick: "Step 12 · Limits & roadmap", title: "Methods & limitations", lede: "Phase <mark>2</mark> tests the model, simulator and optimizers on synthetic records.<sup>1</sup> The next phase repeats the evaluation with observed vulnerability data.<sup>2</sup>",
    explain: { what: "A three-phase view of the build, an explicit list of what is simulated, and what we do not claim.", why: "Examiners reward clear scoping and an honest account of limitations far more than inflated claims.", say: "Close with the 'what we do not claim' card, then the Phase 3 list as the plan for the remaining weeks." } }) +
    `<div class="grid g21"><div class="card"><h3>Three phases</h3>
    ${ph("Phase 1", "Foundations", [["done", "Data schema, labels, time-based split, censoring"], ["done", "Baseline models + calibrated Random Forest"], ["done", "Simulator, risk and cost formulas"], ["done", "Greedy, ILP and NSGA-II with constraints"]])}
    ${ph("Phase 2", "This demo", [["done", "20-inventory time-machine backtest vs Random / CVSS / EPSS"], ["done", "Attack-path extension (non-linear) and cost-noise robustness"], ["done", "Cost-ratio sensitivity, calibration, per-CVE explanations"], ["done", "Interactive offline demo with section-by-section navigation"], ["done", "Gradient-boosting model alongside DT / RF"]])}
    ${ph("Phase 3", "To finish", [["next", "Replace the synthetic generator with real NVD + CISA KEV + EPSS downloads, document formats, retrain, re-run every result"], ["next", "SHAP values (replace the occlusion explanation) and XGBoost"], ["next", "Sensitivity analysis over exposure weights and effort-hour assumptions"], ["next", "Optional: Exploit-DB feature, live NVD feed with cached fallback"], ["next", "Final report, slides and viva rehearsal"]])}</div>
    <div style="display:grid;gap:18px;align-content:start"><div class="card"><h3>Simulated in this prototype</h3><ol style="margin:0;padding-left:18px;color:var(--ink2)"><li>The CVE corpus, KEV labels and EPSS scores (real schema)</li><li>The network inventory and every patch cost</li><li>The attack topology (internet → DMZ → internal)</li></ol></div>
    <aside class="footnotes"><h3>Method notes</h3><ol><li>The synthetic KEV label uses a 365-day window after publication.</li><li>KEV records observed exploitation. A missing entry cannot establish that a CVE was never exploited.</li></ol></aside>
    <div class="card"><h3>What we do not claim</h3><ol style="margin:0;padding-left:18px;color:var(--ink2)"><li>No real-world accuracy numbers — data is synthetic</li><li>No new algorithm: DT, RF, isotonic calibration, ILP and NSGA-II are all existing methods; the contribution is the combination and the backtest</li><li>ILP is optimal on the basic problem; the GA's value is the Pareto front and non-linear objectives</li><li>No scanning of real networks, no automatic patching, no zero-day prediction</li></ol></div></div></div>`;
};
