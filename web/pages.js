/* Story pages 1-5. (pages2.js holds 6-11.) */
const NAV = [
  { id: "home", n: 1, nav: "Project", group: "Menu" },
  { id: "model", n: 2, nav: "Model", group: "Menu" },
  { id: "planner", n: 3, nav: "Planner", group: "Menu" },
  // not in the menu: opened from buttons inside the Planner (or by typing the address, e.g. #/network)
  { id: "network", n: 0, nav: "Network & risk", group: "Hidden", hidden: true },
  { id: "upload", n: 0, nav: "Bring your own data", group: "Hidden", hidden: true },
  { id: "pareto", n: 0, nav: "Optimizer lab", group: "Hidden", hidden: true },
  { id: "evidence", n: 0, nav: "Backtest results", group: "Hidden", hidden: true },
  { id: "roadmap", n: 0, nav: "Limits & roadmap", group: "Hidden", hidden: true },
  { id: "pipeline", n: 0, nav: "How it works", group: "Hidden", hidden: true },
  { id: "data", n: 0, nav: "Data & labels", group: "Hidden", hidden: true },
  { id: "cves", n: 0, nav: "Explain a CVE", group: "Hidden", hidden: true },
  { id: "extend", n: 0, nav: "Extensions", group: "Hidden", hidden: true },
];
const PAGES = {};
NAV.forEach(p => PAGES[p.id] = p);
const fmtP = v => (v == null ? "–" : nf(v, 3));

/* ============================== 1. THE PROBLEM ============================== */
PAGES.home.render = async v => {
  const [cmp, mod] = await Promise.all([api("/api/compare"), api("/api/model")]);
  const row = (s, b = 0.2) => cmp.summary.find(r => r.strategy === s && Math.abs(r.budget_frac - b) < 1e-6);
  const cvss = row("cvss_sorted"), epss = row("epss_sorted"), ilp = row("ml_ilp"), rnd = row("random");
  const ratio = ilp.coverage_mean / cvss.coverage_mean;
  v.innerHTML = `
  <div class="hero"><div><div class="kick">The problem</div>
    <h1 class="title">Which patches do we apply first — when we can only afford some?</h1>
    <div style="display:flex;gap:10px;flex-wrap:wrap"><a class="btn" href="#/planner">Open the patch planner</a></div></div>
    <div class="card"><div class="head"><div class="grow"><h3>Later-exploited CVEs covered at a 20% budget</h3><div class="sub">Backtest, mean over ${cmp.n_inventories} random inventories · synthetic data</div></div><span class="tag amb">hindsight</span></div>
    <div id="h-bars"></div><p class="small mut" style="margin:10px 0 0">Same budget, same networks. Only the <b>ranking</b> differs. ML + ILP covers <b>${nf(ratio, 1)}×</b> as many later-exploited CVEs as CVSS-sorted.</p></div></div>
  <div class="grid g3"><div class="card stat"><div class="v">25,000+</div><div class="l">new CVEs published every year</div><small>Source: synopsis, §2.1</small></div>
    <div class="card stat"><div class="v" style="color:var(--acc2)">1–2%</div><div class="l">are ever exploited in the wild</div><small>Source: synopsis, §2.1 (CISA KEV is the label)</small></div>
    <div class="card stat"><div class="v" style="color:var(--bad)">≈ random</div><div class="l">how well “patch high CVSS first” performs</div><small>Allodi &amp; Massacci, cited in synopsis [2]</small></div></div>
  <h2 class="mt2">Our answer, in four moves</h2><p class="sub">Existing work covers each piece separately. The contribution here is chaining them and testing the chain against what attackers really did next.</p>
  <div class="flow mt"><div class="step"><b>Predict</b><span>Cost-sensitive Decision Tree / Random Forest estimate the probability a CVE gets exploited. Isotonic calibration makes the output a real probability.</span></div>
   <div class="step"><b>Translate</b><span>A simulated 200–500-host network turns CVE probabilities into host-level risk and patch cost (effort + downtime).</span></div>
   <div class="step"><b>Optimize</b><span>Greedy, ILP and NSGA-II pick the patch set with the most risk removed under budget, downtime and dependency limits.</span></div>
   <div class="step"><b>Prove</b><span>Time-machine backtest: train on the past, patch, then count which CVEs were exploited afterwards — against CVSS and EPSS baselines.</span></div></div>
  <div class="callout mt2"><b>Honest scope.</b> No real network is scanned and no patch is applied automatically. Inventory and patch costs are simulated, and in this prototype the CVE data is a <b>synthetic stand-in</b> for NVD + KEV + EPSS. EPSS uses richer signals than we have, so it can beat our model — we report that as it is.</div>`;
  BarChart($("#h-bars"), { max: 100, fmt: v => pc(v, 1), rows: [
    { label: "Random", value: rnd.coverage_mean, color: STRAT.random.color }, { label: "CVSS-sorted", value: cvss.coverage_mean, color: STRAT.cvss_sorted.color },
    { label: "EPSS-sorted", value: epss.coverage_mean, color: STRAT.epss_sorted.color }, { label: "ML + ILP (ours)", value: ilp.coverage_mean, color: STRAT.ml_ilp.color, hi: true }] });
};

/* ============================== 2. HOW IT WORKS ============================== */
const STAGES = [
  { id: "data", t: "1 · Data", f: "src/data_synth.py", out: "data/raw/cves_synthetic.parquet", st: "synthetic",
    what: "Builds the CVE table: CVSS v3 vector, CWE, vendor/product, description, reference count, publish date, KEV date and an EPSS value.",
    bullets: ["Label = 1 if added to CISA KEV within 365 days of publication.", "Censoring: only CVEs published ≥ 12 months before the download date are kept.", "Prototype uses a synthetic generator with the same columns; Phase 3 swaps in real NVD/KEV/EPSS files."] },
  { id: "model", t: "2 · Risk model", f: "src/model.py", out: "data/processed/scored_cves.parquet", st: "done",
    what: "Trains Logistic Regression, Decision Tree, Random Forest and Gradient Boosting on features known at publication time, then calibrates the probabilities.",
    bullets: ["class_weight balanced for the rare exploited class; threshold chosen to minimise 50·FN + 1·FP.", "Isotonic regression fitted on the validation period → p_exploit behaves like a probability.", "Metrics: PR-AUC, recall@100, Brier score, expected cost — never accuracy."] },
  { id: "sim", t: "3 · Simulator", f: "src/simulate.py", out: "patches.csv · hosts.csv", st: "done",
    what: "Generates 200–500 hosts, each with exposure (internet / DMZ / internal), criticality 1–5 and real products. A patch = update product P on host H.",
    bullets: ["risk(CVE,host) = p_exploit × impact × criticality × exposure weight.", "cost = base effort hours (by software type) + downtime penalty × criticality.", "App patches may require the host's OS patch first (dependency)."] },
  { id: "opt", t: "4 · Optimizers", f: "src/optimize.py", out: "selected patch sets · Pareto front", st: "done",
    what: "Random, CVSS-sorted, EPSS-sorted, ML + Greedy, ML + ILP (exact), ML + NSGA-II (genetic, two objectives).",
    bullets: ["Constraints: budget, downtime window, dependencies.", "NSGA-II returns the whole cost-vs-risk Pareto front in one run.", "Extension: attack-path risk makes the objective non-linear — ILP no longer applies, NSGA-II still does."] },
  { id: "eval", t: "5 · Backtest", f: "src/evaluate.py", out: "results/*.csv", st: "done",
    what: "Runs every strategy at 10 / 20 / 30 % of total patch cost on 20 random inventories and scores them on CVEs exploited afterwards.",
    bullets: ["Primary metric: % of later-KEV CVEs covered. Also residual risk, optimality gap vs ILP, runtime.", "Results are reported as mean ± standard deviation.", "Extra runs: attack-path objective and cost-estimate noise."] },
  { id: "dash", t: "6 · This demo", f: "server.py + web/", out: "http://localhost:8000", st: "done",
    what: "Offline web app that reads the precomputed files and calls the optimizers live, so the whole chain can be shown and explained.",
    bullets: ["Runs on a laptop with no internet and no GPU.", "Every number you see comes from the pipeline files — nothing is hard-coded.", "Use the guided demo for a scripted walkthrough."] },
];
PAGES.pipeline.render = v => {
  v.innerHTML = head({ kick: "Step 2 · How it works", title: "Six scripts, one pipeline", lede: "Each stage reads the file the previous stage wrote, so every piece can be tested and explained on its own.",
    explain: { what: "The architecture of the whole project as a left-to-right flow. Click any stage to see its inputs, outputs and design decisions.", why: "A modular chain lets us swap synthetic data for real NVD/KEV/EPSS data, or ILP for NSGA-II, without touching anything else.", say: "Walk left to right. Stress that the model output (p_exploit) is the only thing the network stage needs — that is the interface between ML and optimization." } }) +
    `<div class="card"><svg viewBox="0 0 1120 190" width="100%" id="arch"></svg></div><div class="card mt" id="stage-detail"></div>
    <div class="grid g2 mt"><div class="card"><h3>Data-integrity rules</h3><p class="sub">These keep the evaluation honest — and are the first thing an examiner will probe.</p>
      <div class="chips" style="gap:8px"><span class="tag acc">Censoring</span><span class="small">only CVEs older than 12 months at download</span></div>
      <div class="chips mt" style="gap:8px"><span class="tag acc">No leakage</span><span class="small">features use publication-date info only</span></div>
      <div class="chips mt" style="gap:8px"><span class="tag acc">EPSS fairness</span><span class="small">baseline uses EPSS as of the cutoff, never as a feature</span></div>
      <div class="chips mt" style="gap:8px"><span class="tag acc">Time split</span><span class="small">train → validation → test by date, never random</span></div></div>
    <div class="card"><h3>Reproducibility</h3><p class="sub">Everything driven by <span class="mono">config.yaml</span>.</p><ul style="margin:0;padding-left:18px;color:var(--ink2)"><li>Fixed random seeds, one-command run: <span class="mono">python run_pipeline.py</span></li><li>All assumptions (exposure weights, effort hours, cost ratio) in one file</li><li>Runs offline on a standard laptop</li></ul></div></div>`;
  const svg = $("#arch"); const bw = 164, gap = 24;
  STAGES.forEach((s, i) => {
    const x = 6 + i * (bw + gap), g = S("g", { class: "stage", "data-id": s.id }, svg);
    S("rect", { x, y: 18, width: bw, height: 120, rx: 14, fill: "var(--surface2)", stroke: "var(--line2)", "stroke-width": 1.2 }, g);
    S("text", { x: x + 14, y: 44, style: "fill:var(--acc);font:600 11px var(--mono);letter-spacing:.1em" }, g).textContent = s.t.split(" · ")[0].padStart(2, "0") + " STAGE";
    S("text", { x: x + 14, y: 68, style: "fill:var(--ink);font:600 15px var(--serif)" }, g).textContent = s.t.split(" · ")[1];
    S("text", { x: x + 14, y: 90, style: "fill:var(--mut);font:500 10.5px var(--mono)" }, g).textContent = s.f;
    S("text", { x: x + 14, y: 112, style: "fill:var(--ink2);font:11px var(--sans)" }, g).textContent = s.out.length > 26 ? s.out.slice(0, 25) + "…" : s.out;
    if (i < STAGES.length - 1) { S("path", { d: `M${x + bw + 3} 78 h${gap - 8}`, stroke: "var(--acc)", "stroke-width": 2, fill: "none" }, svg); S("path", { d: `M${x + bw + gap - 8} 72 l6 6 -6 6`, stroke: "var(--acc)", "stroke-width": 2, fill: "none" }, svg); }
    S("text", { x: x + bw / 2, y: 164, "text-anchor": "middle", style: `font:600 10px var(--sans);letter-spacing:.12em;fill:${s.st === "synthetic" ? "var(--acc2)" : "var(--good)"}` }, svg).textContent = s.st === "synthetic" ? "SYNTHETIC IN PROTOTYPE" : "IMPLEMENTED";
    g.addEventListener("click", () => showStage(s.id));
  });
  function showStage(id) {
    const s = STAGES.find(x => x.id === id);
    $$(".stage").forEach(e => e.classList.toggle("on", e.dataset.id === id));
    $("#stage-detail").innerHTML = `<div class="head"><div class="grow"><h2>${esc(s.t)}</h2><div class="sub mono">${esc(s.f)} → ${esc(s.out)}</div></div><span class="tag ${s.st === "synthetic" ? "amb" : "good"}">${s.st === "synthetic" ? "synthetic data" : "implemented"}</span></div><p style="color:var(--ink2);margin-top:0">${esc(s.what)}</p><ul style="color:var(--ink2);margin:0;padding-left:18px">${s.bullets.map(b => `<li>${esc(b)}</li>`).join("")}</ul>`;
  }
  showStage("model");
};

/* ============================== 3. DATA & LABELS ============================== */
PAGES.data.render = async v => {
  const d = await api("/api/data");
  const tot = d.splits.reduce((a, s) => a + s.n, 0), cols = { train: "var(--acc)", val: "var(--acc2)", test: "var(--bad)" };
  v.innerHTML = head({ kick: "Step 3 · Data & labels", title: "What the model learns from — and what it must never see", lede: "Features come from the vulnerability record at publication time. The label comes later: did CISA add it to the Known Exploited Vulnerabilities catalog within a year?",
    explain: { what: "The CVE corpus, how it is split by date into train / validation / test, and how rare the positive (exploited) class is.", why: "Only 1–2% of CVEs are exploited, so accuracy is meaningless and a random split would leak the future into training. Time-based splitting mimics real deployment.", say: "Point at the timeline: the test period starts after both training and validation end. Then show that CVSS bands barely separate exploited from non-exploited CVEs." } }) +
    `<div class="grid g4">${kpi("CVEs in corpus", nf(d.total), "after 12-month censoring")}${kpi("Exploited (label = 1)", nf(d.positives), "KEV within 365 days", "amb")}${kpi("Positive rate", pc(d.rate, 2), "severe class imbalance", "acc")}${kpi("Label window", d.label_window + " d", "publication → KEV date")}</div>
    <div class="card mt"><div class="head"><div class="grow"><h3>Time-based split</h3><div class="sub">Older CVEs train the model, a later period tunes it and calibrates probabilities, the latest period is the held-out test.</div></div></div>
    <div class="timeline">${d.splits.map(s => `<div style="flex:${s.n};background:${cols[s.split]}">${s.split.toUpperCase()} · ${nf(s.n)}</div>`).join("")}</div>
    <div style="display:flex;margin-top:8px">${d.splits.map(s => `<div style="flex:${s.n};font-size:12px;color:var(--mut)">${s.range} · <b style="color:var(--ink2)">${s.pos}</b> exploited</div>`).join("")}</div></div>
    <div class="grid g2 mt"><div class="card"><h3>Exploit rate by CVSS band</h3><p class="sub">If CVSS were a good guide, the high bands would stand far above the rest.</p><div id="d-cvss"></div></div>
    <div class="card"><h3>Exploited CVEs by publication year</h3><p class="sub">Positives per year (older years had longer to be added to KEV — hence censoring).</p><div id="d-year"></div></div></div>
    <div class="grid g21 mt"><div class="card"><h3>Highest-scored CVEs in the test period</h3><p class="sub">A glimpse of the table the model produces (<span class="mono">scored_cves.parquet</span>). Label column is hindsight.</p><div id="d-sample"></div></div>
    <div class="card"><h3>Features used</h3><p class="sub">All available on the publication date.</p><ul style="margin:0 0 14px;padding-left:18px;color:var(--ink2)">${d.features.map(f => `<li>${esc(f)}</li>`).join("")}</ul><h3>Never used as a feature</h3><p class="small" style="color:var(--ink2);margin:0">EPSS (competing baseline) and KEV status (it is the label).</p></div></div>
    <div class="callout mt">⚠ <b>Synthetic data.</b> This prototype generates a stand-in with the real schema, so the pipeline can be shown offline. Real NVD, KEV and EPSS downloads — and their data dictionary — are the first item of Phase 3.</div>`;
  ColChart($("#d-cvss"), { cols: d.by_cvss.map((r, i) => ({ label: r.cvss, value: r.rate, color: ["#4f8a67", "#4f8a67", "var(--acc2)", "var(--bad)"][i], note: `${nf(r.n)} CVEs (${nf(r.share, 1)}%) · ${r.pos} exploited` })), vfmt: v => nf(v, 1) + "%", yfmt: v => nf(v, 1) + "%" });
  ColChart($("#d-year"), { cols: d.by_year.map(r => ({ label: r.year, value: r.pos, color: "var(--acc)", note: `${r.n} CVEs · ${nf(r.rate, 2)}% exploited` })), vfmt: v => nf(v, 0), yfmt: v => nf(v, 0) });
  table($("#d-sample"), d.sample, [{ k: "cve_id", label: "CVE" }, { k: "product", label: "Product" }, { k: "cvss", label: "CVSS", num: 1 }, { k: "epss", label: "EPSS", num: 1 }, { k: "p_exploit", label: "p_exploit", num: 1, fmt: v => `<b style="color:var(--acc)">${nf(v, 3)}</b>` },
    { k: "label", label: "Exploited later?", fmt: v => ST.hindsight ? (v ? '<span class="tag bad">yes</span>' : '<span class="tag">no</span>') : '<span class="mut">hidden</span>' }], { pageSize: 8, sortKey: "p_exploit", onRow: r => { location.hash = "#/cves"; } });
};

/* ============================== 4. EXPLOIT MODEL ============================== */
PAGES.model.render = async v => {
  const m = await api("/api/model"), M = m.metrics;
  const names = { random_forest: "Random Forest", gradient_boosting: "Gradient boosting", logreg: "Logistic regression", decision_tree: "Decision tree", cvss_baseline: "CVSS only", epss_baseline: "EPSS (baseline)" };
  const colors = { random_forest: "var(--acc)", gradient_boosting: "var(--sky)", logreg: "var(--vio)", decision_tree: "#4fb072", cvss_baseline: "var(--acc2)", epss_baseline: "var(--bad)" };
  const bars = k => Object.keys(names).filter(n => M[n]).map(n => ({ label: names[n], value: M[n][k], color: colors[n], hi: n === "random_forest" }));
  const meta = M._meta, rf = M.random_forest;
  v.innerHTML = head({ kick: "Step 4 · Exploit-probability model", title: "From a CVE record to a calibrated probability", lede: "Cost-sensitive tree models predict P(exploited within a year). A missed exploited CVE is far more expensive than a false alarm — and the probabilities are calibrated so they can be multiplied into risk.",
    explain: { what: "Test-period performance of every model against the CVSS-only and EPSS baselines, calibration, feature importances and a live cost-ratio slider.", why: "Accuracy would reward predicting 'never exploited'. PR-AUC and recall@100 measure what a patch team needs: are the exploited CVEs near the top of the list?", say: "Show RF beating CVSS. Then be upfront: EPSS wins here because it carries richer signals — the synopsis predicts exactly that. Finish on the cost-ratio slider." } }) +
    `<div class="grid g4">${kpi("RF PR-AUC", nf(rf.pr_auc, 3), `CVSS-only: ${nf(M.cvss_baseline.pr_auc, 3)}`, "acc")}${kpi("RF recall@100", pc(rf["recall@100"] * 100, 1), `CVSS-only: ${pc(M.cvss_baseline["recall@100"] * 100, 1)}`, "acc")}${kpi("Brier (calibrated)", nf(rf.brier_calibrated, 4), `raw: ${nf(rf.brier_raw, 4)}`)}${kpi("Test set", nf(meta.n_test), `${meta.test_positives} later exploited`, "amb")}</div>
    <div class="grid g2 mt"><div class="card"><h3>PR-AUC (higher is better)</h3><p class="sub">Area under the precision–recall curve · test period</p><div id="m-pr"></div></div><div class="card"><h3>Recall @ top-100</h3><p class="sub">Share of all exploited CVEs found in the model's 100 highest-ranked CVEs</p><div id="m-rc"></div></div></div>
    <div class="callout mt">EPSS ranks higher than our model here. That is expected and reported as-is: EPSS uses signals (exploit chatter, telemetry) that NVD fields cannot provide, so it is a <b>competing baseline, never a feature</b>.</div>
    <div class="grid g2 mt"><div class="card"><h3>Cost-sensitive threshold</h3><p class="sub">Choose the cut-off that minimises <span class="mono">FN×cost + FP×1</span> on the validation set, then judge it on the test set.</p>
      <label class="f">Cost of a missed exploit vs a false alarm <span class="val" id="r-val">50 : 1</span></label><input type="range" id="ratio" min="0" max="100" value="68"><div id="thr" style="margin-top:14px"></div></div>
    <div class="card"><h3>Calibration (test)</h3><p class="sub">Predicted probability vs observed rate. On the diagonal = trustworthy as a risk value.</p><div id="m-cal"></div><p class="small mut" style="margin:8px 0 0">Brier score improves from <b>${nf(rf.brier_raw, 4)}</b> (raw forest votes) to <b>${nf(rf.brier_calibrated, 4)}</b> after isotonic calibration.</p></div></div>
    <div class="grid g2 mt"><div class="card"><h3>What the Random Forest relies on</h3><p class="sub">Feature importance (top 15)</p><div id="m-fi"></div></div>
    <div class="card"><h3>The interpretable Decision Tree</h3><p class="sub">Top four levels — readable rules an analyst can challenge.</p><pre style="max-height:360px;overflow:auto;font:11.5px/1.5 var(--mono);background:var(--surface2);padding:12px;border-radius:10px;margin:0">${esc(m.tree)}</pre></div></div>`;
  BarChart($("#m-pr"), { max: Math.max(...bars("pr_auc").map(b => b.value)) * 1.15, fmt: v => nf(v, 3), rows: bars("pr_auc") });
  BarChart($("#m-rc"), { max: Math.max(...bars("recall@100").map(b => b.value)) * 1.15, fmt: v => pc(v * 100, 1), rows: bars("recall@100") });
  const cal = m.calibration, mx = Math.max(...cal.map(r => r.mean_predicted));
  LineChart($("#m-cal"), { height: 260, xlabel: "Mean predicted probability", ylabel: "Observed rate", xfmt: v => nf(v, 2), yfmt: v => nf(v, 2), xmax: niceMax(Math.max(mx, ...cal.map(r => r.observed_rate))), ymax: niceMax(Math.max(mx, ...cal.map(r => r.observed_rate))),
    series: [{ name: "Perfect calibration", color: "#8793a3", dash: "5 4", pts: [[0, 0], [niceMax(mx), niceMax(mx)]] }, { name: "Random Forest (calibrated)", color: "var(--acc)", dots: 1, pts: cal.map(r => [r.mean_predicted, r.observed_rate]) }] });
  BarChart($("#m-fi"), { fmt: v => nf(v, 3), rows: m.importance.slice(0, 12).map(r => ({ label: r.feature.replace(/^(tf_|cwe_)/, m => m === "tf_" ? "word: " : "CWE-"), value: r.importance, color: "var(--acc)" })) });
  const upd = async () => {
    const ratio = Math.round(Math.pow(10, +$("#ratio").value / 40)); $("#r-val").textContent = `${ratio} : 1`;
    const t = await api("/api/threshold", { ratio });
    $("#thr").innerHTML = `<div class="matrix"><div class="h"></div><div class="h">Predicted exploited</div><div class="h">Predicted safe</div>
      <div class="h">Actually exploited</div><div class="c good"><b>${t.tp}</b>caught (TP)</div><div class="c bad"><b>${t.fn}</b>missed (FN)</div>
      <div class="h">Not exploited</div><div class="c"><b>${nf(t.fp)}</b>false alarms (FP)</div><div class="c"><b>${nf(t.tn)}</b>correctly ignored</div></div>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:14px"><div><div class="mono" style="font-size:19px;color:var(--acc)">${pc(t.recall * 100, 0)}</div><div class="small mut">recall</div></div><div><div class="mono" style="font-size:19px">${pc(t.precision * 100, 1)}</div><div class="small mut">precision</div></div><div><div class="mono" style="font-size:19px;color:var(--acc2)">${nf(t.expected_cost)}</div><div class="small mut">expected cost (vs ${nf(t.naive_cost)} flagging nothing)</div></div></div>
      <p class="small mut" style="margin:10px 0 0">Threshold p ≥ <b class="mono">${nf(t.threshold, 4)}</b>. Raise the ratio and the model flags more CVEs, trading precision for recall.</p>`;
  };
  $("#ratio").oninput = debounce(upd, 120); upd();
};

/* ============================== 5. EXPLAIN A CVE ============================== */
PAGES.cves.render = async v => {
  v.innerHTML = head({ kick: "Step 5 · Explainability", title: "Why did this CVE get this score?", lede: "Pick any CVE. The page shows the probability, how it ranks, and which groups of features pushed it up or down.",
    explain: { what: "A searchable list of test-period CVEs with model score, CVSS and EPSS. Selecting one explains the score by group marginalisation: each feature group is swapped for values from 80 real training CVEs and the change in the forest's score is measured.", why: "Analysts will not act on a black-box number. This also shows why a CVSS-9.8 CVE can rank below a CVSS-7 one that is network-reachable and easy to exploit.", say: "Pick a high p_exploit CVE with a modest CVSS score — that is the story. (SHAP values are the Phase 3 upgrade of this view.)" } }) +
    `<div class="grid g12"><div class="card"><div class="head"><div class="grow"><input type="text" id="c-q" placeholder="Search CVE id or product…"></div></div>
    <div class="chips" style="margin-bottom:12px" id="c-sort"><span class="chip on" data-s="p_exploit">Highest model risk</span><span class="chip" data-s="cvss">Highest CVSS</span><span class="chip" data-s="epss">Highest EPSS</span></div><div id="c-list"></div></div><div id="c-detail"></div></div>`;
  let sort = "p_exploit", page = 0, selected = null;
  const load = async () => {
    const d = await api("/api/cves", { q: $("#c-q").value, sort, page, split: "test" });
    $("#c-list").innerHTML = `<div class="tw" style="max-height:540px"><table><thead><tr><th>CVE</th><th>Product</th><th class="num">CVSS</th><th class="num">EPSS</th><th class="num">p_exploit</th></tr></thead><tbody>${d.rows.map(r => `<tr class="click ${r.cve_id === selected ? "sel" : ""}" data-id="${r.cve_id}"><td class="mono">${r.cve_id}</td><td>${esc(r.product)}</td><td class="num">${nf(r.cvss, 1)}</td><td class="num">${nf(r.epss, 2)}</td><td class="num"><b style="color:var(--acc)">${nf(r.p_exploit, 3)}</b></td></tr>`).join("")}</tbody></table></div>
    <div class="pager"><span>${nf(d.total)} CVEs</span><button class="btn ghost sm" id="c-prev" ${page === 0 ? "disabled" : ""}>‹</button><span>${page + 1}</span><button class="btn ghost sm" id="c-next" ${(page + 1) * 20 >= d.total ? "disabled" : ""}>›</button></div>`;
    $$("#c-list tr.click").forEach(tr => tr.onclick = () => select(tr.dataset.id));
    $("#c-prev").onclick = () => { page--; load(); }; $("#c-next").onclick = () => { page++; load(); };
    return d;
  };
  const select = async id => {
    selected = id; $$("#c-list tr.click").forEach(tr => tr.classList.toggle("sel", tr.dataset.id === id));
    const c = await api("/api/cve", { id }), mx = Math.max(...c.contrib.map(x => Math.abs(x.delta)), 1e-6);
    $("#c-detail").innerHTML = `<div class="card"><div class="head"><div class="grow"><div class="kick" style="margin-bottom:4px">${esc(c.product)} · ${esc(c.vendor)}</div><h2 class="mono" style="font-size:20px">${c.cve_id}</h2><div class="sub">Published ${c.published} · CWE-${c.cwe} · AV:${c.av} · ${c.impact}</div></div></div>
      <p style="color:var(--ink2);margin-top:0">${esc(c.description)}</p>
      <div class="grid g3"><div class="card flat kpi acc"><div class="v">${nf(c.p_exploit, 3)}</div><div class="l">model p_exploit</div><div class="s">top ${nf(c.rank_pct, 1)}% of all CVEs</div></div><div class="card flat kpi"><div class="v">${nf(c.cvss, 1)}</div><div class="l">CVSS base score</div></div><div class="card flat kpi"><div class="v">${nf(c.epss, 2)}</div><div class="l">EPSS (baseline)</div></div></div>
      <h3 class="mt">What drove the score</h3><p class="sub">Change in the forest's score when that feature group is swapped for values from real typical CVEs (a typical CVE scores <b class=\"mono\">${nf(c.baseline_raw, 2)}</b>; this one scores <b class=\"mono\">${nf(c.raw_score, 2)}</b>). Teal pushes risk up, red pushes it down.</p>
      <div id="c-contrib">${c.contrib.map(x => `<div style="display:grid;grid-template-columns:200px 1fr 70px;gap:10px;align-items:center;padding:4px 0"><span style="font-size:12.5px">${esc(x.group)}</span><div style="position:relative;height:12px;background:var(--bg2);border-radius:99px"><div style="position:absolute;top:0;bottom:0;border-radius:99px;${x.delta >= 0 ? `left:50%;width:${Math.abs(x.delta) / mx * 50}%;background:var(--acc)` : `right:50%;width:${Math.abs(x.delta) / mx * 50}%;background:var(--bad)`}"></div><div style="position:absolute;left:50%;top:-2px;bottom:-2px;width:1px;background:var(--line2)"></div></div><span class="mono small" style="text-align:right;color:${x.delta >= 0 ? "var(--acc)" : "var(--bad)"}">${x.delta >= 0 ? "+" : ""}${nf(x.delta, 3)}</span></div>`).join("")}</div>
      <div class="callout acc mt small">Appears on <b>${c.instances}</b> host${c.instances === 1 ? "" : "s"} in the current simulated network.</div>
      <div class="callout mt small" id="c-hind">${ST.hindsight ? (c.label ? `<b>Hindsight:</b> this CVE <b>was added to KEV</b> on ${c.kev_date}.` : `<b>Hindsight:</b> not added to KEV within the label window.`) : `Outcome hidden (backtest honesty). <a href="#" id="c-rev">Reveal</a>`}</div></div>`;
    const rv = $("#c-rev"); if (rv) rv.onclick = e => { e.preventDefault(); ST.hindsight = true; select(id); };
  };
  $("#c-q").oninput = debounce(() => { page = 0; load(); }, 250);
  $$("#c-sort .chip").forEach(ch => ch.onclick = () => { sort = ch.dataset.s; page = 0; $$("#c-sort .chip").forEach(x => x.classList.toggle("on", x === ch)); load(); });
  const d = await load(); if (d.rows[0]) select(d.rows[0].cve_id);
};
