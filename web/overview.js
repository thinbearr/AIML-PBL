/* The single overview page: what the project does, in one screen. Replaces the earlier longer home page. */
PAGES.home.render = async v => {
  const cmp = await api("/api/compare");
  const row = (s, b = 0.2) => cmp.summary.find(r => r.strategy === s && Math.abs(r.budget_frac - b) < 1e-6);
  v.innerHTML = `
  <div class="kick">Exploit-aware patch prioritization</div>
  <h1 class="title">Which patches do we apply first, when we can only afford some?</h1>
  <div class="grid g3 mt">
    <div class="card stat"><div class="v">25,000+</div><div class="l">new CVEs a year</div></div>
    <div class="card stat"><div class="v" style="color:var(--acc2)">1–2%</div><div class="l">ever exploited</div></div>
    <div class="card stat"><div class="v" style="color:var(--bad)">≈ random</div><div class="l">patching by CVSS alone</div></div>
  </div>
  <div class="flow mt2">
    <div class="step"><b>Predict</b><span>ML estimates how likely each CVE is to be exploited</span></div>
    <div class="step"><b>Translate</b><span>risk and cost of every patch on every host</span></div>
    <div class="step"><b>Optimize</b><span>best patch set within the budget</span></div>
    <div class="step"><b>Prove</b><span>backtest against what was exploited later</span></div>
  </div>
  <div class="card mt2"><div class="head"><div class="grow"><h3>Later-exploited CVEs covered at a 20% budget</h3></div><span class="tag amb">${cmp.n_inventories} networks · synthetic data</span></div>
    <div id="h-bars"></div></div>
  <div style="display:flex;gap:10px;margin-top:20px;flex-wrap:wrap"><a class="btn" href="#/model">Model</a><a class="btn" href="#/planner">Planner</a></div>`;
  BarChart($("#h-bars"), { max: 100, fmt: x => pc(x, 1), rows: [
    { label: "Random", value: row("random").coverage_mean, color: STRAT.random.color },
    { label: "CVSS-sorted", value: row("cvss_sorted").coverage_mean, color: STRAT.cvss_sorted.color },
    { label: "EPSS-sorted", value: row("epss_sorted").coverage_mean, color: STRAT.epss_sorted.color },
    { label: "ML + ILP (ours)", value: row("ml_ilp").coverage_mean, color: STRAT.ml_ilp.color, hi: true }] });
};
