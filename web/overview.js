PAGES.home.render = async (v, token) => {
  const cmp = await api("/api/compare");
  const rows = cmp.summary.filter(r => Math.abs(r.budget_frac - .2) < 1e-6);
  const coverage = key => rows.find(r => r.strategy === key).coverage_mean;
  const ratio = nf(coverage("ml_ilp") / coverage("cvss_sorted"), 1);
  if (token !== _routeToken) return;
  v.innerHTML = `
    <header class="opening"><div><div class="kick">01 · The problem</div>
    <h1 class="title">Which patches<br>come first?</h1>
    <p class="lede">Cost-sensitive, exploit-aware vulnerability prioritization under a limited budget of patch hours.</p>
    <a class="btn" href="#/planner">Open patch planner</a> <a class="textlink" href="#/evidence">Read the evidence</a></div>${coverMap()}</header>
    <div class="scoreboard">
      <a class="stat" href="#/evidence"><div class="l">Coverage advantage</div><div class="v"><mark>${ratio}×</mark></div><small><sup>1</sup> ML + ILP relative to CVSS-sorted</small></a>
      <a class="stat" href="#/planner"><div class="l">Patch budget</div><div class="v">20<span>%</span></div><small><sup>2</sup> Share of total patch effort</small></a>
      <a class="stat" href="#/evidence"><div class="l">Study population</div><div class="v">${cmp.n_inventories}</div><small><sup>3</sup> Simulated network inventories</small></a>
    </div>
    <div class="results-layout"><section class="card overview-result"><div class="figure-label">FIG. 1 <span>/</span> BACKTEST EVIDENCE</div>
      <h2>Coverage of later-exploited CVEs</h2><div class="sub">Mean coverage at a fixed 20% budget</div><div id="h-bars"></div>
      <p class="caption">Each strategy faces the same patch-hour limit. Coverage is measured against subsequent KEV labels.</p></section>
      <aside class="marginal"><div class="figure-label">Margin note 01</div><h3>Why cost matters</h3><p>A CVE score estimates the likelihood of exploitation. A patch decision also depends on host exposure, business impact and the hours needed to apply it.</p><a class="textlink" href="#/network">Explore network risk</a></aside></div>
    <h2 class="mt2">Study design</h2><div class="flow"><a class="step" href="#/model"><b>Predict</b><span>Estimate each CVE’s exploit probability.</span></a><a class="step" href="#/network"><b>Translate</b><span>Calculate risk and patch cost for each host.</span></a><a class="step" href="#/planner"><b>Optimize</b><span>Select patches within the available hours.</span></a><a class="step" href="#/evidence"><b>Backtest</b><span>Compare plans with later exploitation.</span></a></div>`;
  bindAtlas($(".atlas", v), ST.meta.weights);
  BarChart($("#h-bars"), {max:100, fmt:x=>pc(x,1), rows:["random","cvss_sorted","epss_sorted","ml_ilp"].map(k=>({label:STRAT[k].name,value:coverage(k),color:STRAT[k].color,hi:k==="ml_ilp"}))});
};
