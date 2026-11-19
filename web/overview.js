/* A schematic plate introduces the exposure tiers. The network section uses live hosts. */
function exposurePlate() {
  const point = (angle, radius) => {
    const relief = 1 + .10 * Math.sin(3 * angle + radius) + .07 * Math.cos(5 * angle - radius) + .035 * Math.sin(8 * angle);
    return [158 + 122 * radius * relief * Math.cos(angle), 100 + 77 * radius * relief * Math.sin(angle)];
  };
  const contours = Array.from({length: 15}, (_, i) => {
    const path = Array.from({length: 181}, (_, j) => point(j * Math.PI / 90, .14 + i * .06).map(v=>v.toFixed(1)).join(",")).join(" ");
    return `<polygon points="${path}" fill="none" stroke="var(--ink2)" stroke-width="${i % 4 ? .55 : 1.15}"/>`;
  }).join("");
  const dots = Array.from({length: 48}, (_, i) => {
    const r = .2 + ((i * 37) % 67) / 100, [x,y] = point(i * 2.4, r), risk = r > .70;
    return `<circle cx="${x}" cy="${y}" r="${risk ? 3.5 : 2}" fill="${risk ? "var(--bad)" : "var(--ink)"}" stroke="var(--bg)" stroke-width=".7"/>`;
  }).join("");
  return `<figure class="plate"><div class="plate-label"><span>PLATE 01</span> EXPOSURE TIERS</div><svg viewBox="0 0 360 198" role="img" aria-label="Schematic contour map of internal, DMZ and internet exposure tiers">
    <defs><pattern id="grid" patternUnits="userSpaceOnUse" width="18" height="18"><path d="M18 0H0V18" fill="none" stroke="var(--line)" stroke-width=".7"/></pattern></defs>
    <rect width="360" height="198" fill="url(#grid)"/>${contours}${dots}
    <g fill="none" stroke="var(--ink)" stroke-width=".8"><path d="M166 92l38 -42h81M213 110l38 -25h34M261 132h24"/></g>
    <g class="map-label"><text x="289" y="53">Internal</text><text x="289" y="88">DMZ</text><text x="289" y="135">Internet</text></g></svg><figcaption>Exposure by network position · schematic</figcaption></figure>`;
}

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
    <a class="btn" href="#/planner">Open patch planner</a> <a class="textlink" href="#/evidence">Read the evidence</a></div>${exposurePlate()}</header>
    <div class="scoreboard">
      <div class="stat"><div class="l">Coverage advantage</div><div class="v"><mark>${ratio}×</mark></div><small><sup>1</sup> ML + ILP relative to CVSS-sorted</small></div>
      <div class="stat"><div class="l">Patch budget</div><div class="v">20<span>%</span></div><small><sup>2</sup> Share of total patch effort</small></div>
      <div class="stat"><div class="l">Study population</div><div class="v">${cmp.n_inventories}</div><small><sup>3</sup> Simulated network inventories</small></div>
    </div>
    <div class="results-layout"><section class="card overview-result"><div class="figure-label">FIG. 1 <span>/</span> BACKTEST EVIDENCE</div>
      <h2>Coverage of later-exploited CVEs</h2><div class="sub">Mean coverage at a fixed 20% budget</div><div id="h-bars"></div>
      <p class="caption">Each strategy faces the same patch-hour limit. Coverage is measured against subsequent KEV labels.</p></section>
      <aside class="marginal"><div class="figure-label">Margin note 01</div><h3>Why cost matters</h3><p>A CVE score estimates the likelihood of exploitation. A patch decision also depends on host exposure, business impact and the hours needed to apply it.</p><a class="textlink" href="#/network">Explore network risk</a></aside></div>
    <h2 class="mt2">Study design</h2><div class="flow"><div class="step"><b>Predict</b><span>Estimate each CVE’s exploit probability.</span></div><div class="step"><b>Translate</b><span>Calculate risk and patch cost for each host.</span></div><div class="step"><b>Optimize</b><span>Select patches within the available hours.</span></div><div class="step"><b>Backtest</b><span>Compare plans with later exploitation.</span></div></div>`;
  BarChart($("#h-bars"), {max:100, fmt:x=>pc(x,1), rows:["random","cvss_sorted","epss_sorted","ml_ilp"].map(k=>({label:STRAT[k].name,value:coverage(k),color:STRAT[k].color,hi:k==="ml_ilp"}))});
};
