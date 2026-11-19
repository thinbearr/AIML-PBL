/* Intro: the bulletin's cover. Shown at the site root (#/intro). */
const CONTENTS = [
  ["home", "Why severity-first patching spends hours on the wrong CVEs."],
  ["model", "From a CVE record to a calibrated exploit probability."],
  ["network", "Turning probabilities into host-level risk on a simulated network."],
  ["planner", "Give it a budget of hours, get a justified patch list."],
  ["pareto", "Greedy, exact ILP and NSGA-II, side by side."],
  ["evidence", "Which strategy covers the most later-exploited CVEs."],
  ["upload", "Run the whole pipeline on your own host inventory."],
  ["roadmap", "What is simulated, what is not claimed, and what comes next."],
];

/* A large contour map drawn as ink: each ring is a path that draws itself in. */
function coverMap() {
  const point = (a, r) => {
    const relief = 1 + .11 * Math.sin(3 * a + r * 2) + .07 * Math.cos(5 * a - r) + .03 * Math.sin(9 * a + r);
    return [960 + 520 * r * relief * Math.cos(a), 400 + 330 * r * relief * Math.sin(a)];
  };
  const rings = Array.from({ length: 22 }, (_, i) => {
    const r = .06 + i * .055;
    const d = Array.from({ length: 241 }, (_, j) => point(j * Math.PI / 120, r).map(v => v.toFixed(1)).join(",")).join(" L");
    return `<path d="M${d}Z" pathLength="1" class="ring" style="--i:${i}" stroke-width="${i % 5 === 4 ? 1.4 : .6}"/>`;
  }).join("");
  const dots = Array.from({ length: 70 }, (_, i) => {
    const r = .12 + ((i * 41) % 97) / 100, [x, y] = point(i * 2.39996, r), hot = (i * 7) % 11 === 0;
    return `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${hot ? 6 : 3}" class="pin ${hot ? "hot" : ""}" style="--i:${i}"/>`;
  }).join("");
  return `<svg class="cover-map" viewBox="0 0 1800 800" preserveAspectRatio="xMidYMid slice" aria-hidden="true" data-parallax="-0.12">${rings}${dots}</svg>`;
}

const PAGES_INTRO = { id: "intro", n: "0", nav: "Cover" };
PAGES.intro = PAGES_INTRO;
PAGES_INTRO.render = async (v, token) => {
  const cmp = await api("/api/compare");
  if (token !== _routeToken) return;
  const at20 = cmp.summary.filter(r => Math.abs(r.budget_frac - .2) < 1e-6);
  const cov = k => at20.find(r => r.strategy === k).coverage_mean;
  const m = ST.meta, ratio = nf(cov("ml_ilp") / cov("cvss_sorted"), 1);
  const title = "The Triage Bulletin".split(" ").map((w, wi) =>
    `<span class="cw">${[...w].map((c, ci) => `<span class="ch" style="--i:${wi * 4 + ci}">${c}</span>`).join("")}</span>`).join(" ");
  const tick = [`${nf(m.hosts)} hosts on the current network`, `${nf(m.patches)} candidate patches`, `${nf(m.total_cost)} patch-hours of work`,
    `${cmp.n_inventories} simulated inventories`, `6 strategies × 3 budgets`, `ML + ILP covers ${ratio}× more later-exploited CVEs than CVSS-sorted at a 20% budget`,
    `cost of a missed exploit = ${m.cost_ratio}× a false alarm`];
  const tickHTML = tick.map(t => `<span>${esc(t)}</span><b>✚</b>`).join("");
  v.innerHTML = `
  <section class="cover">
    ${coverMap()}
    <div class="cover-inner">
      <div class="cover-top"><span>IS353IA · AIML Lab</span><i></i><span>Research series · No. 01</span></div>
      <h1 class="cover-title" aria-label="The Triage Bulletin">${title}</h1>
      <p class="cover-sub">A field report on <em>cost-sensitive, exploit-aware</em> vulnerability prioritization: which patches to apply first when there are never enough hours.</p>
      <div class="cover-row"><a class="btn" href="#/home">Begin reading →</a><button class="textlink linkbtn" id="to-contents">Contents</button><span class="cover-stamp">Synthetic data</span></div>
    </div>
    <button class="scrollcue" id="cue" aria-label="Scroll to abstract"><span>Scroll</span><i></i></button>
  </section>
  <div class="ticker" aria-label="Key figures"><div class="ticker-track">${tickHTML}${tickHTML}</div></div>
  <section class="abstract" id="abstract">
    <div class="kick rv-intro">Abstract</div>
    <p class="scrolltext big">Thousands of CVEs are published every year, and only a few percent are ever exploited. Patching by severity alone spends scarce hours on the wrong ones. This project predicts which CVEs will be exploited, turns those probabilities into host-level risk on a simulated network, and picks the patch plan that removes the most risk inside a fixed budget of hours.</p>
  </section>
  <section class="cover-figures">
    <div class="rv-intro"><div class="v count">${nf(m.hosts)}</div><div class="l">Hosts on the network</div></div>
    <div class="rv-intro"><div class="v count">${nf(m.patches)}</div><div class="l">Candidate patches</div></div>
    <div class="rv-intro"><div class="v"><mark>${ratio}×</mark></div><div class="l">Coverage vs CVSS-sorted</div></div>
    <div class="rv-intro"><div class="v count">${cmp.n_inventories}</div><div class="l">Inventories in the backtest</div></div>
  </section>
  <section class="contents" id="contents">
    <div class="kick rv-intro">Contents</div>
    <ol>${CONTENTS.map(([id, line]) => { const p = PAGES[id]; return `<li class="rv-intro"><a href="#/${id}"><span class="n">${String(p.n).padStart(2, "0")}</span><span class="t">${p.nav}</span><span class="lead"></span><span class="d">${line}</span><span class="arrow">→</span></a></li>`; }).join("")}</ol>
  </section>
  <section class="colophon rv-intro"><span>✚ The Triage Bulletin</span><span>Applied Machine Learning · University project · All data synthetic</span><a class="btn ghost" href="#/home">Begin reading →</a></section>`;
  $("#to-contents").onclick = () => $("#contents").scrollIntoView({ behavior: Motion.reduced() ? "auto" : "smooth" });
  $("#cue").onclick = () => $("#abstract").scrollIntoView({ behavior: Motion.reduced() ? "auto" : "smooth" });
};
