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

const PAGES_INTRO = { id: "intro", n: "0", nav: "Cover" };
PAGES.intro = PAGES_INTRO;
PAGES_INTRO.render = async (v, token) => {
  const cmp = await api("/api/compare");
  if (token !== _routeToken) return;
  const at20 = cmp.summary.filter(r => Math.abs(r.budget_frac - .2) < 1e-6);
  const cov = k => at20.find(r => r.strategy === k).coverage_mean;
  const m = ST.meta, ratio = nf(cov("ml_ilp") / cov("cvss_sorted"), 1);
  const tick = [`${nf(m.hosts)} hosts on the current network`, `${nf(m.patches)} candidate patches`, `${nf(m.total_cost)} patch-hours of work`,
    `${cmp.n_inventories} simulated inventories`, `6 strategies × 3 budgets`, `ML + ILP covers ${ratio}× more later-exploited CVEs than CVSS-sorted at a 20% budget`,
    `cost of a missed exploit = ${m.cost_ratio}× a false alarm`];
  const tickHTML = tick.map(t => `<span>${esc(t)}</span><b class="ticker-fold" aria-hidden="true"></b>`).join("");
  v.innerHTML = `
  <header class="cover-mast"><a href="#/intro" class="cover-brand">${bulletinMark} Triage Bulletin</a>
    <span class="edition">IS353IA &nbsp; / &nbsp; Applied Machine Learning</span>
    <div class="mast-actions"><button class="cover-mode" id="cover-mode"></button><button class="contents-link" id="to-contents">Contents <span aria-hidden="true">☰</span></button></div></header>
  <section class="cover spread">
    <div class="cover-inner">
      <div class="cover-top"><i></i> Research series &nbsp;/&nbsp; Field report 01</div>
      <h1 class="cover-title">The Triage<br><em>Bulletin.</em></h1>
      <p class="cover-sub">Which patches come first? A field report on <em>exploit-aware vulnerability prioritization</em> under a limited budget of hours.</p>
      <div class="cover-row"><a class="btn" href="#/home">Begin reading</a><a class="textlink" href="#/network">Explore the live risk map</a></div>
    </div>
    ${coverMap()}
  </section>
  <section class="cover-figures" aria-label="Study at a glance">
    ${[["network", nf(m.hosts), "Network hosts"], ["planner",nf(m.patches),"Candidate patches"],["evidence",ratio+"×","Coverage vs CVSS-sorted"],["evidence",cmp.n_inventories,"Backtest inventories"]].map(([id,value,label]) => `<a href="#/${id}"><span class="v">${value}</span><span class="l">${label}</span></a>`).join("")}
  </section>
  <div class="ticker" aria-label="Key figures"><div class="ticker-track">${tickHTML}${tickHTML}</div></div>
  <section class="abstract" id="abstract">
    <div class="kick rv-intro">Abstract</div>
    <p class="scrolltext big">Thousands of CVEs are published every year, and only a few percent are ever exploited. Patching by severity alone spends scarce hours on the wrong ones. This project predicts which CVEs will be exploited, turns those probabilities into host-level risk on a simulated network, and picks the patch plan that removes the most risk inside a fixed budget of hours.</p>
  </section>
  <section class="contents" id="contents">
    <div class="kick rv-intro">Contents</div>
    <ol>${CONTENTS.map(([id, line]) => { const p = PAGES[id]; return `<li class="rv-intro"><a href="#/${id}"><span class="n">${String(p.n).padStart(2, "0")}</span><span class="t">${p.nav}</span><span class="lead"></span><span class="d">${line}</span><span class="arrow">→</span></a></li>`; }).join("")}</ol>
  </section>
  <section class="colophon rv-intro"><span class="colophon-brand">${bulletinMark} The Triage Bulletin</span><span>Applied Machine Learning · University project · All study data synthetic</span><a class="btn ghost" href="#/home">Begin reading</a></section>`;
  $("#to-contents").onclick = () => $("#contents").scrollIntoView({ behavior: Motion.reduced() ? "auto" : "smooth" });
  bindAtlas($(".atlas", v), m.weights);
  const mode = $("#cover-mode");
  function labelMode() {
    const dark = document.documentElement.dataset.theme === "dark";
    mode.innerHTML = ic(dark ? "sun" : "moon", 16) + (dark ? "Paper" : "Darkroom");
    mode.setAttribute("aria-label", "Switch to " + (dark ? "Paper" : "Darkroom") + " theme");
  }
  mode.onclick = () => { const target = document.documentElement.dataset.theme === "dark" ? "light" : "dark"; document.querySelector(`.themes [data-mode="${target}"]`).click(); labelMode(); };
  labelMode();
};
