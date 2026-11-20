/* Pipeline trace: one real CVE from the current plan travels through the six stages of the
   architecture diagram. Scrolling moves it; the Trace button plays it from start to finish. */
async function traceCve(card, svg) {
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
  card.classList.add("trace-card");
  const ticket = document.createElement("div");
  ticket.className = "trace-ticket";
  ticket.innerHTML = `<span class="figure-label">Specimen</span><div class="trace-value">Loading a CVE from the current plan…</div><span></span>`;
  card.querySelector(".caption").before(ticket);
  let plan, detail;
  try {
    plan = ST.plan?.inventory_id === ST.meta.inventory_id && ST.plan.plan?.length ? ST.plan : await api("/api/plan", planParams());
    if (!plan.plan.length) throw new Error("The current plan selects no patches.");
    detail = await api("/api/patch", {id: plan.plan[0].patch_id, inventory_id: plan.inventory_id});
  } catch (e) { ticket.querySelector(".trace-value").textContent = "Trace unavailable: " + e.message; return; }
  if (!card.isConnected) return;
  const p = detail.patch, c = detail.cves[0], f = detail.formula, s = STRAT[plan.strategy].name;
  const readings = [
    [`${c.cve_id}`, `CVSS ${nf(c.cvss, 1)} · EPSS ${nf(c.epss, 3)} · affects ${esc(p.product)}`],
    [`p(exploit) = ${nf(c.p_exploit, 3)}`, "Calibrated probability from publication-time features"],
    [`risk ${nf(c.risk, 3)} on ${esc(p.host)}`, `${nf(c.p_exploit, 3)} × ${nf(f.top_impact, 2)} impact × ${p.criticality} criticality × ${nf(f.exposure_weight, 2)} (${esc(p.exposure)})`],
    [`Patch #${p.patch_id}: ${nf(p.benefit, 2)} benefit for ${nf(p.cost, 1)} h`, `${s} selects it at a ${budgetPercent(plan.pct)}% budget (${detail.n_total_cves} CVEs covered)`],
    [c.kev_later ? "Exploited later: covered by the plan" : "Not exploited in the follow-up year", "Backtest scores the plan against later KEV entries"],
    ["Visible in the planner and host drawer", `<a class="textlink" href="#/network?host=${encodeURIComponent(p.host)}&patch=${p.patch_id}">Open ${esc(p.host)} on the network map</a>`]
  ];
  const value = ticket.querySelector(".trace-value"), stageLabel = ticket.querySelector(".figure-label");
  const button = document.createElement("button");
  button.className = "btn ghost sm"; button.type = "button"; button.textContent = "Trace";
  ticket.lastElementChild.replaceWith(button);
  ticket.insertAdjacentHTML("beforeend", `<div class="trace-steps" aria-hidden="true">${readings.map(() => "<i></i>").join("")}</div>`);
  const steps = ticket.querySelectorAll(".trace-steps i");

  if (reduced()) {
    // No travelling token: list every reading instead.
    value.innerHTML = `${esc(c.cve_id)}<small>One CVE from the current plan, stage by stage</small>`;
    button.remove();
    ticket.insertAdjacentHTML("afterend", `<ol class="trace-list">${readings.map(([a, b], i) => `<li><b>${esc(STAGES[i].t.split(" · ")[1])}:</b> ${a}. <span class="mut">${b}</span></li>`).join("")}</ol>`);
    return;
  }

  const token = document.createElement("span");
  token.className = "trace-token"; token.setAttribute("aria-hidden", "true"); token.textContent = "CVE";
  card.append(token);
  let shown = -1, playing = null, frame = 0;
  function centers() {
    const base = card.getBoundingClientRect();
    return [...svg.querySelectorAll(".stage rect")].map(r => {
      const b = r.getBoundingClientRect();
      return [b.left - base.left + b.width * .78, b.top - base.top];   // ride along the top edge, clear of the stage text
    });
  }
  function place(progress) {
    const pts = centers();
    if (pts.length < 2) return;
    const at = Math.max(0, Math.min(1, progress)) * (pts.length - 1), i = Math.min(pts.length - 2, Math.floor(at)), k = at - i;
    const [a, b] = [pts[i], pts[i + 1]], sameRow = Math.abs(a[1] - b[1]) < 4;
    const [x, y] = sameRow ? [a[0] + (b[0] - a[0]) * k, a[1] - Math.sin(Math.PI * k) * 26] : (k < .5 ? a : b);
    token.style.transform = `translate(${x.toFixed(1)}px,${y.toFixed(1)}px)`;
    const stage = Math.round(at);
    if (stage !== shown) {
      shown = stage;
      svg.querySelectorAll(".stage").forEach((g, j) => g.classList.toggle("traced", j === stage));
      stageLabel.textContent = `Stage ${stage + 1} · ${STAGES[stage].t.split(" · ")[1]}`;
      value.innerHTML = `${readings[stage][0]}<small>${readings[stage][1]}</small>`;
      steps.forEach((el, j) => el.classList.toggle("on", j <= stage));
    }
  }
  function scrollProgress() {
    const r = card.getBoundingClientRect(), vh = innerHeight;
    const room = document.documentElement.scrollHeight - vh;
    if (room < 240) return null;   // the page barely scrolls: leave it to the Trace button
    return (vh * .82 - r.top) / Math.max(1, vh * .55);
  }
  function onScroll() {
    if (!card.isConnected) { removeEventListener("scroll", queue); removeEventListener("resize", queue); return; }
    if (playing) return;
    const p = scrollProgress();
    place(p === null ? 0 : p);
  }
  const queue = () => { if (!frame) frame = requestAnimationFrame(() => { frame = 0; onScroll(); }); };
  addEventListener("scroll", queue, {passive: true});
  addEventListener("resize", queue);
  function play() {
    const start = performance.now(), duration = 6500;
    playing = true; button.disabled = true;
    const tick = now => {
      if (!card.isConnected) return;
      const t = Math.min(1, (now - start) / duration);
      place(t);
      if (t < 1) requestAnimationFrame(tick);
      else { playing = null; button.disabled = false; button.textContent = "Trace again"; }
    };
    requestAnimationFrame(tick);
  }
  button.onclick = play;
  onScroll();
  if (new URLSearchParams(location.hash.split("?")[1]).has("trace")) { card.scrollIntoView({block: "center"}); setTimeout(play, 400); }
}
