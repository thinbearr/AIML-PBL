/* Network lab add-ons: the 2D atlas / 3D towers switch and the breach replay.
   The breach replay is illustrative, not a measured attack. An attacker enters through internet-facing
   hosts and moves to downstream hosts along the simulator's parent links. Whether a step succeeds is
   a fixed per-host draw compared with that host's modelled risk (before patching, or residual after the
   plan). The draws are the same in both runs, so any difference comes only from the patch plan. */
const Breach = (() => {
  // Deterministic per-host uniform draw in [0,1); the salt separates the timing draw from the success draw.
  const draw = (i, salt) => {
    let x = Math.imul((i + 1) ^ salt, 2654435761) >>> 0;
    x ^= x >>> 16; x = Math.imul(x, 2246822507) >>> 0; x ^= x >>> 13; x = Math.imul(x, 3266489909) >>> 0; x ^= x >>> 16;
    return (x >>> 0) / 4294967296;
  };
  function simulate(hosts, phase) {
    const scale = Math.max(...hosts.map(h => h.initial), 1e-3);
    const children = new Map();
    for (const h of hosts) if (h.parent >= 0) { if (!children.has(h.parent)) children.set(h.parent, []); children.get(h.parent).push(h); }
    const risk = h => phase === "after" ? h.residual : h.initial;
    const succeeds = h => draw(h.i, 0x5bd1) < .92 * Math.sqrt(Math.min(1, risk(h) / scale));
    const events = [], reached = new Set();
    const visit = (h, from, t0) => {
      const t1 = t0 + .55 + draw(h.i, 0x9e37) * .35, ok = succeeds(h);
      events.push({from, to: h.i, t0, t1, ok});
      if (!ok) return;
      reached.add(h.i);
      for (const c of children.get(h.i) || []) visit(c, h.i, t1 + .08 + draw(c.i, 0x1f3) * .25);
    };
    hosts.filter(h => h.exposure === "internet").forEach(h => visit(h, null, draw(h.i, 0x77) * .9));
    const end = Math.max(0, ...events.map(e => e.t1)) + .4;
    return {events, reached, end, phase};
  }

  /* SVG overlay on the 2D atlas. */
  function overlay2D(svg, map) {
    const ns = "http://www.w3.org/2000/svg";
    const layer = document.createElementNS(ns, "g");
    layer.setAttribute("class", "breach-layer");
    layer.setAttribute("aria-hidden", "true");
    svg.append(layer);
    const marked = new Set();
    const el = (tag, attrs) => { const n = document.createElementNS(ns, tag); for (const k in attrs) n.setAttribute(k, attrs[k]); layer.append(n); return n; };
    return {
      frame(run, t) {
        layer.replaceChildren();
        for (const e of run.events) {
          if (t < e.t0) continue;
          const end = map.position(e.to);
          if (!end) continue;
          // Entry attempts arrive from outside the outer (internet) shelf, along the line from the map centre.
          const out = Math.hypot(end[0] - 425, end[1] - 244) || 1;
          const start = e.from === null ? [end[0] + (end[0] - 425) / out * 70, end[1] + (end[1] - 244) / out * 45] : map.position(e.from);
          if (!start) continue;
          const f = Math.min(1, (t - e.t0) / (e.t1 - e.t0));
          const stop = e.ok ? 1 : .72;   // a blocked step fizzles short of the host
          const k = Math.min(f, stop), lift = -26 * Math.sin(Math.PI * k);
          const x = start[0] + (end[0] - start[0]) * k, y = start[1] + (end[1] - start[1]) * k + lift;
          if (f < 1) {
            el("path", {class: "trail", d: `M${start[0].toFixed(1)} ${start[1].toFixed(1)} Q${((start[0] + x) / 2).toFixed(1)} ${(Math.min(start[1], y) - 14).toFixed(1)} ${x.toFixed(1)} ${y.toFixed(1)}`});
            el("circle", {class: "spark", cx: x.toFixed(1), cy: y.toFixed(1), r: 2.6});
          } else if (!e.ok && t - e.t1 < .7) {
            const o = (1 - (t - e.t1) / .7).toFixed(2), cx = x.toFixed(1), cy = y.toFixed(1);
            el("path", {class: "blocked", d: `M${cx - 4} ${cy - 4}l8 8m0 -8l-8 8`, opacity: o});
          }
          if (e.ok && f >= 1 && !marked.has(e.to)) { marked.add(e.to); map.marker(e.to)?.classList.add("breached"); }
        }
      },
      clear() {
        layer.replaceChildren();
        for (const id of marked) map.marker(id)?.classList.remove("breached");
        marked.clear();
      },
      settle(run) {   // reduced motion: show the outcome without the journey
        this.clear();
        for (const id of run.reached) { marked.add(id); map.marker(id)?.classList.add("breached"); }
      },
      destroy() { this.clear(); layer.remove(); }
    };
  }
  return {simulate, overlay2D};
})();

/* Wraps the 2D risk map so the network page drives either view through one interface. */
function withAttackViews(map, root, hosts, onInspect) {
  const svg = root.querySelector("#n-svg"), tools = root.querySelector(".map-tools");
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
  let current = hosts, mode = "2d", view3d = null, loading = null, wipe = 100, tiers = null, selected = null, run = null;
  const overlay = Breach.overlay2D(svg, map);

  const stage = document.createElement("div");
  stage.className = "map-stage";
  svg.before(stage); stage.append(svg);
  const readout = document.createElement("div");
  readout.className = "breach-readout"; readout.setAttribute("role", "status");
  readout.innerHTML = `<span>Breach replay: press <b style="font-size:1rem">Simulate breach</b> to send an attacker in from the internet tier, once before patching and once after the plan.</span>`;
  root.querySelector(".map-key").before(readout);
  tools.insertAdjacentHTML("beforeend", `<div class="fx-map-actions">
    <div class="seg" role="group" aria-label="Map view"><button type="button" data-view="2d" aria-pressed="true">Atlas</button><button type="button" data-view="3d" aria-pressed="false">3D towers</button></div>
    <button type="button" class="btn sm breach-btn">Simulate breach</button></div>`);
  const viewButtons = tools.querySelectorAll("[data-view]"), breachButton = tools.querySelector(".breach-btn");
  const wipeInput = root.querySelector("#risk-wipe");
  const setWipe = value => { wipeInput.value = value; wipeInput.dispatchEvent(new Event("input")); };

  async function show3D() {
    if (!loading) loading = import("/attack3d.js").then(m => {
      view3d = m.mountTowers(stage, current, {onInspect, wipe, tiers, selected});
      return view3d;
    }).catch(error => { loading = null; throw error; });
    return loading;
  }
  async function setMode(next) {
    if (next === mode) return;
    cancel();
    viewButtons.forEach(b => b.setAttribute("aria-pressed", b.dataset.view === next));
    if (next === "3d") {
      try { await show3D(); } catch (error) { console.error(error); toast("3D view could not start: " + error.message); viewButtons.forEach(b => b.setAttribute("aria-pressed", b.dataset.view === "2d")); return; }
      if (!stage.isConnected) return;
      svg.style.display = "none"; view3d.show(true);
    } else { view3d?.show(false); svg.style.display = ""; }
    mode = next;
  }
  viewButtons.forEach(b => b.onclick = () => setMode(b.dataset.view));

  function cancel() {
    if (!run) return;
    cancelAnimationFrame(run.frame); clearTimeout(run.timer);
    run = null; overlay.clear(); view3d?.clearBreach();
    breachButton.disabled = false;
  }
  function play(sim) {
    return new Promise(resolve => {
      const renderer = mode === "3d" ? view3d : overlay;
      if (reduced()) { renderer.settle(sim); resolve(); return; }
      const start = performance.now(), speed = 1.6;   // 1.6 simulated units per second
      const tick = now => {
        if (!run || !stage.isConnected) return;
        const t = (now - start) / 1000 * speed;
        renderer.frame(sim, t);
        if (t < sim.end) run.frame = requestAnimationFrame(tick); else resolve();
      };
      run.frame = requestAnimationFrame(tick);
    });
  }
  const wait = ms => new Promise(r => { if (run) run.timer = setTimeout(r, reduced() ? 0 : ms); });
  async function breach() {
    cancel();
    const token = run = {frame: 0, timer: 0};
    breachButton.disabled = true;
    const before = Breach.simulate(current, "before"), after = Breach.simulate(current, "after");
    const total = current.length;
    readout.innerHTML = `<span class="before">Before patching <b>…</b></span>`;
    setWipe(0);
    await play(before);
    if (run !== token) return;
    readout.innerHTML = `<span class="before">Before patching <b>${before.reached.size}</b>hosts reached</span><span class="after">After plan <b>…</b></span>`;
    await wait(900);
    if (run !== token) return;
    overlay.clear(); view3d?.clearBreach();
    setWipe(100);
    await play(after);
    if (run !== token) return;
    const drop = before.reached.size ? 100 * (1 - after.reached.size / before.reached.size) : 0;
    readout.innerHTML = `<span class="before">Before patching <b>${before.reached.size}</b>of ${total} hosts reached</span>
      <span class="after">After plan <b>${after.reached.size}</b>hosts reached (${nf(drop, 0)}% fewer)</span>
      <small>Illustrative replay. Each step succeeds with a chance that rises with the host's modelled risk. Both runs use the same random draws, so only the patch plan differs.</small>`;
    window.FX?.stamp(readout, drop >= 40 ? "Contained" : drop > 0 ? "Slowed" : "Exposed", drop >= 40 ? "good" : "bad");
    breachButton.disabled = false;
    breachButton.textContent = "Replay breach";
    run = null;
  }
  breachButton.onclick = breach;
  if (new URLSearchParams(location.hash.split("?")[1]).has("breach"))
    requestAnimationFrame(() => { stage.scrollIntoView({block: "center", behavior: reduced() ? "auto" : "smooth"}); setTimeout(breach, reduced() ? 0 : 500); });

  return {
    rotate(angle) { mode === "3d" ? view3d?.rotate(angle) : map.rotate(angle); },
    scrub(value) { wipe = value; map.scrub(value); view3d?.scrub(value); },
    select(id) { selected = id; map.select(id); view3d?.select(id); },
    update(next, added) { cancel(); current = next; map.update(next, added); view3d?.update(next, added); },
    marker(id) { return mode === "3d" && view3d ? view3d.canvas : map.marker(id); },
    filter(next) { tiers = new Set(next); map.filter(next); view3d?.filter(tiers); }
  };
}
