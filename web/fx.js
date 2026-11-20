/* Experience layer: page-turn transitions, a drifting contour-map background, paper grain,
   magnetic buttons, rubber stamps and a Ctrl+K command palette.
   Everything except the palette is decoration; with prefers-reduced-motion the page stays still. */
window.FX = (() => {
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
  const finePointer = matchMedia("(hover: hover) and (pointer: fine)");
  const root = document.documentElement;
  const cssVar = name => getComputedStyle(root).getPropertyValue(name).trim();

  /* ---------------- contour-map background ---------------- */
  const terrain = (() => {
    const canvas = document.createElement("canvas");
    canvas.className = "fx-terrain";
    canvas.setAttribute("aria-hidden", "true");
    document.body.prepend(canvas);
    const grain = document.createElement("div");
    grain.className = "fx-grain";
    grain.setAttribute("aria-hidden", "true");
    document.body.prepend(grain);
    const ctx = canvas.getContext("2d");
    const STEP = 22, LEVELS = 9;
    let w = 0, h = 0, cols = 0, rows = 0, values = new Float32Array(0);
    let frame = 0, last = 0, colors = {}, visible = !document.hidden;
    const pointer = {x: -1e4, y: -1e4, strength: 0, target: 0};
    // Each section gets its own terrain; switching sections morphs one into the next.
    const seedOf = id => { let s = 7; for (const c of String(id)) s = (s * 31 + c.charCodeAt(0)) % 9973; return s; };
    const wavesFor = id => {
      let s = seedOf(id);
      const rnd = () => (s = (s * 16807) % 2147483647) / 2147483647;
      return Array.from({length: 5}, (_, k) => ({
        fx: (rnd() - .5) * .011 / (1 + k * .35), fy: (rnd() - .5) * .011 / (1 + k * .35),
        ph: rnd() * Math.PI * 2, sp: (rnd() - .5) * .00018, amp: 1 / (1 + k * .55)
      }));
    };
    let waves = wavesFor("intro"), from = waves, to = waves, morph = 1, morphStart = 0;

    function readColors() {
      colors = {line: cssVar("--line") || "#cfc7b4", strong: cssVar("--line2") || "#827c6f", accent: cssVar("--bad") || "#c8102e"};
      draw(performance.now());
    }
    function resize() {
      const dpr = Math.min(devicePixelRatio || 1, 2);
      w = innerWidth; h = innerHeight;
      canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
      canvas.style.width = w + "px"; canvas.style.height = h + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      cols = Math.ceil(w / STEP) + 2; rows = Math.ceil(h / STEP) + 2;
      values = new Float32Array(cols * rows);
      draw(performance.now());
    }
    function field(time) {
      const mix = morph >= 1 ? null : morph * morph * (3 - 2 * morph);
      const active = from.map((a, k) => mix === null ? to[k] : {
        fx: a.fx + (to[k].fx - a.fx) * mix, fy: a.fy + (to[k].fy - a.fy) * mix,
        ph: a.ph + (to[k].ph - a.ph) * mix, sp: a.sp + (to[k].sp - a.sp) * mix, amp: a.amp
      });
      const scroll = scrollY * .35, sigma2 = 2 * 120 * 120, bump = 1.5 * pointer.strength;
      for (let j = 0; j < rows; j++) {
        const y = j * STEP - STEP;
        for (let i = 0; i < cols; i++) {
          const x = i * STEP - STEP;
          let v = 0;
          for (const a of active) v += a.amp * Math.sin(x * a.fx + (y + scroll) * a.fy + a.ph + time * a.sp);
          if (bump) { const dx = x - pointer.x, dy = y - pointer.y; v += bump * Math.exp(-(dx * dx + dy * dy) / sigma2); }
          values[j * cols + i] = v;
        }
      }
    }
    // Marching squares, one path per pass; every fourth level is an index contour, drawn heavier.
    function contours(level, path) {
      for (let j = 0; j < rows - 1; j++) for (let i = 0; i < cols - 1; i++) {
        const a = values[j * cols + i], b = values[j * cols + i + 1], c = values[(j + 1) * cols + i + 1], d = values[(j + 1) * cols + i];
        const code = (a > level) | (b > level) << 1 | (c > level) << 2 | (d > level) << 3;
        if (code === 0 || code === 15) continue;
        const x = i * STEP - STEP, y = j * STEP - STEP;
        const t = (p, q) => (level - p) / (q - p || 1e-6);
        const top = [x + STEP * t(a, b), y], right = [x + STEP, y + STEP * t(b, c)];
        const bottom = [x + STEP * t(d, c), y + STEP], left = [x, y + STEP * t(a, d)];
        const seg = (p, q) => { path.moveTo(p[0], p[1]); path.lineTo(q[0], q[1]); };
        switch (code) {
          case 1: case 14: seg(left, top); break;
          case 2: case 13: seg(top, right); break;
          case 3: case 12: seg(left, right); break;
          case 4: case 11: seg(right, bottom); break;
          case 6: case 9: seg(top, bottom); break;
          case 7: case 8: seg(left, bottom); break;
          case 5: seg(left, top); seg(right, bottom); break;
          case 10: seg(top, right); seg(bottom, left); break;
        }
      }
    }
    function draw(time) {
      if (!w) return;
      if (morph < 1) morph = Math.min(1, (time - morphStart) / 1400);
      pointer.strength += (pointer.target - pointer.strength) * .08;
      field(reduced() ? 0 : time);
      const thin = new Path2D(), index = new Path2D();
      for (let k = 0; k < LEVELS; k++) contours(-2.2 + 4.4 * (k + .5) / LEVELS, k % 4 === 1 ? index : thin);
      ctx.clearRect(0, 0, w, h);
      ctx.lineJoin = "round";
      ctx.globalAlpha = .55; ctx.strokeStyle = colors.line; ctx.lineWidth = 1; ctx.stroke(thin);
      ctx.globalAlpha = .45; ctx.strokeStyle = colors.strong; ctx.lineWidth = 1.2; ctx.stroke(index);
      if (pointer.strength > .02) {
        // Lines near the pen darken, as if the plate were lit from the cursor.
        const glow = ctx.createRadialGradient(pointer.x, pointer.y, 0, pointer.x, pointer.y, 220);
        glow.addColorStop(0, colors.accent); glow.addColorStop(1, "transparent");
        ctx.globalAlpha = .55 * pointer.strength; ctx.strokeStyle = glow; ctx.lineWidth = 1.3;
        ctx.stroke(thin); ctx.stroke(index);
      }
      ctx.globalAlpha = 1;
    }
    function loop(time) {
      frame = 0;
      if (!visible || reduced()) return;
      if (time - last > 1000 / 24) { last = time; draw(time); }   // 24 fps is plenty for drifting ink
      frame = requestAnimationFrame(loop);
    }
    const start = () => { if (!frame && visible && !reduced()) frame = requestAnimationFrame(loop); };
    addEventListener("resize", resize);
    addEventListener("scroll", () => { if (reduced()) draw(0); }, {passive: true});
    document.addEventListener("visibilitychange", () => { visible = !document.hidden; start(); });
    document.addEventListener("pointermove", e => {
      if (e.pointerType !== "mouse" || !finePointer.matches) return;
      pointer.x = e.clientX; pointer.y = e.clientY; pointer.target = 1;
    }, {passive: true});
    document.addEventListener("pointerout", e => { if (!e.relatedTarget) pointer.target = 0; });
    matchMedia("(prefers-reduced-motion: reduce)").addEventListener("change", () => { draw(0); start(); });
    new MutationObserver(readColors).observe(root, {attributes: true, attributeFilter: ["data-theme"]});
    resize(); readColors(); start();
    return {
      retarget(id) {
        from = waves.map(a => ({...a}));
        to = wavesFor(id); waves = to;
        morph = reduced() ? 1 : 0; morphStart = performance.now();
        if (reduced()) draw(0);
      }
    };
  })();

  /* ---------------- page turns (View Transitions API) ---------------- */
  const order = id => id === "intro" ? -1 : NAV.findIndex(p => p.id === id);
  let current = null;
  async function pageTurn(id, update) {
    const previous = current;
    current = id;
    ensureShell();
    terrain.retarget(id);
    if (!document.startViewTransition || reduced() || previous === null || previous === id) { await update(); return; }
    root.dataset.turn = order(id) >= order(previous) ? "forward" : "back";
    const transition = document.startViewTransition(update);
    transition.finished.finally(() => { if (current === id) delete root.dataset.turn; });
    try { await transition.updateCallbackDone; } catch (e) { console.error(e); }
  }

  /* ---------------- magnetic buttons ---------------- */
  let magnet = null;
  const release = el => { if (el) { el.style.setProperty("--mag-x", "0px"); el.style.setProperty("--mag-y", "0px"); } };
  document.addEventListener("pointermove", e => {
    if (e.pointerType !== "mouse" || !finePointer.matches || reduced()) return;
    const el = e.target.closest?.(".btn:not(:disabled),.chip,.cover-mode,.contents-link,.fx-search");
    if (el !== magnet) { release(magnet); magnet = el; el?.classList.add("fx-mag"); }
    if (!el) return;
    const r = el.getBoundingClientRect();
    const pull = (v, a, len) => Math.max(-1, Math.min(1, (v - a - len / 2) / (len / 2)));
    el.style.setProperty("--mag-x", (pull(e.clientX, r.left, r.width) * 5).toFixed(1) + "px");
    el.style.setProperty("--mag-y", (pull(e.clientY, r.top, r.height) * 3).toFixed(1) + "px");
  }, {passive: true});
  document.addEventListener("pointerout", e => { if (magnet && !magnet.contains(e.relatedTarget)) { release(magnet); magnet = null; } });

  /* ---------------- rubber stamps ---------------- */
  function stamp(host, text, kind = "bad") {
    if (!host?.isConnected) return null;
    host.querySelector(":scope > .fx-stamp")?.remove();
    const mark = document.createElement("span");
    mark.className = `fx-stamp ${kind}`;
    mark.textContent = text;
    mark.setAttribute("aria-hidden", "true");
    mark.style.setProperty("--tilt", (Math.random() * 7 - 6).toFixed(1) + "deg");
    if (getComputedStyle(host).position === "static") host.style.position = "relative";
    host.append(mark);
    if (!reduced()) host.animate([{transform: "none"}, {transform: "translateY(2px) scale(.995)"}, {transform: "none"}],
      {duration: 180, delay: 260, easing: "ease-out"});
    return mark;
  }

  /* ---------------- command palette ---------------- */
  let palette, input, list, items = [], active = 0, hostCache = null, cveTicket = 0, lastFocus = null;
  const isTyping = el => el?.closest?.("input,textarea,select,[contenteditable=true]");
  function ensureShell() {
    const top = document.getElementById("top");
    if (!top || top.querySelector(".fx-search")) return;
    const button = document.createElement("button");
    button.type = "button"; button.className = "pill fx-search";
    button.innerHTML = `<span>Search</span><kbd>${/Mac|iPhone/.test(navigator.platform) ? "⌘" : "Ctrl"} K</kbd>`;
    button.setAttribute("aria-label", "Open the command palette");
    button.onclick = openPalette;
    top.querySelector(".grow")?.after(button);
  }
  function buildPalette() {
    palette = document.createElement("div");
    palette.className = "fx-palette";
    palette.innerHTML = `<div class="fx-pal-box" role="dialog" aria-modal="true" aria-label="Go to a section, host or CVE">
      <div class="fx-pal-field"><span class="figure-label">Go to</span><input type="text" role="combobox" aria-expanded="true" aria-controls="fx-pal-list" aria-autocomplete="list" placeholder="Section, host (H012), CVE id or action…" spellcheck="false"></div>
      <ul id="fx-pal-list" role="listbox"></ul>
      <footer><span>↑ ↓ move</span><span>Enter open</span><span>Esc close</span></footer></div>`;
    document.body.append(palette);
    input = palette.querySelector("input"); list = palette.querySelector("ul");
    palette.addEventListener("pointerdown", e => { if (e.target === palette) closePalette(); });
    input.addEventListener("input", refresh);
    input.addEventListener("keydown", e => {
      if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); move(e.key === "ArrowDown" ? 1 : -1); }
      else if (e.key === "Enter") { e.preventDefault(); choose(items[active]); }
      else if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); closePalette(); }
      else if (e.key === "Tab") e.preventDefault();
    });
    list.addEventListener("click", e => { const li = e.target.closest("li[data-i]"); if (li) choose(items[+li.dataset.i]); });
    list.addEventListener("pointermove", e => { const li = e.target.closest("li[data-i]"); if (li && +li.dataset.i !== active) { active = +li.dataset.i; paint(); } });
  }
  function actions() {
    const dark = root.dataset.theme === "dark";
    return [
      {kind: "Action", label: dark ? "Switch to Paper (light)" : "Switch to Darkroom (dark)", run: () => document.querySelector(`.themes [data-mode=${dark ? "light" : "dark"}]`)?.click()},
      {kind: "Action", label: "Generate a new network inventory", run: () => document.getElementById("invpill")?.click()},
      {kind: "Action", label: "Simulate a breach on the network map", run: () => { location.hash = "#/network?breach=1"; }},
      {kind: "Action", label: "Trace a CVE through the pipeline", run: () => { location.hash = "#/pipeline?trace=1"; }},
    ];
  }
  function sections() {
    return [{id: "intro", n: "0", nav: "Cover"}, ...NAV].map(p => ({kind: p.hidden ? "Appendix" : "Section", label: p.nav, meta: String(p.n).padStart(2, "0"), run: () => { location.hash = "#/" + p.id; }}));
  }
  async function hosts() {
    if (ST.plan?.hosts) return ST.plan.hosts;
    if (!hostCache) hostCache = api("/api/plan", planParams()).then(p => p.hosts).catch(() => []);
    return hostCache;
  }
  const score = (text, q) => {
    text = text.toLowerCase();
    if (text.startsWith(q)) return 3;
    if (text.split(/[\s·(),]+/).some(w => w.startsWith(q))) return 2;
    return text.includes(q) ? 1 : 0;
  };
  async function refresh() {
    const q = input.value.trim().toLowerCase(), ticket = ++cveTicket;
    let pool = [...sections(), ...actions()];
    if (!q) { items = pool.slice(0, 14); active = 0; paint(); return; }
    const hostRows = (await hosts()).map(h => ({kind: "Host", label: h.host, meta: `${h.exposure} · risk ${nf(h.initial, 1)}`, run: () => { location.hash = `#/network?host=${encodeURIComponent(h.host)}`; }}));
    if (ticket !== cveTicket) return;
    pool = [...pool, ...hostRows];
    items = pool.map(it => [it, score(it.label + " " + (it.meta || ""), q)]).filter(([, s]) => s).sort((a, b) => b[1] - a[1]).map(([it]) => it).slice(0, 12);
    active = 0; paint();
    if (q.length >= 3) {
      try {
        const d = await api("/api/cves", {q, sort: "p_exploit", split: "test"});   // the CVE page lists the test split
        if (ticket !== cveTicket || !palette.classList.contains("on")) return;
        const cves = d.rows.slice(0, 6).map(r => ({kind: "CVE", label: r.cve_id, meta: `${r.product} · p ${nf(r.p_exploit, 3)}`, run: () => openCve(r.cve_id)}));
        items = [...items.slice(0, 12 - Math.min(6, cves.length)), ...cves];
        paint();
      } catch {}
    }
  }
  function openCve(id) {
    location.hash = "#/cves";
    const deadline = performance.now() + 4000;
    const fill = () => {
      const field = document.getElementById("c-q");
      if (field && !document.querySelector("#view .skel")) { field.value = id; field.dispatchEvent(new Event("input")); return; }
      if (performance.now() < deadline) requestAnimationFrame(fill);
    };
    requestAnimationFrame(fill);
  }
  function paint() {
    list.innerHTML = items.length ? items.map((it, i) => `<li role="option" id="fx-opt-${i}" data-i="${i}" aria-selected="${i === active}"><span class="fx-kind">${esc(it.kind)}</span><b>${esc(it.label)}</b>${it.meta ? `<span class="fx-meta">${esc(it.meta)}</span>` : ""}</li>`).join("")
      : `<li class="fx-empty">Nothing matches. Try a host like H012, a product, or a CVE id.</li>`;
    input.setAttribute("aria-activedescendant", items.length ? `fx-opt-${active}` : "");
    list.querySelector('[aria-selected="true"]')?.scrollIntoView({block: "nearest"});
  }
  function move(step) { if (!items.length) return; active = (active + step + items.length) % items.length; paint(); }
  function choose(item) { if (!item) return; closePalette(); item.run(); }
  function openPalette() {
    if (!palette) buildPalette();
    if (palette.classList.contains("on")) return;
    lastFocus = document.activeElement;
    hostCache = null;
    document.querySelector(".app").inert = true;
    palette.classList.add("on");
    input.value = ""; refresh();
    input.focus();
  }
  function closePalette() {
    if (!palette?.classList.contains("on")) return;
    palette.classList.remove("on");
    if (!document.getElementById("drawer").classList.contains("open") && !document.getElementById("modal").classList.contains("on"))
      document.querySelector(".app").inert = false;
    if (lastFocus?.isConnected) lastFocus.focus({preventScroll: true});
  }
  document.addEventListener("keydown", e => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); palette?.classList.contains("on") ? closePalette() : openPalette(); }
    else if (e.key === "/" && !isTyping(e.target) && !e.ctrlKey && !e.metaKey) { e.preventDefault(); openPalette(); }
  });

  return {pageTurn, stamp, reduced, openPalette};
})();
