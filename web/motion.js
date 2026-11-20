/* The illustrations on the section dividers are schematic printing plates. */
function folioPlate(page) {
  const topology = '<path d="m12 42 27-23 31 12 37-15M39 19l18 35 13-23 19 16 18-31"/>' +
    [[12,42],[39,19],[57,54],[70,31],[89,47],[107,16]].map(([x,y]) =>
      `<circle cx="${x}" cy="${y}" r="3.5"/>`).join("");
  const bars = '<path d="M14 53h92"/><path class="plate-columns" d="M22 51V39h9v12zm20 0V29h9v22zm20 0V33h9v18zm20 0V14h9v37z"/>';
  const ledger = '<path d="M26 16h76M26 30h63M26 44h72M26 52h40"/><path class="plate-columns" d="M13 13h5v5h-5zm0 14h5v5h-5zm0 14h5v5h-5z"/>';
  const curve = '<path d="M12 11v43h93"/><path class="plate-trace" d="M13 49c14-1 19-5 27-14s17-6 28-10 12-13 35-14"/><path class="plate-guide" d="m14 49 84-34"/>';
  const phases = '<path d="M10 44h24V30h27V18h45"/><circle cx="18" cy="44" r="4"/><circle cx="47" cy="30" r="4"/><circle cx="83" cy="18" r="4"/>';
  const print = {network:topology,extend:topology,model:curve,pareto:curve,evidence:bars,data:bars,
    planner:ledger,upload:ledger,cves:ledger,pipeline:phases,roadmap:phases}[page] || ledger;
  return `<button class="folio" type="button" aria-label="Separate the illustration layers" aria-pressed="false">
    <span class="folio-shadow" aria-hidden="true"></span>
    <span class="folio-camera" aria-hidden="true"><span class="folio-stack">
      <span class="folio-layer folio-board"></span><span class="folio-layer folio-grid"></span>
      <span class="folio-layer folio-proof"><svg viewBox="0 0 120 64" focusable="false">${print}</svg></span>
    </span></span></button>`;
}

/* Motion layer: headline reveals, scroll reveals, scroll-linked text, reading progress, parallax, nav underline.
   Everything here is decoration. With prefers-reduced-motion the page renders fully and statically. */
window.Motion = (() => {
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
  const finePointer = matchMedia("(hover: hover) and (pointer: fine)");
  const halo = document.createElement("div");
  halo.className = "ink-cursor";
  halo.setAttribute("aria-hidden","true");
  document.body.append(halo);
  let litSurface, depthSurface, pointerFrame, latestPointer;
  const depthTargets = ".folio,.atlas,.cover-inner,.cover-figures a,.stat,.kpi,.step,.marginal,.drop,.contents li,.phase";
  function resetDepth() {
    if (!depthSurface) return;
    depthSurface.classList.remove("tilting");
    for (const key of ["--rotate-x","--rotate-y"]) depthSurface.style.removeProperty(key);
    depthSurface = null;
  }
  function clearPointer() {
    cancelAnimationFrame(pointerFrame);
    pointerFrame = 0;
    halo.classList.remove("active");
    litSurface?.classList.remove("ink-surface");
    litSurface = null;
    resetDepth();
  }
  function paintPointer() {
    pointerFrame = 0;
    const {target,clientX,clientY} = latestPointer;
    const surface = target.closest(".card,.cover-figures a,.step,.plate");
    const depth = target.closest(depthTargets);
    if (depth !== depthSurface) {
      resetDepth();
      depthSurface = depth;
      depth?.classList.add("tilting");
    }
    if (depth) {
      const rect = depth.getBoundingClientRect();
      const normalized = (value, start, length) => Math.max(-1,Math.min(1,2*(value-start)/length-1));
      const amplitude = depth.matches(".folio") ? 18 : depth.matches(".atlas,.cover-inner") ? 3 : 6;
      depth.style.setProperty("--rotate-x", (-amplitude*normalized(clientY,rect.top,rect.height)).toFixed(2)+"deg");
      depth.style.setProperty("--rotate-y", (amplitude*normalized(clientX,rect.left,rect.width)).toFixed(2)+"deg");
    }
    if (surface !== litSurface) {
      litSurface?.classList.remove("ink-surface");
      litSurface = surface;
      surface?.classList.add("ink-surface");
    }
    if (surface) {
      const r = surface.getBoundingClientRect();
      surface.style.setProperty("--light-x", (clientX-r.left)+"px");
      surface.style.setProperty("--light-y", (clientY-r.top)+"px");
    }
    const inspect = target.closest(".figure-mark,.chart-probe,.host-node,.atlas-pin");
    const control = target.closest("a,button,summary,.drop,.stage");
    halo.dataset.mode = inspect ? "probe" : "ink";
    halo.classList.toggle("active", Boolean(inspect || control));
    halo.style.transform = `translate3d(${clientX}px,${clientY}px,0)`;
  }
  document.addEventListener("pointermove", e => {
    if (e.pointerType !== "mouse" || !finePointer.matches || reduced()) { clearPointer(); return; }
    latestPointer = e;
    if (!pointerFrame) pointerFrame = requestAnimationFrame(paintPointer);
  }, {passive:true});
  document.addEventListener("pointerout", e => { if (!e.relatedTarget) clearPointer(); });
  document.addEventListener("focusin", clearPointer);
  window.addEventListener("blur",clearPointer);
  window.addEventListener("scroll",clearPointer,{passive:true});
  document.addEventListener("click", event => {
    const folio = event.target.closest(".folio");
    if (!folio) return;
    const separated = folio.getAttribute("aria-pressed") !== "true";
    folio.setAttribute("aria-pressed", String(separated));
    folio.setAttribute("aria-label", separated ? "Stack the illustration layers" : "Separate the illustration layers");
  });
  const motionPreference = matchMedia("(prefers-reduced-motion: reduce)");
  motionPreference.addEventListener("change", clearPointer);
  const REVEAL = [".sectionhead .lede", ".sectionhead .definition", ".opening .lede", ".opening .plate", ".opening .btn", ".opening .textlink",
    ".scoreboard .stat", ".card", ".marginal", ".flow .step", ".view > h2", ".finding", ".callout", ".phase", ".footnotes", ".pagelinks",
    "#criteria li", ".rv-intro"].join(",");
  const FILL = ".finding, .callout, .marginal p, .scrolltext";
  let io, fills = [], parallax = [], cover;
  const visibleFolios = new IntersectionObserver(entries => {
    for (const entry of entries) entry.target.classList.toggle("is-visible", entry.isIntersecting);
  });

  /* Split the text of an element into word spans, keeping inline markup (<b>, <mark>, <br>) intact. */
  function splitWords(root, cls) {
    const words = [];
    const walk = node => {
      for (const child of [...node.childNodes]) {
        if (child.nodeType === 3) {
          const frag = document.createDocumentFragment();
          for (const part of child.textContent.split(/(\s+)/)) {
            if (!part) continue;
            if (/^\s+$/.test(part)) { frag.append(part); continue; }
            const s = document.createElement("span"); s.className = cls; s.textContent = part; frag.append(s); words.push(s);
          }
          child.replaceWith(frag);
        } else if (child.nodeType === 1 && !child.matches("svg, .tag, mark")) walk(child);
        else if (child.nodeType === 1 && child.matches("mark")) { child.classList.add(cls); words.push(child); }
      }
    };
    walk(root);
    return words;
  }

  /* Page headline: each word rises out of a mask, one after another. */
  function headline(view) {
    for (const h of view.querySelectorAll("h1.title")) {
      splitWords(h, "hw").forEach((w, i) => {
        const mask = document.createElement("span"); mask.className = "hw-mask";
        w.replaceWith(mask); mask.append(w); w.style.setProperty("--i", i);
      });
      h.classList.add("split");
    }
  }

  /* Numbers count up the first time they scroll into view. */
  const counted = new WeakSet();
  function countUp(root) {
    for (const el of root.querySelectorAll(".v mark, .v:not(:has(*)), .count")) {
      if (counted.has(el)) continue; counted.add(el);
      const original = el.textContent, m = /^([\d,]+(?:\.\d+)?)(.*)$/.exec(original.trim());
      if (!m) continue;
      const end = Number(m[1].replaceAll(",", "")), dec = (m[1].split(".")[1] || "").length, t0 = performance.now();
      let written = original;
      const tick = t => {
        if (!el.isConnected || el.textContent !== written) return;   // page code replaced the value: stop
        const f = Math.min(1, (t - t0) / 900), e = 1 - Math.pow(1 - f, 3);
        written = el.textContent = f === 1 ? original : nf(end * e, dec) + m[2];
        if (f < 1) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    }
  }

  /* Charts redraw their ink when their figure is revealed, not when the page loads below the fold. */
  function redraw(root) {
    for (const el of root.querySelectorAll(".ink-stroke, .ink-bar")) { el.style.animation = "none"; void el.getBoundingClientRect(); el.style.animation = ""; }
  }

  function reveal(view) {
    io?.disconnect();
    const els = [...new Set(view.querySelectorAll(REVEAL))];
    els.forEach(el => el.classList.add("rv"));
    io = new IntersectionObserver(entries => {
      const shown = entries.filter(e => e.isIntersecting).map(e => e.target)
        .sort((a, b) => { const p = a.getBoundingClientRect(), q = b.getBoundingClientRect(); return p.top - q.top || p.left - q.left; });
      shown.forEach((el, i) => {
        el.style.transitionDelay = `${Math.min(i, 7) * 70}ms`;
        el.classList.add("in"); io.unobserve(el);
        countUp(el); redraw(el);
        setTimeout(() => { el.style.transitionDelay = ""; }, 1400);
      });
    }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
    els.forEach(el => io.observe(el));
  }

  /* Scroll-linked text: words darken from faint to full ink as the paragraph moves up the screen. */
  function fillText(view) {
    // Only text that starts below the fold is scroll-linked; text already on screen is simply shown.
    fills = [...view.querySelectorAll(FILL)].filter(el => el.getBoundingClientRect().top > innerHeight * .85)
      .map(el => ({ el, words: splitWords(el, "wf") })).filter(f => f.words.length > 3);
    fills.forEach(f => f.el.classList.add("filling"));
  }

  function onScroll() {
    const y = scrollY, vh = innerHeight, max = document.documentElement.scrollHeight - vh;
    const bar = document.getElementById("progress"); if (bar) bar.style.transform = `scaleX(${max > 0 ? Math.min(1, y / max) : 0})`;
    document.getElementById("chrome")?.classList.toggle("scrolled", y > 8);
    if (cover?.isConnected && !reduced()) {
      const progress = Math.min(1, Math.max(0, y / Math.max(1,cover.offsetHeight)));
      cover.style.setProperty("--page-turn", (progress*9).toFixed(2)+"deg");
      cover.style.setProperty("--page-lift", (progress*-20).toFixed(1)+"px");
    }
    // A word is faint only while it sits in the bottom quarter of the screen; anything a reader is looking at is full ink.
    const atEnd = y >= max - 4, line = vh * .75;
    for (const f of fills) {
      if (!f.el.isConnected) continue;
      const tops = f.words.map(w => w.getBoundingClientRect().top);   // read all positions first, then write classes
      f.words.forEach((w, i) => w.classList.toggle("lit", atEnd || tops[i] < line));
    }
    for (const [el, k] of parallax) {
      if (!el.isConnected) continue;
      const r = el.getBoundingClientRect();
      el.style.transform = `translate3d(0, ${((r.top + r.height / 2) - vh / 2) * k}px, 0)`;
    }
  }
  let ticking = false;
  const queue = () => { if (!ticking) { ticking = true; requestAnimationFrame(() => { ticking = false; onScroll(); }); } };
  addEventListener("scroll", queue, { passive: true });
  addEventListener("resize", () => { queue(); navInk(); chromeHeight(); });

  function chromeHeight() {
    const c = document.getElementById("chrome");
    if (c) document.documentElement.style.setProperty("--chrome-h", c.offsetHeight + "px");
    const t = document.getElementById("top");
    if (t) document.documentElement.style.setProperty("--top-h", t.offsetHeight + "px");
  }

  /* The thick rule under the nav slides to the active section. On appendix pages the Appendices label is marked instead (CSS). */
  function navInk() {
    const ink = document.getElementById("navink"), strip = document.getElementById("navscroll"); if (!ink || !strip) return;
    const on = strip.querySelector(".nav.on");
    if (on) {
      const pad = parseFloat(getComputedStyle(on).paddingLeft) || 0;
      ink.style.width = `${on.offsetWidth - pad * 2}px`;
      ink.style.transform = `translateX(${on.offsetLeft + pad}px)`;
      ink.style.opacity = 1;
      // keep the active section visible inside the strip (horizontal only, never moves the page)
      const left = on.offsetLeft, right = left + on.offsetWidth;
      if (left < strip.scrollLeft || right > strip.scrollLeft + strip.clientWidth)
        strip.scrollTo({ left: Math.max(0, left - 24), behavior: reduced() ? "auto" : "smooth" });
    } else ink.style.opacity = 0;
    navEdges();
  }
  /* Fade the strip's edges when more sections are hidden off to the side. */
  function navEdges() {
    const strip = document.getElementById("navscroll"); if (!strip) return;
    strip.classList.toggle("more-left", strip.scrollLeft > 2);
    strip.classList.toggle("more-right", strip.scrollLeft + strip.clientWidth < strip.scrollWidth - 2);
  }
  document.addEventListener("scroll", e => { if (e.target.id === "navscroll") navEdges(); }, true);

  function after(view) {
    clearPointer();
    visibleFolios.disconnect();
    for (const folio of view.querySelectorAll(".folio")) visibleFolios.observe(folio);
    cover = view.querySelector(".cover.spread");
    chromeHeight(); navInk();
    if (reduced()) { onScroll(); return; }
    headline(view);
    fillText(view);
    parallax = [...view.querySelectorAll("[data-parallax]")].map(el => [el, +el.dataset.parallax]);
    reveal(view);
    onScroll();
  }

  return { after, navInk, splitWords, countUp, reduced, onScroll: queue };
})();
