/* Motion layer: headline reveals, scroll reveals, scroll-linked text, reading progress, parallax, nav underline.
   Everything here is decoration. With prefers-reduced-motion the page renders fully and statically. */
window.Motion = (() => {
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
  const REVEAL = [".sectionhead .lede", ".sectionhead .definition", ".opening .lede", ".opening .plate", ".opening .btn", ".opening .textlink",
    ".scoreboard .stat", ".card", ".marginal", ".flow .step", ".view > h2", ".finding", ".callout", ".phase", ".footnotes", ".pagelinks",
    "#criteria li", ".rv-intro"].join(",");
  const FILL = ".finding, .callout, .marginal p, .scrolltext";
  let io, fills = [], parallax = [];

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
