/* Tiny dependency-free chart helpers (offline). */
const SVGNS = "http://www.w3.org/2000/svg";
function S(tag, attrs, parent) {
  const e = document.createElementNS(SVGNS, tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  if (parent) parent.appendChild(e);
  return e;
}
const TT = {
  el: null,
  show(html, x, y) {
    if (!this.el) { this.el = document.createElement("div"); this.el.id = "tt"; document.body.appendChild(this.el); }
    this.el.innerHTML = html; this.el.style.opacity = 1;
    const w = this.el.offsetWidth, h = this.el.offsetHeight;
    this.el.style.left = Math.min(x + 16, innerWidth - w - 10) + "px";
    this.el.style.top = Math.min(Math.max(y - h - 10, 8), innerHeight - h - 8) + "px";
  },
  hide() { if (this.el) this.el.style.opacity = 0; },
};
function niceMax(v) {
  if (!(v > 0)) return 1;
  const e = Math.pow(10, Math.floor(Math.log10(v))), m = v / e;
  return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10) * e;
}
const nf = (v, d = 0) => (Number.isFinite(+v) ? (+v).toLocaleString("en-US", { minimumFractionDigits: d, maximumFractionDigits: d }) : "–");

/* o: {series:[{name,color,pts:[[x,y]],dash,dots,width}], xlabel,ylabel,xmax,ymax,xfmt,yfmt,height,marks:[{x,y,label,color}],hlines:[{y,label,color}]} */
function LineChart(host, o) {
  host.innerHTML = "";
  const W = 640, H = o.height || 300, m = { l: 54, r: 16, t: 14, b: 40 };
  const hidden = host._hidden || (host._hidden = new Set());
  const vis = () => o.series.filter(s => !hidden.has(s.name));
  const all = o.series.flatMap(s => s.pts);
  const X1 = o.xmax ?? niceMax(Math.max(...all.map(p => p[0]))), X0 = o.xmin ?? 0;
  const Y1 = o.ymax ?? niceMax(Math.max(...all.map(p => p[1]), ...(o.hlines || []).map(h => h.y)) * 1.04), Y0 = o.ymin ?? 0;
  const sx = v => m.l + (v - X0) / (X1 - X0) * (W - m.l - m.r), sy = v => H - m.b - (v - Y0) / (Y1 - Y0) * (H - m.t - m.b);
  const xf = o.xfmt || (v => nf(v, X1 <= 10 ? 1 : 0)), yf = o.yfmt || (v => nf(v, Y1 <= 5 ? 2 : Y1 <= 50 ? 1 : 0));
  const svg = S("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", style: "display:block;overflow:visible" }, host);
  for (let i = 0; i <= 4; i++) {
    const yv = Y0 + (Y1 - Y0) * i / 4, xv = X0 + (X1 - X0) * i / 4;
    S("line", { x1: m.l, x2: W - m.r, y1: sy(yv), y2: sy(yv), class: i ? "ax" : "axl" }, svg);
    S("text", { x: m.l - 8, y: sy(yv) + 4, "text-anchor": "end" }, svg).textContent = yf(yv);
    S("text", { x: sx(xv), y: H - m.b + 16, "text-anchor": "middle" }, svg).textContent = xf(xv);
  }
  if (o.xlabel) S("text", { x: (W + m.l) / 2, y: H - 6, "text-anchor": "middle" }, svg).textContent = o.xlabel;
  if (o.ylabel) S("text", { x: 13, y: H / 2, "text-anchor": "middle", transform: `rotate(-90 13 ${H / 2})` }, svg).textContent = o.ylabel;
  for (const hl of o.hlines || []) {
    S("line", { x1: m.l, x2: W - m.r, y1: sy(hl.y), y2: sy(hl.y), stroke: hl.color || "var(--acc2)", "stroke-dasharray": "5 4", "stroke-width": 1.5 }, svg);
    S("text", { x: W - m.r - 4, y: sy(hl.y) - 5, "text-anchor": "end", style: `fill:${hl.color || "var(--acc2)"}` }, svg).textContent = hl.label;
  }
  for (const s of vis()) {
    const pts = s.pts.filter(p => p[0] <= X1);
    if (s.fill) S("polygon", { points: `${sx(pts[0][0])},${sy(0)} ` + pts.map(p => sx(p[0]) + "," + sy(p[1])).join(" ") + ` ${sx(pts.at(-1)[0])},${sy(0)}`, fill: s.color, opacity: .1 }, svg);
    S("polyline", { fill: "none", stroke: s.color, "stroke-width": s.width || 2.2, "stroke-linejoin": "round", "stroke-linecap": "round", "stroke-dasharray": s.dash || "", points: pts.map(p => sx(p[0]) + "," + sy(p[1])).join(" ") }, svg);
    if (s.dots) pts.forEach(p => S("circle", { cx: sx(p[0]), cy: sy(p[1]), r: 3, fill: s.color }, svg));
  }
  for (const mk of o.marks || []) {
    S("circle", { cx: sx(mk.x), cy: sy(mk.y), r: 6.5, fill: mk.color || "var(--acc2)", stroke: "var(--surface)", "stroke-width": 2 }, svg);
    S("text", { x: sx(mk.x) + 10, y: sy(mk.y) - 9, style: `fill:${mk.color || "var(--acc2)"};font-weight:600` }, svg).textContent = mk.label;
  }
  const cross = S("line", { y1: m.t, y2: H - m.b, stroke: "var(--ink2)", "stroke-width": 1, opacity: 0 }, svg);
  const dots = vis().map(s => S("circle", { r: 4.5, fill: s.color, stroke: "var(--surface)", "stroke-width": 2, opacity: 0 }, svg));
  const ov = S("rect", { x: m.l, y: m.t, width: W - m.l - m.r, height: H - m.t - m.b, fill: "transparent" }, svg);
  const xs = [...new Set(vis().flatMap(s => s.pts.map(p => p[0])))].sort((a, b) => a - b);
  ov.addEventListener("mousemove", ev => {
    const r = svg.getBoundingClientRect(), px = (ev.clientX - r.left) / r.width * W;
    const xv = X0 + (px - m.l) / (W - m.l - m.r) * (X1 - X0);
    const near = xs.reduce((a, b) => Math.abs(b - xv) < Math.abs(a - xv) ? b : a, xs[0]);
    cross.setAttribute("x1", sx(near)); cross.setAttribute("x2", sx(near)); cross.setAttribute("opacity", .5);
    let rows = "";
    vis().forEach((s, i) => {
      const p = s.pts.find(q => q[0] === near);
      if (p) { dots[i].setAttribute("cx", sx(p[0])); dots[i].setAttribute("cy", sy(p[1])); dots[i].setAttribute("opacity", 1);
        rows += `<div class="r"><span style="color:${s.color}">●</span><span>${s.name}</span><b>${yf(p[1])}</b></div>`; }
      else dots[i].setAttribute("opacity", 0);
    });
    TT.show(`<b>${o.xlabel ? o.xlabel.split("(")[0].trim() + ": " : ""}${xf(near)}</b>${rows}`, ev.clientX, ev.clientY);
  });
  ov.addEventListener("mouseleave", () => { cross.setAttribute("opacity", 0); dots.forEach(d => d.setAttribute("opacity", 0)); TT.hide(); });
  if (o.legend !== false && o.series.length > 1) {
    const lg = document.createElement("div"); lg.className = "legend"; host.appendChild(lg);
    o.series.forEach(s => {
      const sp = document.createElement("span"); sp.className = hidden.has(s.name) ? "off" : "";
      sp.innerHTML = `<i style="background:${s.color}"></i>${s.name}`;
      sp.onclick = () => { hidden.has(s.name) ? hidden.delete(s.name) : hidden.add(s.name); LineChart(host, o); };
      lg.appendChild(sp);
    });
  }
}

/* horizontal bars: rows [{label,value,color,err,hi,note}] */
function BarChart(host, o) {
  const max = o.max ?? niceMax(Math.max(...o.rows.map(r => (r.value || 0) + (r.err || 0))) * 1.02);
  host.innerHTML = o.rows.map(r => {
    const w = Math.max(0, Math.min(100, (r.value || 0) / max * 100));
    const err = r.err ? `<div class="e" style="left:${Math.max(0, (r.value - r.err) / max * 100)}%;width:${Math.min(100, 2 * r.err / max * 100)}%"></div>` : "";
    return `<div class="hb ${r.hi ? "hi" : ""}" title="${r.note || ""}"><div class="nm">${r.label}</div><div class="t"><div class="f" style="width:${w}%;background:${r.color || "var(--acc)"}"></div>${err}</div><div class="vv">${(o.fmt || (v => nf(v, 1)))(r.value)}${r.err ? ` <span class="mut">±${nf(r.err, 1)}</span>` : ""}</div></div>`;
  }).join("");
}

/* vertical columns: cols [{label,value,color,note}] */
function ColChart(host, o) {
  host.innerHTML = "";
  const W = 560, H = o.height || 240, m = { l: 44, r: 8, t: 12, b: 38 };
  const Y1 = o.ymax ?? niceMax(Math.max(...o.cols.map(c => c.value)) * 1.1);
  const svg = S("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", style: "display:block" }, host);
  const sy = v => H - m.b - v / Y1 * (H - m.t - m.b), bw = (W - m.l - m.r) / o.cols.length;
  for (let i = 0; i <= 4; i++) {
    const v = Y1 * i / 4; S("line", { x1: m.l, x2: W - m.r, y1: sy(v), y2: sy(v), class: i ? "ax" : "axl" }, svg);
    S("text", { x: m.l - 6, y: sy(v) + 4, "text-anchor": "end" }, svg).textContent = (o.yfmt || (x => nf(x, Y1 <= 10 ? 1 : 0)))(v);
  }
  o.cols.forEach((c, i) => {
    const x = m.l + i * bw + bw * .18, w = bw * .64;
    const r = S("rect", { x, y: sy(c.value), width: w, height: Math.max(1, H - m.b - sy(c.value)), rx: 5, fill: c.color || "var(--acc)" }, svg);
    S("text", { x: x + w / 2, y: sy(c.value) - 6, "text-anchor": "middle", style: "fill:var(--ink2);font-weight:600" }, svg).textContent = (o.vfmt || (x => nf(x, 1)))(c.value);
    S("text", { x: x + w / 2, y: H - m.b + 16, "text-anchor": "middle" }, svg).textContent = c.label;
    r.addEventListener("mousemove", ev => TT.show(`<b>${c.label}</b><br>${c.note || ""}`, ev.clientX, ev.clientY));
    r.addEventListener("mouseleave", () => TT.hide());
  });
  if (o.ylabel) S("text", { x: 11, y: H / 2, "text-anchor": "middle", transform: `rotate(-90 11 ${H / 2})` }, svg).textContent = o.ylabel;
}

/* ring gauge */
function Ring(host, value, max, label, color) {
  const R = 46, C = 2 * Math.PI * R, f = Math.max(0, Math.min(1, value / max));
  host.innerHTML = `<svg viewBox="0 0 120 120" width="112"><circle cx="60" cy="60" r="${R}" fill="none" stroke="var(--bg2)" stroke-width="11"/>
  <circle cx="60" cy="60" r="${R}" fill="none" stroke="${color || "var(--acc)"}" stroke-width="11" stroke-linecap="round" stroke-dasharray="${C * f} ${C}" transform="rotate(-90 60 60)" style="transition:stroke-dasharray .7s"/>
  <text x="60" y="58" text-anchor="middle" style="font:500 20px var(--mono);fill:var(--ink)">${label}</text></svg>`;
}
