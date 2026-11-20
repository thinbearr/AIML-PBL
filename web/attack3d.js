/* 3D towers: the same hosts as the atlas, stacked by exposure tier. Tower height and colour show
   modelled risk; the before/after slider morphs heights; parent links are drawn as arcs between tiers.
   Loaded on demand (ES module) from breach.js. Three.js r170 is vendored in /vendor for offline use. */
import * as THREE from "/vendor/three.module.min.js";

const INK = 0xd6e2d1, PLATE = 0x1d3a33, PLATE_EDGE = 0x73877c, LINK = 0x9fb5a8, BAD = 0xff6c41, GOOD = 0x95d6bf;
const LOW = [107, 169, 155], HIGH = [255, 108, 65];
const TIERS = [{id: "internet", y: 4.2, name: "INTERNET"}, {id: "dmz", y: 2.1, name: "DMZ"}, {id: "internal", y: 0, name: "INTERNAL"}];
const W = 10, D = 5.4;

function hash(i) {
  let x = Math.imul(i + 1, 2654435761) >>> 0;
  x ^= x >>> 15; x = Math.imul(x, 2246822507) >>> 0; x ^= x >>> 13;
  return (x >>> 0) / 4294967296;
}
function label(text) {
  const c = document.createElement("canvas");
  c.width = 256; c.height = 64;
  const g = c.getContext("2d");
  g.font = "600 30px 'IBM Plex Mono', Consolas, monospace";
  g.fillStyle = "#d6e2d1"; g.textBaseline = "middle";
  g.fillText(text, 4, 34);
  const texture = new THREE.CanvasTexture(c);
  texture.colorSpace = THREE.SRGBColorSpace;
  const sprite = new THREE.Sprite(new THREE.SpriteMaterial({map: texture, transparent: true, depthWrite: false}));
  sprite.scale.set(2, .5, 1);
  sprite.center.set(0, .5);
  return sprite;
}

export function mountTowers(stage, hosts, opts) {
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
  const canvas = document.createElement("canvas");
  canvas.className = "attack-3d";
  canvas.tabIndex = 0;
  canvas.setAttribute("role", "group");
  canvas.setAttribute("aria-label", "3D tower view of host risk by exposure tier. Drag or use the arrow keys to orbit. Click a tower to inspect its host.");
  const hint = document.createElement("span");
  hint.className = "attack-3d-hint";
  hint.textContent = "Drag to orbit · click a tower to inspect";
  stage.append(canvas, hint);

  const renderer = new THREE.WebGLRenderer({canvas, antialias: true, alpha: true});
  renderer.setPixelRatio(Math.min(devicePixelRatio || 1, 2));
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(33, 850 / 418, .1, 200);
  scene.add(new THREE.HemisphereLight(0xf4efe0, 0x0b1c17, 2.1));
  const sun = new THREE.DirectionalLight(0xffffff, 1.7);
  sun.position.set(-6, 11, 8);
  scene.add(sun);

  /* tier plates */
  const plates = new Map();
  for (const t of TIERS) {
    const group = new THREE.Group();
    const slab = new THREE.Mesh(new THREE.BoxGeometry(W, .08, D), new THREE.MeshLambertMaterial({color: PLATE, transparent: true, opacity: .9}));
    slab.position.y = t.y - .04;
    const edges = new THREE.LineSegments(new THREE.EdgesGeometry(slab.geometry), new THREE.LineBasicMaterial({color: PLATE_EDGE}));
    edges.position.copy(slab.position);
    const pts = [];
    for (let x = -W / 2 + .5; x < W / 2; x += .5) pts.push(x, t.y + .002, -D / 2, x, t.y + .002, D / 2);
    for (let z = -D / 2 + .5; z < D / 2; z += .5) pts.push(-W / 2, t.y + .002, z, W / 2, t.y + .002, z);
    const gridGeometry = new THREE.BufferGeometry();
    gridGeometry.setAttribute("position", new THREE.Float32BufferAttribute(pts, 3));
    const grid = new THREE.LineSegments(gridGeometry, new THREE.LineBasicMaterial({color: PLATE_EDGE, transparent: true, opacity: .22}));
    const name = label(t.name);
    name.position.set(-W / 2 - .1, t.y + .35, D / 2 + .2);
    group.add(slab, edges, grid, name);
    scene.add(group);
    plates.set(t.id, group);
  }

  /* towers: one instanced mesh for the faces, one back-face hull for the ink outline */
  const box = new THREE.BoxGeometry(1, 1, 1).translate(0, .5, 0);
  const towers = new THREE.InstancedMesh(box, new THREE.MeshLambertMaterial({color: 0xffffff}), hosts.length);
  const hull = new THREE.InstancedMesh(box, new THREE.MeshBasicMaterial({color: 0xffffff, side: THREE.BackSide}), hosts.length);
  scene.add(hull, towers);
  const scale = Math.max(...hosts.map(h => h.initial), 1e-3);
  const tierY = Object.fromEntries(TIERS.map(t => [t.id, t.y]));
  const state = hosts.map((h, k) => ({
    h, k, x: (h.x - .5) * (W - .9), z: (hash(h.i) - .5) * (D - .9), y: tierY[h.exposure] ?? 0,
    w: .11 + h.crit * .028, height: .06, target: .06
  }));
  const byId = new Map(state.map(s => [s.h.i, s]));
  let wipe = opts.wipe ?? 100, tiers = opts.tiers ? new Set(opts.tiers) : new Set(TIERS.map(t => t.id)), selected = opts.selected ?? null;
  const breached = new Set();
  const visible = s => tiers.has(s.h.exposure);

  const m = new THREE.Matrix4(), q = new THREE.Quaternion(), v = new THREE.Vector3(), sc = new THREE.Vector3(), color = new THREE.Color();
  function risk(h) { const t = wipe / 100; return h.initial + (h.residual - h.initial) * t; }
  function targets() { for (const s of state) s.target = .06 + 1.05 * Math.sqrt(Math.min(1, risk(s.h) / scale)); }
  function paint() {
    for (const s of state) {
      const on = visible(s);
      v.set(s.x, s.y, s.z); sc.set(on ? s.w : 0, on ? s.height : 0, on ? s.w : 0);
      towers.setMatrixAt(s.k, m.compose(v, q, sc));
      v.set(s.x, s.y - .02, s.z); sc.set(on ? s.w + .045 : 0, on ? s.height + .04 : 0, on ? s.w + .045 : 0);
      hull.setMatrixAt(s.k, m.compose(v, q, sc));
      if (breached.has(s.h.i)) color.setHex(BAD);
      else {
        const f = Math.sqrt(Math.min(1, Math.max(0, risk(s.h) / scale)));
        color.setRGB(...LOW.map((c, i) => (c + (HIGH[i] - c) * f) / 255), THREE.SRGBColorSpace);
      }
      towers.setColorAt(s.k, color);
      color.setHex(breached.has(s.h.i) ? BAD : s.h.patched && wipe >= 50 ? GOOD : 0x0c1a16);
      hull.setColorAt(s.k, color);
    }
    towers.instanceMatrix.needsUpdate = hull.instanceMatrix.needsUpdate = true;
    towers.instanceColor.needsUpdate = hull.instanceColor.needsUpdate = true;
  }
  const top = s => new THREE.Vector3(s.x, s.y + s.height, s.z);

  /* parent links as arcs between tiers */
  const linkMaterial = new THREE.LineBasicMaterial({color: LINK, transparent: true, opacity: .32});
  const focusMaterial = new THREE.LineBasicMaterial({color: INK, transparent: true, opacity: .95});
  let links = null, focus = null;
  function arc(a, b, out, lift = .45) {
    const curve = new THREE.QuadraticBezierCurve3(a, new THREE.Vector3((a.x + b.x) / 2, Math.max(a.y, b.y) + lift, (a.z + b.z) / 2), b);
    const p = curve.getPoints(12);
    for (let i = 0; i < p.length - 1; i++) out.push(p[i].x, p[i].y, p[i].z, p[i + 1].x, p[i + 1].y, p[i + 1].z);
  }
  function segments(filter, material) {
    const pts = [];
    for (const s of state) {
      const parent = byId.get(s.h.parent);
      if (!parent || !visible(s) || !visible(parent) || !filter(s, parent)) continue;
      arc(new THREE.Vector3(parent.x, parent.y + .01, parent.z), new THREE.Vector3(s.x, s.y + .01, s.z), pts);
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.Float32BufferAttribute(pts, 3));
    return new THREE.LineSegments(g, material);
  }
  function rebuildLinks() {
    if (links) { scene.remove(links); links.geometry.dispose(); }
    links = segments(() => true, linkMaterial);
    scene.add(links);
    rebuildFocus();
  }
  const ring = new THREE.Mesh(new THREE.RingGeometry(.2, .27, 40), new THREE.MeshBasicMaterial({color: INK, side: THREE.DoubleSide}));
  ring.rotation.x = -Math.PI / 2;
  scene.add(ring);
  function rebuildFocus() {
    if (focus) { scene.remove(focus); focus.geometry.dispose(); }
    focus = segments((s, parent) => s.h.i === selected || parent.h.i === selected, focusMaterial);
    scene.add(focus);
  }

  /* breach sparks */
  const sparks = new THREE.InstancedMesh(new THREE.SphereGeometry(.07, 12, 8), new THREE.MeshBasicMaterial({color: 0xffffff}), hosts.length + 4);
  const glow = new THREE.InstancedMesh(new THREE.SphereGeometry(.17, 12, 8), new THREE.MeshBasicMaterial({color: BAD, transparent: true, opacity: .28, depthWrite: false}), hosts.length + 4);
  sparks.count = glow.count = 0;
  scene.add(sparks, glow);

  /* camera orbit */
  let yaw = -.5, pitch = .4, radius = 18, drag = null, idleSince = performance.now(), frame = 0, shown = false, onScreen = true;
  const target = new THREE.Vector3(0, 2.3, 0);
  function placeCamera() {
    camera.position.set(target.x + radius * Math.cos(pitch) * Math.sin(yaw), target.y + radius * Math.sin(pitch), target.z + radius * Math.cos(pitch) * Math.cos(yaw));
    camera.lookAt(target);
  }
  function resize() {
    const width = canvas.clientWidth || stage.clientWidth;
    if (!width) return;
    const height = Math.round(width * 418 / 850);
    renderer.setSize(width, height, false);
    camera.aspect = width / height;
    radius = width < 560 ? 22 : 18;
    camera.updateProjectionMatrix();
  }
  const resizer = new ResizeObserver(resize);
  resizer.observe(stage);
  const watcher = new IntersectionObserver(e => { onScreen = e[0].isIntersecting; start(); });
  watcher.observe(canvas);

  const raycaster = new THREE.Raycaster(), ndc = new THREE.Vector2();
  function pick(e) {
    const r = canvas.getBoundingClientRect();
    ndc.set((e.clientX - r.left) / r.width * 2 - 1, -(e.clientY - r.top) / r.height * 2 + 1);
    raycaster.setFromCamera(ndc, camera);
    const hit = raycaster.intersectObject(towers).find(x => visible(state[x.instanceId]));
    return hit ? state[hit.instanceId] : null;
  }
  canvas.addEventListener("pointerdown", e => {
    if (e.button !== 0) return;
    drag = {id: e.pointerId, x: e.clientX, y: e.clientY, yaw, pitch, moved: 0};
    canvas.setPointerCapture(e.pointerId);
  });
  canvas.addEventListener("pointermove", e => {
    idleSince = performance.now();
    if (drag?.id === e.pointerId) {
      drag.moved = Math.max(drag.moved, Math.abs(e.clientX - drag.x) + Math.abs(e.clientY - drag.y));
      yaw = drag.yaw - (e.clientX - drag.x) * .008;
      pitch = Math.max(.12, Math.min(1.35, drag.pitch + (e.clientY - drag.y) * .006));
      TT.hide();
      return;
    }
    if (e.pointerType !== "mouse") return;
    const s = pick(e);
    canvas.style.cursor = s ? "pointer" : "";
    if (s) TT.show(`<b>${esc(s.h.host)}</b> · ${esc(s.h.exposure)}<br>Before ${nf(s.h.initial, 2)} · After ${nf(s.h.residual, 2)}`, e.clientX, e.clientY);
    else TT.hide();
  });
  canvas.addEventListener("pointerup", e => {
    if (drag?.id !== e.pointerId) return;
    const click = drag.moved < 5;
    drag = null;
    if (!click) return;
    const s = pick(e);
    if (s) opts.onInspect(s.h, canvas);
  });
  canvas.addEventListener("lostpointercapture", () => { drag = null; });
  canvas.addEventListener("pointerleave", () => TT.hide());
  canvas.addEventListener("keydown", e => {
    const turns = {ArrowLeft: [-.18, 0], ArrowRight: [.18, 0], ArrowUp: [0, .1], ArrowDown: [0, -.1]}[e.key];
    if (!turns) return;
    e.preventDefault();
    yaw += turns[0]; pitch = Math.max(.12, Math.min(1.35, pitch + turns[1])); idleSince = performance.now();
  });

  let last = performance.now();
  function loop(now) {
    frame = 0;
    if (!canvas.isConnected) { destroy(); return; }
    if (!shown || !onScreen || document.hidden) return;
    const dt = Math.min(.05, (now - last) / 1000); last = now;
    if (!reduced() && !drag && now - idleSince > 3500) yaw += dt * .09;
    for (const s of state) s.height = reduced() ? s.target : s.height + (s.target - s.height) * Math.min(1, dt * 7);
    paint();
    const sel = byId.get(selected);
    ring.visible = Boolean(sel && visible(sel));
    if (ring.visible) ring.position.copy(top(sel)).add(new THREE.Vector3(0, .02, 0));
    placeCamera();
    renderer.render(scene, camera);
    frame = requestAnimationFrame(loop);
  }
  function start() { if (!frame && shown && onScreen) { last = performance.now(); frame = requestAnimationFrame(loop); } }
  document.addEventListener("visibilitychange", start);
  function destroy() {
    cancelAnimationFrame(frame); frame = 0;
    resizer.disconnect(); watcher.disconnect();
    document.removeEventListener("visibilitychange", start);
    renderer.dispose();
  }

  targets(); rebuildLinks(); paint(); resize();

  /* breach replay renderer (same interface as the 2D overlay) */
  function frameBreach(run, t) {
    let n = 0;
    for (const e of run.events) {
      if (t < e.t0) continue;
      const end = byId.get(e.to);
      if (!end || !visible(end)) continue;
      const from = e.from === null ? null : byId.get(e.from);
      if (e.from !== null && (!from || !visible(from))) continue;
      const b = top(end), a = from ? top(from) : new THREE.Vector3(end.x + .6, end.y + 2.4, end.z);
      const f = Math.min(1, (t - e.t0) / (e.t1 - e.t0)), k = Math.min(f, e.ok ? 1 : .72);
      if (f < 1 || (!e.ok && t - e.t1 < .6)) {
        v.lerpVectors(a, b, k); v.y += Math.sin(Math.PI * k) * .7;
        const size = f < 1 ? 1 : 1 - (t - e.t1) / .6;
        sc.setScalar(size);
        sparks.setMatrixAt(n, m.compose(v, q, sc)); glow.setMatrixAt(n, m);
        sparks.setColorAt(n, color.setHex(f < 1 ? 0xffd2bf : GOOD));
        n++;
      }
      if (e.ok && f >= 1) breached.add(e.to);
    }
    sparks.count = glow.count = n;
    sparks.instanceMatrix.needsUpdate = glow.instanceMatrix.needsUpdate = true;
    if (sparks.instanceColor) sparks.instanceColor.needsUpdate = true;
  }

  return {
    canvas,
    show(on) {
      shown = on;
      canvas.style.display = hint.style.display = on ? "" : "none";
      if (on) { resize(); start(); canvas.focus({preventScroll: true}); } else TT.hide();
    },
    rotate(angle) { yaw += angle; idleSince = performance.now(); },
    scrub(value) { wipe = value; targets(); },
    select(id) { selected = id; rebuildFocus(); },
    update(next) { for (const h of next) { const s = byId.get(h.i); if (s) s.h = h; } targets(); },
    filter(next) {
      tiers = new Set(next);
      for (const [id, group] of plates) group.visible = tiers.has(id);
      rebuildLinks();
    },
    frame: frameBreach,
    settle(run) { breached.clear(); for (const id of run.reached) breached.add(id); sparks.count = glow.count = 0; },
    clearBreach() { breached.clear(); sparks.count = glow.count = 0; }
  };
}
