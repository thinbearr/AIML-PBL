/* World coordinates depend only on inventory order and exposure. Budget solves
   update ink on the same SVG nodes, leaving position, selection and focus intact. */
function mountRiskMap(svg, hosts, onInspect) {
  const layers = [
    {id:"internet", inner:.78, outer:1, height:0},
    {id:"dmz", inner:.51, outer:.78, height:28},
    {id:"internal", inner:0, outer:.51, height:57}
  ];
  let yaw = -.19, after = 100, selected = null, drag = null, pendingFrame = 0;
  const enabled = new Set(layers.map(l => l.id));
  const scale = Math.max(...hosts.map(h => h.initial), .001);
  const entries = new Map();
  const contours = [], grid = S("g",{"aria-hidden":"true"},svg);
  const links = S("g",{"aria-hidden":"true",class:"map-links"},svg);
  const dots = S("g",{},svg);
  const seam = S("line",{y1:0,y2:418,class:"map-seam","pointer-events":"none"},svg);
  function world(r,a,z) {
    const radius=r*(1+.045*Math.sin(a*3)+.025*Math.cos(a*4));
    return {x:Math.cos(a)*radius*362,y:Math.sin(a)*radius*235,z};
  }
  function project(p) {
    const c=Math.cos(yaw),s=Math.sin(yaw);
    return [425+p.x*c-p.y*s,244+(p.x*s+p.y*c)*.56-p.z];
  }
  for(const layer of layers) {
    for(let j=0;j<4;j++) {
      const r=layer.outer-(layer.outer-layer.inner)*j/4;
      const points=Array.from({length:100},(_,i)=>world(r,2*Math.PI*i/100,layer.height));
      const shape=S("polygon",{class:j ? "map-contour" : "map-shelf", "data-tier":layer.id},grid);
      contours.push({shape,points});
    }
    const members=hosts.filter(h=>h.exposure===layer.id);
    members.forEach((h,i)=>{
      const r=Math.sqrt(layer.inner**2+(layer.outer**2-layer.inner**2)*(i+.5)/members.length);
      const group=S("g",{class:"risk-host",role:"button",tabindex:-1,"data-id":h.i},dots);
      S("circle",{r:12,fill:"transparent"},group);
      S("circle",{class:"change-ring",r:7,fill:"none"},group);
      S("circle",{class:"host-outline",r:8,fill:"none"},group);
      const face=S("circle",{class:"host-face",r:2.9+h.crit*.6},group);
      S("path",{class:"patch-tick",d:"M-3 0l2 2 4-5",fill:"none"},group);
      const entry={h,group,face,point:world(r,i*2.39996,layer.height),sx:0,sy:0};
      entries.set(h.i,entry);
      group.onclick=()=>onInspect(entry.h,group);
      group.onkeydown=e=>{
        if(e.key==="Enter" || e.key===" ") {e.preventDefault();onInspect(entry.h,group);}
      };
      group.onpointermove=e=>{
        if(e.pointerType==="mouse") TT.show(`<b>${esc(entry.h.host)}</b><br>Before ${nf(entry.h.initial,2)} · After ${nf(entry.h.residual,2)}`,e.clientX,e.clientY);
      };
      group.onpointerleave=()=>TT.hide();
    });
  }
  function colour(e) {
    const patchedSide=after===100 || (after>0 && e.sx<=850*after/100);
    const risk=patchedSide?e.h.residual:e.h.initial;
    const strength=Math.sqrt(Math.min(1,Math.max(0,risk/scale)));
    const low=[107,169,155], high=[255,108,65];
    e.face.setAttribute("fill",`rgb(${low.map((v,i)=>Math.round(v+(high[i]-v)*strength)).join(",")})`);
    e.group.classList.toggle("has-patch",patchedSide && e.h.patched);
  }
  function connections() {
    links.replaceChildren();
    const central=entries.get(selected);
    if(!central || !enabled.has(central.h.exposure)) return;
    for(const e of entries.values()) {
      if(enabled.has(e.h.exposure) && (e.h.parent===selected || central.h.parent===e.h.i))
        S("line",{x1:central.sx,y1:central.sy,x2:e.sx,y2:e.sy},links);
    }
  }
  function layout() {
    for(const {shape,points} of contours)
      shape.setAttribute("points",points.map(p=>project(p).map(n=>n.toFixed(1)).join(",")).join(" "));
    for(const e of entries.values()) {
      [e.sx,e.sy]=project(e.point);
      e.group.setAttribute("transform",`translate(${e.sx.toFixed(1)} ${e.sy.toFixed(1)})`);
      colour(e);
    }
    connections();
  }
  function rotate(angle) { yaw+=angle;layout(); }
  svg.onpointerdown=e=>{
    if(e.button!==0 || e.target.closest(".risk-host")) return;
    drag={id:e.pointerId,x:e.clientX,yaw};svg.setPointerCapture(e.pointerId);
  };
  svg.onpointermove=e=>{
    if(drag?.id!==e.pointerId) return;
    yaw=drag.yaw+(e.clientX-drag.x)/Math.max(1,svg.clientWidth)*2.5;
    if(!pendingFrame) pendingFrame=requestAnimationFrame(()=>{pendingFrame=0;if(svg.isConnected) layout();});
  };
  svg.onlostpointercapture=()=>{drag=null;};
  svg.onkeydown=e=>{
    if(["ArrowLeft","ArrowRight"].includes(e.key)) {e.preventDefault();rotate(e.key==="ArrowLeft"?-.18:.18);}
  };
  function scrub(value) {
    after=value;
    const x=850*value/100;
    seam.setAttribute("x1",x);seam.setAttribute("x2",x);
    seam.style.display=value===0 || value===100?"none":"";
    for(const e of entries.values()) colour(e);
  }
  function select(id) {
    selected=id;
    for(const e of entries.values()) {
      e.group.classList.toggle("selected",e.h.i===id);
      e.group.setAttribute("tabindex",e.h.i===id?0:-1);
    }
    connections();
  }
  function update(next,newHosts=new Set()) {
    for(const h of next) {
      const e=entries.get(h.i);
      e.h=h; colour(e);
      e.group.setAttribute("aria-label",`Inspect ${h.host}, ${h.exposure}. Risk before ${nf(h.initial,2)}, after ${nf(h.residual,2)}.`);
      if(newHosts.has(h.i) && enabled.has(h.exposure) && !Motion.reduced())
        e.group.querySelector(".change-ring").animate([{r:"7px",opacity:1},{r:"17px",opacity:0}],{duration:1050});
    }
  }
  layout();scrub(100);update(hosts);
  return {rotate,scrub,select,update,marker:id=>entries.get(id)?.group,
    position:id=>{const e=entries.get(id);return e && e.group.style.display!=="none" ? [e.sx,e.sy] : null;},
    filter(tiers) {
      enabled.clear();tiers.forEach(t=>enabled.add(t));
      for(const e of entries.values()) e.group.style.display=enabled.has(e.h.exposure)?"":"none";
      contours.forEach(({shape})=>shape.style.opacity=enabled.has(shape.dataset.tier)?"1":".18");
      connections();
    }
  };
}
