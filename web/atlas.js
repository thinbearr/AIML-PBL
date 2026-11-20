/* Schematic relief, independent of the host-level risk graph. */
const ATLAS_TIERS = [
  {id:"internal", name:"Internal", x:-22, y:-12, dx:10, dy:-20},
  {id:"dmz", name:"DMZ", x:-103, y:36, dx:-36, dy:23},
  {id:"internet", name:"Internet", x:117, y:-29, dx:7, dy:-19}
];

function coverMap() {
  return `<figure class="atlas" aria-label="Interactive schematic of network exposure tiers">
    <figcaption><span class="plate-code">FIG. 01</span><strong>Exposure atlas</strong><span class="atlas-kind">Synthetic · schematic</span></figcaption>
    <div class="atlas-screen" tabindex="0" role="group" aria-label="Exposure relief. Drag horizontally or use the arrow keys to rotate.">
      <canvas aria-hidden="true" width="550" height="330"></canvas>
      <svg viewBox="0 0 550 330" role="group" aria-label="Select an exposure tier">
        ${ATLAS_TIERS.map(t => `<g class="atlas-pin" role="button" tabindex="0" data-tier="${t.id}" aria-label="Inspect ${t.name} exposure">
          <circle r="16" fill="transparent"/><circle class="locator" r="5.5"/><circle class="core" r="2.2"/>
          <g transform="translate(${t.dx} ${t.dy})"><rect x="-5" y="-11" width="${t.name.length*7.2+11}" height="17"/><text>${t.name.toUpperCase()}</text></g></g>`).join("")}
      </svg>
      <span class="orbit-hint" aria-hidden="true">↔ Drag to orbit</span>
      <button class="atlas-motion" type="button"></button>
    </div>
    <div class="atlas-controls" role="group" aria-label="Exposure tier">${ATLAS_TIERS.map(t => `<button type="button" data-tier="${t.id}">${t.name}</button>`).join("")}</div>
    <div class="atlas-reading" aria-live="polite"></div></figure>`;
}

// Sample a continuous height field once. Marching squares joins its level sets
// into closed paths so a higher slice can occlude the terrain behind it.
function atlasHeight(x,y) {
  const hill = (cx,cy,rx,ry) => Math.exp(-(((x-cx)/rx)**2 + ((y-cy)/ry)**2));
  const relief = 121*hill(-27,-10,63,47) + 89*hill(72,-43,55,39)
    + 66*hill(-100,31,47,40) + 69*hill(50,38,64,35) + 21*hill(0,0,165,93);
  return relief*(1 + .065*Math.sin(x*.057+y*.032) + .038*Math.cos(y*.11-x*.023));
}

let atlasSlices;
function reliefSlices() {
  if (atlasSlices) return atlasSlices;
  const cols=91, rows=57, step=6;
  const grid=Array.from({length:rows},(_,j)=>Array.from({length:cols},(_,i)=>{
    const x=(i-(cols-1)/2)*step, y=(j-(rows-1)/2)*step;
    return {x,y,z:atlasHeight(x,y)};
  }));
  atlasSlices=[];
  for (let z=5; z<=153; z+=3.5) {
    const edges=new Map();
    function connect(a,b) {
      if (!edges.has(a.key)) edges.set(a.key,{point:a,next:[]});
      edges.get(a.key).next.push(b.key);
    }
    for(let j=0;j<rows-1;j++) for(let i=0;i<cols-1;i++) {
      const cell=[grid[j][i],grid[j][i+1],grid[j+1][i+1],grid[j+1][i]], hits=[];
      for(let k=0;k<4;k++) {
        const a=cell[k], b=cell[(k+1)%4];
        if((a.z>=z)===(b.z>=z)) continue;
        const t=(z-a.z)/(b.z-a.z), x=a.x+t*(b.x-a.x), y=a.y+t*(b.y-a.y);
        hits.push({x,y,key:Math.round(x*1000)+","+Math.round(y*1000)});
      }
      for(let k=0;k+1<hits.length;k+=2) {connect(hits[k],hits[k+1]);connect(hits[k+1],hits[k]);}
    }
    const loops=[];
    for(const [start] of edges) {
      if(edges.get(start).seen) continue;
      const path=[]; let key=start;
      while(key!==undefined && !edges.get(key).seen) {
        const node=edges.get(key); node.seen=true; path.push(node.point);
        key=node.next.find(n=>!edges.get(n).seen);
      }
      if(path.length>2) loops.push(path);
    }
    if(loops.length) atlasSlices.push({z,loops});
  }
  return atlasSlices;
}

function bindAtlas(figure, weights) {
  const screen=figure.querySelector(".atlas-screen"), canvas=screen.querySelector("canvas");
  const ctx=canvas.getContext("2d"), toggle=screen.querySelector(".atlas-motion");
  const pins=[...screen.querySelectorAll(".atlas-pin")];
  const levels=reliefSlices(), preference=matchMedia("(prefers-reduced-motion: reduce)");
  let playing=!preference.matches, visible=true, clock=0, previous=0, frame=0;
  let yaw=-.2, orbit=-.2, pitch=.53, aimY=0, aimX=0, dragging=null, selected=2, lift=0;
  let pixelWidth=0, pixelHeight=0;
  const nodes=ATLAS_TIERS.map(t=>({...t,z:atlasHeight(t.x,t.y)}));
  function draw() {
    const w=screen.clientWidth, h=screen.clientHeight;
    if(!w || !h) return;
    const dpr=Math.min(devicePixelRatio || 1,2);
    if(pixelWidth!==Math.round(w*dpr) || pixelHeight!==Math.round(h*dpr)) {
      pixelWidth=canvas.width=Math.round(w*dpr); pixelHeight=canvas.height=Math.round(h*dpr);
    }
    const cs=Math.cos(yaw), sn=Math.sin(yaw);
    const arrival=playing && !preference.matches ? Math.min(1,.28+clock*.55) : 1;
    const stretch=(1+.045*Math.sin(clock*.8)+lift*.08)*(1-(1-arrival)**2);
    const project=(x,y,z)=>[275+(x*cs-y*sn)*1.025,213+(x*sn+y*cs)*pitch-z*stretch];
    if(ctx) {
      ctx.setTransform(pixelWidth/550,0,0,pixelHeight/330,0,0);
      ctx.clearRect(0,0,550,330);
      // Perspective grid establishes the ground plane as the relief turns.
      ctx.lineWidth=.65; ctx.strokeStyle="rgba(138,188,162,.22)"; ctx.beginPath();
      for(let i=-280;i<=280;i+=28) {
        ctx.moveTo(...project(-280,i,0));ctx.lineTo(...project(280,i,0));
        ctx.moveTo(...project(i,-210,0));ctx.lineTo(...project(i,210,0));
      }
      ctx.stroke();
      const scan=(clock*.19)%1;
      for(const {z,loops} of levels) {
        const t=z/154;
        const gleam=Math.exp(-((t-scan)**2)/.004);
        const band=selected===0 ? .83 : selected===1 ? .48 : .15;
        const accent=Math.exp(-((t-band)**2)/.018);
        ctx.fillStyle=`rgb(${20+Math.round(18*t)},${48+Math.round(38*t)},${43+Math.round(25*t)})`;
        ctx.strokeStyle=`rgba(${Math.round(104+95*t+48*accent+48*gleam)},${Math.round(168+33*t+19*accent+18*gleam)},${Math.round(150+25*t-35*accent-30*gleam)},${.73+.26*gleam})`;
        ctx.lineWidth=.9+1.25*gleam;
        for(const loop of loops) {
          ctx.beginPath();
          loop.forEach((p,i)=>{const x=275+(p.x*cs-p.y*sn)*1.025, y=213+(p.x*sn+p.y*cs)*pitch-z*stretch;
            if(i) ctx.lineTo(x,y); else ctx.moveTo(x,y);});
          ctx.closePath();ctx.fill();ctx.stroke();
        }
      }
    }
    nodes.forEach((n,i)=>{
      const [x,y]=project(n.x,n.y,n.z);
      pins[i].setAttribute("transform",`translate(${x.toFixed(2)} ${y.toFixed(2)})`);
      if(ctx && i===selected) {
        const pulse=(clock*.6)%1;
        ctx.beginPath();ctx.arc(x,y,8+15*pulse,0,Math.PI*2);
        ctx.strokeStyle=`rgba(255,177,122,${.8*(1-pulse)})`;ctx.lineWidth=1.4;ctx.stroke();
      }
    });
  }
  function tick(now) {
    frame=0;
    if(!figure.isConnected || !visible || document.hidden) { previous=0;return; }
    const dt=previous?Math.min(.05,(now-previous)/1000):1/60;previous=now;
    if(playing) clock+=dt;
    const smooth=preference.matches?1:1-Math.exp(-8*dt);
    const target=orbit+aimX*.38+clock*.10;
    yaw+=(target-yaw)*smooth;
    const targetPitch=.52+aimY*.16+.035*Math.sin(clock*.42);
    pitch+=(targetPitch-pitch)*smooth;
    lift+=((2-selected)*.5-lift)*smooth;
    draw();
    if(playing || Math.abs(target-yaw)+Math.abs(targetPitch-pitch)+Math.abs((2-selected)*.5-lift)>.002) schedule();
    else previous=0;
  }
  function schedule() { if(!frame && visible && !document.hidden) frame=requestAnimationFrame(tick); }
  function motionLabel() {
    toggle.textContent=playing?"Ⅱ  Pause":"▷  Play";
    toggle.setAttribute("aria-label",playing?"Pause atlas motion":"Play atlas motion");
  }
  toggle.onclick=()=>{ playing=!playing;motionLabel();schedule(); };
  function select(id) {
    selected=ATLAS_TIERS.findIndex(t=>t.id===id);
    const tier=ATLAS_TIERS[selected];
    figure.dataset.active=id;
    figure.querySelectorAll("[data-tier]").forEach(el=>el.setAttribute("aria-pressed",el.dataset.tier===id));
    figure.querySelector(".atlas-reading").innerHTML=`<span>${tier.name} exposure weight</span><b>${nf(weights[id],1)}×</b><a href="#/network?tier=${id}" aria-label="Inspect ${tier.name} hosts">Inspect hosts</a>`;
    schedule();
  }
  figure.querySelectorAll("[data-tier]").forEach(el=>{
    el.onclick=()=>select(el.dataset.tier);
    if(el.matches("g")) el.onkeydown=e=>{if(["Enter"," "].includes(e.key)){e.preventDefault();select(el.dataset.tier);}};
  });
  screen.onpointerdown=e=>{
    if(e.target.closest("button,.atlas-pin") || e.button!==0 || dragging) return;
    dragging={id:e.pointerId,x:e.clientX,orbit};
    screen.setPointerCapture(e.pointerId);screen.classList.add("orbiting");
  };
  screen.onpointermove=e=>{
    const r=screen.getBoundingClientRect();
    if(dragging?.id===e.pointerId) orbit=dragging.orbit+(e.clientX-dragging.x)/r.width*3.8;
    else if(e.pointerType==="mouse" && !preference.matches) aimX=(e.clientX-r.left)/r.width*2-1;
    if(!preference.matches) aimY=(e.clientY-r.top)/r.height*2-1;
    schedule();
  };
  screen.onlostpointercapture=()=>{dragging=null;screen.classList.remove("orbiting");};
  screen.onpointerleave=()=>{aimX=aimY=0;schedule();};
  screen.onkeydown=e=>{
    if(e.target!==screen || !["ArrowLeft","ArrowRight"].includes(e.key)) return;
    e.preventDefault();orbit+=e.key==="ArrowLeft"?-.25:.25;schedule();
  };
  const observer=new IntersectionObserver(entries=>{visible=entries[0].isIntersecting;previous=0;schedule();});
  observer.observe(figure);
  const resize=new ResizeObserver(schedule);resize.observe(screen);
  function changePreference() { playing=!preference.matches;motionLabel();schedule(); }
  document.addEventListener("visibilitychange",schedule);
  preference.addEventListener("change",changePreference);
  // A forced refresh may replace the view without changing the URL.
  const lifetime=new MutationObserver(()=>{
    if(figure.isConnected) return;
    cancelAnimationFrame(frame);observer.disconnect();resize.disconnect();lifetime.disconnect();
    document.removeEventListener("visibilitychange",schedule);
    preference.removeEventListener("change",changePreference);
  });
  lifetime.observe(document.getElementById("view"),{childList:true});
  motionLabel();select("internet");
}
