/* Current-inventory budget lab. A solver response is committed as a unit. */
PAGES.network.render = async (view, token) => {
  let plan=await api("/api/plan",planParams());
  if(token!==_routeToken) return;
  ST.plan=plan;
  const query=new URLSearchParams(location.hash.split("?")[1]), tiers=["internet","dmz","internal"];
  const visible=new Set(tiers.includes(query.get("tier"))?[query.get("tier")]:tiers);
  view.innerHTML=head({title:"Where do the patch hours go?",lede:"Set a maintenance budget, then inspect how the plan changes risk on individual hosts."})+`
    <div class="lab-nav"><a href="#/planner">Planner settings</a><a href="#/replay">Compare two strategies</a></div>
    <section class="lab card" aria-label="Live patch-budget map">
      <header class="lab-title"><div><span class="figure-label">Current inventory</span><h2>Host risk atlas</h2></div><span class="lab-meta">${esc(STRAT[plan.strategy].name)} · ${nf(plan.hosts.length)} hosts</span></header>
      <div class="lab-layout"><div class="map-frame">
        <div class="map-tools"><span>Exposure tiers</span><div id="n-ex">${tiers.map(t=>`<button class="chip" data-e="${t}" type="button">${t==="dmz"?"DMZ":t}</button>`).join("")}</div></div>
        <svg id="n-svg" class="risk-map" viewBox="0 0 850 418" role="group" tabindex="0" aria-label="Three-dimensional host risk map. Drag the background or use left and right arrows to rotate. Inspect a marker or use the host picker."></svg>
        <div class="map-key"><span class="risk-gradient"></span> Lower to higher risk <span class="map-tick">✓</span> Receives a patch
          <div class="turn-map"><button type="button" aria-label="Rotate map left">↶</button><button type="button" aria-label="Rotate map right">↷</button></div></div>
        <div class="wipe"><label for="risk-wipe">Before / after risk</label><output id="wipe-value" for="risk-wipe">After plan</output>
          <input id="risk-wipe" type="range" min="0" max="100" value="100"><div><span>Before patching</span><span>After plan</span></div></div>
      </div><aside class="lab-controls">
        <label class="figure-label" for="live-budget">Patch budget</label><div class="budget-value"><output id="budget-pct" for="live-budget">${budgetPercent(plan.pct)}</output><small>%</small></div>
        <input id="live-budget" type="range" step="any" min="5" max="40" value="${plan.pct}">
        <div class="budget-adjust"><span id="budget-limit" class="small"></span><button class="btn ghost sm" id="add-hours">+10 hours</button></div><div id="map-totals"></div><p id="budget-change" class="lab-status" role="status"></p>
        <label class="f" for="n-host">Inspect host</label><select id="n-host"></select><button id="inspect-host" class="btn">Inspect selected host</button>
      </aside></div>
      <div id="n-panel" class="host-strip"></div>
    </section>
    <div class="grid g2 mt"><section class="card"><h3>Reading the atlas</h3><p>Each marker is one host. Its size indicates criticality. The outer shelf holds internet-facing hosts, the middle shelf holds DMZ hosts, and the raised centre holds internal hosts. The same colour scale applies before and after patching.</p><p class="caption">Drag the divider control to reveal the solved plan from the left. Hosts stay in place while their risk changes.</p></section>
    <section class="card"><h3>How the plan values a patch</h3><div class="formula">Host–CVE risk = probability × impact × criticality × exposure weight</div><p>A patch covers the open CVEs for one product on one host. Its benefit is the sum of their risks. Inspect a host to follow a patch through the calculation.</p></section></div>`;
  const root=view.querySelector(".lab"), find=s=>root.querySelector(s);
  const slider=find("#live-budget"), picker=find("#n-host"), status=find("#budget-change");
  const map=withAttackViews(mountRiskMap(find("#n-svg"),plan.hosts,(h,marker)=>inspect(h,marker)),root,plan.hosts,(h,marker)=>inspect(h,marker));
  let selected, revision=0, solving=false;
  const live=()=>root.isConnected && token===_routeToken;
  const signed=(value,d=1)=>(value>0?"+":"")+nf(value,d);
  function totals() {
    find("#add-hours").disabled=plan.budget+10>plan.total_cost*.4;
    find("#budget-limit").textContent=nf(plan.budget,1)+" patch-hours available";
    find("#map-totals").innerHTML=[
      ["Hours used",nf(plan.cost_used,1)+" h"],["Risk removed",pc(plan.risk_removed_pct,1)],
      ["Hosts receiving patches",nf(plan.hosts_touched)],["Patches selected",nf(plan.n_selected)]
    ].map(([label,value])=>`<div><span>${label}</span><b>${value}</b></div>`).join("");
  }
  function highlight(h) {
    selected=h;map.select(h?.i);picker.value=h?String(h.i):"";
    find("#inspect-host").disabled=!h || solving;
    find("#n-panel").innerHTML=h?`<strong>${esc(h.host)}</strong>${expTag(h.exposure)}<span>Criticality ${h.crit}</span><span>Risk <b>${nf(h.initial,2)}</b> → <b>${nf(h.residual,2)}</b></span>`:"No hosts in the selected tiers.";
  }
  function filters() {
    const options=plan.hosts.filter(h=>visible.has(h.exposure));
    map.filter(visible);
    for(const button of root.querySelectorAll("#n-ex button")) press(button,visible.has(button.dataset.e));
    picker.replaceChildren(...options.map(h=>new Option(h.host,h.i)));
    picker.disabled=!options.length;
    highlight(options.find(h=>h.i===selected?.i) || options.reduce((best,h)=>!best||h.initial>best.initial?h:best,null));
  }
  function inspect(h,origin,patchId=null) {
    if(!h || solving) return;
    highlight(h);TT.hide();
    const hostBody=document.createElement("div");
    openDrawer("Host inspection",h.host,"",origin);
    $("#db").replaceChildren(hostBody);
    loadHostDetail(hostBody,h,plan,patchId);
  }
  async function solve(ticket,pct) {
    if(ticket!==revision || !live()) return;
    try {
      const next=await api("/api/plan",{...planParams(),pct});
      if(!live() || ticket!==revision) return;
      const prior=plan, covered=new Set(prior.hosts.filter(h=>h.patched).map(h=>h.i));
      const added=new Set(next.hosts.filter(h=>h.patched && !covered.has(h.i)).map(h=>h.i));
      const lost=next.hosts.filter(h=>!h.patched && covered.has(h.i)).length;
      plan=next;ST.pct=next.pct;ST.plan=next;ST.strategies=null;solving=false;
      map.update(next.hosts,added);highlight(next.hosts.find(h=>h.i===selected?.i));totals();
      status.textContent=`Compared with ${budgetPercent(prior.pct)}%: ${signed(next.cost_used-prior.cost_used)} h used, ${signed(next.risk_removed_pct-prior.risk_removed_pct)} percentage points of risk removed. ${added.size} newly covered hosts${lost?`, ${lost} lost coverage`:""}.`;
    } catch(error) {
      if(!live() || ticket!==revision) return;
      solving=false;slider.value=plan.pct;find("#budget-pct").textContent=budgetPercent(plan.pct);highlight(selected);totals();
      status.textContent=`Showing the ${budgetPercent(plan.pct)}% plan. ${error.message}`;
    }
  }
  const deferred=debounce(solve,220);
  function queueBudget(pct) {
    slider.value=pct;
    find("#add-hours").disabled=true;
    solving=true;find("#inspect-host").disabled=true;
    find("#budget-pct").textContent=budgetPercent(pct);find("#budget-limit").textContent=nf(plan.total_cost*pct/100,1)+" patch-hours available";
    status.textContent=`Solving at ${budgetPercent(pct)}%. The map shows the last completed plan at ${budgetPercent(plan.pct)}%.`;
    deferred(++revision,pct);
  }
  slider.oninput=()=>queueBudget(Number(Number(slider.value).toFixed(2)));
  find("#add-hours").onclick=()=>queueBudget((plan.budget+10)/plan.total_cost*100);
  find("#risk-wipe").oninput=e=>{
    const pct=Number(e.target.value);map.scrub(pct);
    const label=pct===100?"After plan":pct===0?"Before patching":`${pct}% of map after plan`;
    find("#wipe-value").textContent=label;e.target.setAttribute("aria-valuetext",label);
  };
  picker.onchange=()=>highlight(plan.hosts.find(h=>String(h.i)===picker.value));
  find("#inspect-host").onclick=()=>inspect(selected,map.marker(selected?.i));
  for(const b of root.querySelectorAll("#n-ex button")) b.onclick=()=>{const tier=b.dataset.e;visible.has(tier)?visible.delete(tier):visible.add(tier);filters();};
  root.querySelectorAll(".turn-map button").forEach((b,i)=>b.onclick=()=>map.rotate(i === 0 ? -.28 : .28));
  selected=plan.hosts.find(h=>h.host===query.get("host"));
  filters();totals();
  status.textContent="Change the budget to see which hosts gain coverage.";
  if(selected && selected.host===query.get("host") && query.has("patch")) requestAnimationFrame(()=>{
    if(!live()) return;
    const origin=map.marker(selected.i);origin.scrollIntoView({block:"center"});
    inspect(selected,origin,Number(query.get("patch")));
  });
};

async function loadHostDetail(body,host,plan,requestedPatch) {
  body.innerHTML='<p role="status">Loading host patches…</p>';
  const isOpen=()=>body.isConnected && $("#drawer").classList.contains("open");
  try {
    const record=await api("/api/host",{host:host.host,inventory_id:plan.inventory_id});
    if(!isOpen()) return;
    const selectedIds=new Set(plan.plan.map(p=>p.patch_id));
    const patches=record.patches;
    body.innerHTML=`<div class="host-context">${expTag(host.exposure)} <span>Criticality ${host.crit} · ${STRAT[plan.strategy].name} at ${budgetPercent(plan.pct)}%</span></div>
      <h3>Risk on this host</h3><p class="host-risk">${nf(host.initial,2)} <span>→</span> ${nf(host.residual,2)}</p>
      <p class="sub">${record.parent?`Upstream host ${esc(record.parent)}. `:""}${record.children} downstream hosts.</p>
      <h3>Follow one patch</h3><label class="f" for="walk-patch">Candidate patch on ${esc(host.host)}</label><select id="walk-patch"></select>
      <div class="patch-story"></div><details class="host-list"><summary>All candidate patches (${patches.length})</summary><div class="tw"><table><thead><tr><th>Product</th><th>Benefit</th><th>Hours</th><th>Decision</th></tr></thead><tbody>${patches.map(p=>`<tr><td>${esc(p.product)}</td><td>${nf(p.benefit,2)}</td><td>${nf(p.cost,1)}</td><td>${selectedIds.has(p.patch_id)?"Selected":"Skipped"}</td></tr>`).join("")}</tbody></table></div></details>`;
    const picker=body.querySelector("#walk-patch"), story=body.querySelector(".patch-story");
    picker.replaceChildren(...patches.map(p=>new Option(p.product+" · #"+p.patch_id,p.patch_id)));
    if(!patches.length) {picker.disabled=true;story.textContent="This host has no candidate patches.";return;}
    const first=patches.find(p=>p.patch_id===requestedPatch)||patches.find(p=>selectedIds.has(p.patch_id))||patches[0];
    picker.value=first.patch_id;
    let version=0;
    async function walk() {
      const ticket=++version;
      story.textContent="Loading patch evidence…";
      try {
        const detail=await api("/api/patch",{id:picker.value,inventory_id:plan.inventory_id});
        if(isOpen() && ticket===version) renderPatchStory(story,detail,plan,selectedIds);
      } catch(error) {if(isOpen()&&ticket===version) story.textContent=error.message;}
    }
    picker.onchange=walk;await walk();
  } catch(error) {if(isOpen()) body.textContent=error.message;}
}

function renderPatchStory(story,data,plan,selectedIds) {
  const p=data.patch,c=data.cves[0],f=data.formula,chosen=selectedIds.has(p.patch_id);
  const rationale={
    ml_ilp:"ILP maximizes the combined benefit of the patch set within the budget and downtime limits.",
    cvss_sorted:`This strategy considers the highest CVSS on each candidate patch. This patch’s maximum is ${nf(p.max_cvss,1)}.`,
    epss_sorted:`This strategy considers total EPSS across the patch’s CVEs. Here that sum is ${nf(p.sum_epss,3)}.`,
    ml_greedy:"Greedy prioritizes benefit per hour and checks whether a patch and its required prerequisites fit.",
    ml_nsga2:"The genetic search selects a feasible combination of patches from its effort–risk trade-off curve.",
    random:"The random baseline visits patches in seeded random order and includes those that fit."
  };
  const stages=[
    ["Probability",pc(c.p_exploit*100,1),`Calibrated exploitation probability for ${esc(c.cve_id)}, the highest-risk CVE covered by this patch on ${esc(p.host)}.`],
    ["Exposure",nf(c.risk,3),`Host–CVE risk ≈ ${nf(c.p_exploit,3)} probability × ${nf(f.top_impact,3)} impact × ${p.criticality} criticality × ${nf(f.exposure_weight,2)} exposure weight. Values are rounded.`],
    ["Cost",nf(p.cost,2)+" h",`${nf(f.base_hours,2)} h base effort + ${nf(f.downtime_penalty,2)} downtime penalty × ${nf(p.downtime,2)} h downtime × ${p.criticality} criticality. The patch covers ${data.n_total_cves} CVEs with a combined modelled benefit of ${nf(p.benefit,2)}.`],
    ["Decision",chosen?"Selected":"Skipped",`${esc(STRAT[plan.strategy].name)} ${chosen?"included":"did not include"} this patch at a budget of ${nf(plan.budget,1)} h. ${rationale[plan.strategy]} Its modelled benefit per hour is ${nf(p.benefit/p.cost,2)}.${data.requires?` Its recorded prerequisite is ${esc(data.requires.product)} (#${data.requires.patch_id}), ${selectedIds.has(data.requires.patch_id)?"included in":"outside"} this plan.`:""}`]
  ];
  story.innerHTML=`<div class="walk-stages" role="group" aria-label="Patch walkthrough">${stages.map(([name],i)=>`<button data-step="${i}">${i+1} · ${name}</button>`).join("")}</div>
    <article class="walk-page" aria-live="polite"></article><div class="walk-nav"><button class="btn ghost sm">Previous</button><button class="btn sm">Next step</button></div>`;
  const buttons=[...story.querySelectorAll("[data-step]")], nav=story.querySelectorAll(".walk-nav button");
  let step=0;
  function show(i) {
    step=i;buttons.forEach((b,j)=>press(b,i===j));
    const [name,value,text]=stages[i];
    story.querySelector("article").innerHTML=`<small>${esc(p.host)} / ${esc(p.product)} / #${p.patch_id}</small><div class="walk-number">${value}</div><h4>${name}</h4><p>${text}</p>`;
    if(i===3) window.FX?.stamp(story.querySelector("article"),chosen?"Patch":"Deferred",chosen?"good":"ink");
    nav[0].disabled=i===0;nav[1].disabled=i===3;
  }
  buttons.forEach((b,i)=>b.onclick=()=>show(i));nav[0].onclick=()=>show(step-1);nav[1].onclick=()=>show(step+1);show(0);
}
