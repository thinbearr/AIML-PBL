/* Review final solver selections in a documented order. ILP chooses a set. */
function replaySequence(rows, dependencies) {
  const byId=new Map(rows.map(p=>[p.patch_id,p])), seen=new Set(), sequence=[];
  function append(p) {
    if(seen.has(p.patch_id)) return;
    seen.add(p.patch_id);
    const prerequisite=byId.get(p.requires);
    if(dependencies && prerequisite) append(prerequisite);
    sequence.push(p);
  }
  rows.forEach(append);
  return sequence;
}

PAGES.replay.render = (view,token) => {
  view.innerHTML=head({title:"Where do the strategies disagree?",lede:"Give severity-first and ML + ILP the same hours. Replay their choices on the current inventory, then reveal how many later-exploited cases each plan covers."})+`
    <section class="replay lab card"><header class="lab-title"><div><span class="figure-label">Current inventory</span><h2>Strategy replay</h2></div><a href="#/network">Live risk map</a></header>
    <div class="replay-settings"><label for="replay-budget">Patch budget <b id="replay-pct">${budgetPercent(ST.pct)}%</b></label><input type="range" step="any" id="replay-budget" min="5" max="40" value="${ST.pct}">
      <span>${ST.dt}% downtime window · Dependencies ${ST.deps?"on":"off"}</span></div>
    <p class="replay-status" role="status"></p><div id="replay-results"></div></section>`;
  const root=view.querySelector(".replay"), budget=root.querySelector("#replay-budget"), output=root.querySelector("#replay-results");
  let version=0,timer;
  const alive=()=>root.isConnected && token===_routeToken;
  function request(delayed) {
    const ticket=++version,pct=Number(budget.value);
    clearTimeout(timer);output.replaceChildren();
    root.querySelector("#replay-pct").textContent=budgetPercent(pct)+"%";
    root.querySelector(".replay-status").textContent="Solving both strategies…";
    async function solve() {
      if(!alive() || version!==ticket) return;
      try {
        const data=await api("/api/replay",{...planParams(),pct});
        if(!alive() || version!==ticket) return;
        if(ST.pct!==pct) {ST.pct=pct;ST.plan=null;ST.strategies=null;}
        root.querySelector(".replay-status").textContent=`Each plan can spend up to ${nf(data.budget,1)} hours on the same ${ST.meta.hosts} hosts.`;
        display(data,ticket);
      } catch(error) {
        if(!alive() || version!==ticket) return;
        root.querySelector(".replay-status").textContent=error.message;
        const retry=document.createElement("button");retry.className="btn ghost";retry.textContent="Retry comparison";
        retry.onclick=()=>request(false);output.append(retry);
      }
    }
    if(delayed) timer=setTimeout(solve,230);else solve();
  }
  function display(data,ticket) {
    const lanes=data.plans.map(plan=>{
      const rows=replaySequence(plan.patches,data.deps);
      const hours=[0];rows.forEach(p=>hours.push(hours.at(-1)+p.cost));
      return {plan,rows,hours,ids:new Set(rows.map(p=>p.patch_id))};
    });
    const total=Math.max(...lanes.map(l=>l.rows.length));
    const shared=lanes[0].rows.filter(p=>lanes[1].ids.has(p.patch_id)).length;
    let step=total, playing=false, revealed=false;
    output.innerHTML=`<div class="replay-transport">
        <button type="button" class="btn" id="replay-play" ${total?"":"disabled"}>Play replay</button>
        <label for="review-step">Review step <output id="review-position"></output></label>
        <input id="review-step" type="range" min="0" max="${total}" value="${total}" ${total?"":"disabled"}>
        <label class="diff-filter"><input type="checkbox" id="only-diff"> Only differing choices</label></div>
      <p class="caption replay-caption">The display reviews CVSS-first by severity and the ILP selection by modelled benefit. When dependencies are on, prerequisites appear first. Shared and unique labels compare the two complete plans.</p>
      <div class="replay-lanes">${lanes.map(({plan},i)=>`<section class="replay-lane" data-lane="${i}"><header><h3>${STRAT[plan.strategy].name}</h3><span class="lane-hours"></span></header>
        <div class="lane-meter"><i></i></div><p class="lane-count"></p><div class="lane-table"></div></section>`).join("")}</div>
      <div class="outcome"><div><h3>Later-exploitation outcomes</h3><p class="sub">${shared} patches appear in both completed plans. Outcomes use the study’s synthetic later-KEV labels.</p></div>
        <button class="btn ghost" id="reveal-outcome">Reveal outcomes</button><div class="outcome-values" aria-live="polite"></div></div>`;
    const play=output.querySelector("#replay-play"), slider=output.querySelector("#review-step"), diff=output.querySelector("#only-diff");
    const reveal=output.querySelector("#reveal-outcome"), results=output.querySelector(".outcome-values");
    function stop() {clearTimeout(timer);playing=false;play.textContent="Play replay";}
    function draw() {
      slider.value=step;output.querySelector("#review-position").textContent=`${step} / ${total}`;
      slider.setAttribute("aria-valuetext",`Step ${step} of ${total}`);
      for(let i=0;i<lanes.length;i++) {
        const {rows,hours}=lanes[i],other=lanes[1-i].ids,shown=Math.min(step,rows.length);
        const lane=output.querySelector(`[data-lane="${i}"]`);
        lane.querySelector(".lane-hours").textContent=nf(hours[shown],1)+" h";
        lane.querySelector(".lane-meter i").style.width=Math.min(100,hours[shown]/(data.budget||1)*100)+"%";
        lane.querySelector(".lane-count").textContent=`${shown} of ${rows.length} patches · ${nf(Math.max(0,data.budget-hours[shown]),1)} h remaining`;
        const visible=rows.slice(0,shown).map((p,index)=>({...p,step:index+1,choice:other.has(p.patch_id)?"Both":"Unique"}))
          .filter(p=>!diff.checked || p.choice==="Unique");
        table(lane.querySelector(".lane-table"),visible,[
          {k:"step",label:"Step",num:1},{k:"host",label:"Host / patch",fmt:(v,p)=>`<b>${esc(v)}</b><small>${esc(p.product)} · #${p.patch_id}</small>`},
          {k:"cost",label:"Hours",num:1,fmt:v=>nf(v,1)},{k:"choice",label:"Choice",fmt:v=>`<span class="choice ${v==="Unique"?"unique":""}">${v}</span>`}
        ],{pageSize:6,sortKey:"step",desc:step!==total,empty:step===0?"Play or advance the replay to review selections.":"No matching patches at this step."});
      }
      reveal.disabled=step!==total;
      if(step!==total) revealed=false;
      reveal.textContent=revealed?"Hide outcomes":"Reveal outcomes";
      results.innerHTML=revealed?lanes.map(({plan})=>`<div><b>${STRAT[plan.strategy].name}</b><strong>${nf(plan.exploited_covered)} / ${nf(data.total_exploited)}</strong><span>${data.total_exploited?pc(plan.coverage_pct,1)+" covered":"No labelled positive cases"} · host–CVE instances</span></div>`).join(""):"";
    }
    function advance() {
      if(!alive() || ticket!==version || !playing) return;
      step=Math.min(total,step+Math.max(1,Math.ceil(total/52)));draw();
      if(step<total) timer=setTimeout(advance,160);else stop();
    }
    play.onclick=()=>{
      if(playing) {stop();return;}
      if(step>=total) step=0;
      playing=true;play.textContent="Pause replay";draw();timer=setTimeout(advance,160);
    };
    slider.oninput=()=>{stop();step=Number(slider.value);draw();};
    diff.onchange=draw;reveal.onclick=()=>{revealed=!revealed;draw();};draw();
  }
  budget.oninput=()=>request(true);
  request(false);
};
