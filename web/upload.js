/* Step 7: upload an inventory CSV and run the pipeline on it. */
PAGES.upload.render = async v => {
  v.innerHTML = head({ kick: "Step 7 · Bring your own network", title: "Upload an inventory. Watch the pipeline run on it.",
    lede: "Drop in a CSV of hosts and the software they run — the kind of export a scanner or CMDB gives you. The site cleans it, matches the software to known products, attaches the model-scored CVEs and builds the patch problem for your network.",
    explain: { what: "A file upload that turns a plain asset list into the same structures the simulator creates: hosts with exposure and criticality, candidate patches with benefit and cost, and dependencies.",
      why: "This is the real-implementation moment: everything downstream — planner, optimizers, network view, Pareto lab — now runs on <i>your</i> data, not a generated network.",
      say: "Download the sample, upload it, then open the planner. Point out the log: messy names like 'Windows Server 2019' are normalised to products, and unknown software is flagged instead of silently dropped." } }) +
    `<div class="grid g21"><div><div class="card"><div class="drop" id="drop"><b>⇪ Drop your inventory CSV here, or click to browse</b><span>.csv with a host column and a software column · max 8 MB · processed locally, nothing leaves this machine</span><input type="file" id="file" accept=".csv,text/csv,.txt" hidden></div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:14px"><a class="btn amb" href="/sample_inventory.csv" download="sample_inventory.csv">↓ Download sample CSV</a><button class="btn ghost" id="usesample">Use the sample directly</button><button class="btn ghost" id="reset">Reset to synthetic network</button></div></div>
      <div class="card mt"><h3>Terminal</h3><p class="sub">What the server does with your file, step by step.</p><div class="term" id="term"><div class="l cmd">$ awaiting file</div><div class="l cur"></div></div></div></div>
    <div style="display:grid;gap:18px;align-content:start"><div class="card"><h3>Expected columns</h3><p class="sub">Header names are flexible; only host and software are required.</p><div class="tw" style="max-height:none"><table><tbody>
      <tr><td class="mono">host</td><td>hostname, asset, server …</td></tr><tr><td class="mono">software</td><td>product, application, package … (e.g. "Apache HTTP Server 2.4.51")</td></tr>
      <tr><td class="mono">exposure</td><td>internet / dmz / internal <span class="mut">(optional)</span></td></tr><tr><td class="mono">criticality</td><td>1–5 or low / medium / high / critical <span class="mut">(optional)</span></td></tr></tbody></table></div>
      <p class="small mut" style="margin:10px 0 0">Software is matched to the 40 products present in the CVE pool, ignoring versions. Unknown software is reported, not guessed.</p></div>
      <div class="card"><h3>What happens next</h3><ol class="small" style="color:var(--ink2);padding-left:18px;margin:0"><li>Rows are parsed and names normalised.</li><li>Each host's products get every open CVE, already scored by the calibrated model.</li><li>Risk = p_exploit × impact × criticality × exposure weight.</li><li>Patch cost = effort + downtime penalty; OS patches become prerequisites.</li><li>Planner, network and optimizers all switch to your data.</li></ol>
      <p class="small mut" style="margin:10px 0 0">Note: the "hindsight" outcomes still come from the synthetic KEV labels, so they are only meaningful for the synthetic network.</p></div></div></div>
    <div id="up-result"></div>`;
  const term = $("#term");
  const log = async lines => {
    term.innerHTML = "";
    for (const [cls, text] of lines) { const d = document.createElement("div"); d.className = "l " + cls; d.textContent = text; term.appendChild(d); term.scrollTop = term.scrollHeight; await new Promise(r => setTimeout(r, 140)); }
    const c = document.createElement("div"); c.className = "l cur"; term.appendChild(c);
  };
  const show = async r => {
    const rp = r.report, ex = rp.exposure || {};
    const lines = [["cmd", `$ analyse ${r.meta.name || "inventory"}  (${nf(rp.rows)} rows)`],
      ["ok", `[ok]   columns → ${Object.entries(rp.columns).map(([k, c]) => `${k}=${c}`).join("  ")}`],
      ...rp.notes.map(n => ["warn", `[warn] ${n}`]),
      ["ok", `[ok]   ${rp.hosts} hosts · internet ${ex.internet || 0} · dmz ${ex.dmz || 0} · internal ${ex.internal || 0}`],
      ["ok", `[ok]   matched ${rp.matched_rows} host–software pairs to ${rp.products} known products`]];
    if (rp.unmatched_total) lines.push(["warn", `[warn] skipped ${rp.unmatched_total} rows with unrecognised software: ${rp.unmatched.slice(0, 4).map(u => u.raw).join(", ")}${rp.unmatched.length > 4 ? " …" : ""}`]);
    lines.push(["ok", `[ok]   ${nf(rp.cves)} distinct open CVEs · ${nf(rp.instances)} host–CVE instances, each scored by the calibrated model`],
      ["ok", `[ok]   built ${rp.patches} candidate patches · total effort ${nf(rp.total_cost)} h`], ["ok", "[done] planner, network view and optimizers now use this inventory"]);
    await log(lines);
    $("#up-result").innerHTML = `<div class="grid g4 mt">${kpi("Hosts", rp.hosts, `${rp.matched_rows} software installs`, "acc")}${kpi("Products matched", rp.products, rp.unmatched_total ? `${rp.unmatched_total} rows skipped` : "all rows matched", rp.unmatched_total ? "amb" : "")}${kpi("Open CVEs attached", nf(rp.cves), `${nf(rp.instances)} host–CVE instances`)}${kpi("Candidate patches", rp.patches, `${nf(rp.total_cost)} h total effort`, "amb")}</div>
      <div class="grid g2 mt"><div class="card"><h3>How your software names were matched</h3><p class="sub">Raw text → canonical product (versions ignored)</p><div class="tw" style="max-height:300px"><table><thead><tr><th>You wrote</th><th>Matched to</th><th class="num">Rows</th></tr></thead><tbody>${rp.mapping.map(m => `<tr><td>${esc(m.raw)}</td><td class="mono" style="color:var(--acc)">${esc(m.product)}</td><td class="num">${m.rows}</td></tr>`).join("")}</tbody></table></div>
      ${rp.unmatched.length ? `<h3 class="mt">Not recognised</h3><div class="chips">${rp.unmatched.map(u => `<span class="tag amb">${esc(u.raw)} ×${u.rows}</span>`).join("")}</div>` : ""}</div>
      <div class="card"><h3>Riskiest hosts before any patching</h3><p class="sub">Initial risk = Σ over every CVE on the host (p_exploit × impact × criticality × exposure).</p><div class="tw" style="max-height:300px"><table><thead><tr><th>Host</th><th>Exposure</th><th class="num">Crit</th><th class="num">Risk</th></tr></thead><tbody>${rp.top_hosts.map(h => `<tr><td class="mono">${esc(h.host)}</td><td>${expTag(h.exposure)}</td><td class="num">${h.criticality}</td><td class="num"><b>${nf(h.initial_risk, 1)}</b></td></tr>`).join("")}</tbody></table></div>
      <div style="display:flex;gap:10px;margin-top:16px;flex-wrap:wrap"><a class="btn" href="#/planner">Open the patch planner →</a><a class="btn ghost" href="#/network">See your network</a></div></div></div>`;
  };
  const send = async (text, name) => {
    $("#up-result").innerHTML = "";
    await log([["cmd", `$ upload ${name}  (${nf(text.length)} bytes)`], ["ok", "[..]   parsing and matching software names"]]);
    try {
      const r = await fetch("/api/upload", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ csv: text, name }) }), j = await r.json();
      if (j.error) throw new Error(j.error);
      ST.meta = j.meta; ST.plan = null; ST.strategies = null; updatePill(); toast(`Loaded ${j.report.hosts} hosts, ${j.report.patches} patches`);
      await show(j);
    } catch (e) { await log([["cmd", `$ upload ${name}`], ["err", `[error] ${e.message}`], ["warn", "[hint] the file needs at least a host column and a software column"]]); }
  };
  const pick = async f => { if (f) send(await f.text(), f.name); };
  const drop = $("#drop"), file = $("#file");
  drop.onclick = () => file.click(); file.onchange = () => pick(file.files[0]);
  ["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", e => pick(e.dataTransfer.files[0]));
  $("#usesample").onclick = async () => send(await (await fetch("/sample_inventory.csv")).text(), "sample_inventory.csv");
  $("#reset").onclick = async () => {
    ST.meta = await api("/api/inventory", { seed: 42 }); ST.plan = null; ST.strategies = null; updatePill(); $("#up-result").innerHTML = "";
    await log([["cmd", "$ reset"], ["ok", `[ok]   back to the synthetic network (${ST.meta.hosts} hosts)`]]); toast("Reset to synthetic network");
  };
  if (ST.meta.source === "upload" && ST.meta.report) show({ report: ST.meta.report, meta: ST.meta });
};
