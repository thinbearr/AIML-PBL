# Cost-Sensitive, Exploit-Aware Vulnerability Prioritization — Phase 2 prototype

Implements the pipeline from `Project-Synopsis.pdf` end to end (RVCE IS353IA, 1RV24IS067 / 1RV24IS069) and a
**live-demo website that explains the whole project** while it runs.

> **All data is SYNTHETIC.** No NVD/KEV/EPSS download was done; `src/data_synth.py` generates a stand-in with the
> same fields so every stage runs offline. Numbers demonstrate that the pipeline works, not real-world performance.
> Replace `data/raw/cves_synthetic.parquet` with joined real NVD+KEV+EPSS data (same columns) to go real (Phase 3).

## Run
```
pip install -r requirements.txt
python run_pipeline.py        # data -> model -> simulator -> backtest + extensions (~10 min)
python server.py              # demo at http://localhost:8000  (offline; no Streamlit)
```
The site has no guided tour or explanation text: you open the tabs and present them yourself.

## The demo site (tabs in the menu)
1. **The problem** – why CVSS-first fails, headline backtest result
2. **Exploit model** – DT / RF / LogReg / Gradient boosting vs CVSS & EPSS, calibration, live FN:FP cost slider
3. **Network & risk** – tiered network graph, risk/cost formulas, host drill-down
4. **Bring your own data** – upload a host/software CSV; the pipeline runs on it (terminal-style log, name matching report)
5. **Patch planner** – live budget / strategy / downtime / dependency controls, patch table, per-patch reasoning, hindsight reveal, CSV export
6. **Optimizer lab** – live NSGA-II with progressive Pareto front, gap to ILP, attack-path objective
7. **Backtest evidence** – 6 strategies × 3 budgets × 20 inventories; synopsis success criteria computed live
8. **Limits & roadmap** – what is simulated, what is not claimed, Phase 3 list

Four more pages still exist in the code but are hidden from the menu: `#/pipeline` (How it works), `#/data`
(Data & labels), `#/cves` (Explain a CVE) and `#/extend` (Extensions). Type that address after the port to open one.

**Bring your own network (step 7):** drop in a CSV of hosts and software (`web/sample_inventory.csv` is a ready
example; columns `host`, `software`, optional `exposure`, `criticality`). The server normalises names such as
"Windows Server 2019" or "Apache HTTP Server 2.4.51" to the 40 supported products, reports anything it cannot match,
attaches the model-scored open CVEs, builds the patches and dependencies, and from then on the planner, network view
and optimizers all run on the uploaded inventory. "Reset to synthetic network" goes back. (Hindsight/KEV outcomes
still come from the synthetic labels, so they only mean something on the synthetic network.)

"New inventory" (top bar) regenerates the simulated network (seed, 200–500 hosts) and re-runs every optimizer.

## Code map
| Stage | File |
|---|---|
| Synthetic NVD/KEV/EPSS stand-in, label rule, censoring | `src/data_synth.py`, `config.yaml` |
| LogReg / Decision Tree / Random Forest / Gradient boosting, cost-sensitive threshold, isotonic calibration | `src/model.py` |
| Network simulator, risk & cost model, dependencies, topology | `src/simulate.py` |
| Random / CVSS / EPSS rankings, Greedy, ILP (scipy HiGHS), NSGA-II (numpy), attack-path objective | `src/optimize.py` |
| Backtest, extended + robustness experiments | `src/evaluate.py` |
| Demo server (JSON API + static site) | `server.py`, `web/` |

## Phase status
* **Phase 1 (done):** data schema, labels, models, simulator, optimizers.
* **Phase 2 (this):** backtest on 20 inventories, attack-path extension, noise robustness, per-CVE explanations,
  gradient boosting, interactive demo with guided walkthrough.
* **Phase 3 (left):** real NVD + KEV + EPSS data and re-run of all results; SHAP and XGBoost; sensitivity over
  exposure weights / effort hours; optional Exploit-DB + live feed with cached fallback; final report, slides, viva.

Deviations from the synopsis: ILP via `scipy.optimize.milp` (not PuLP); NSGA-II is hand-written (not pymoo);
gradient boosting is scikit-learn's `HistGradientBoostingClassifier` (not XGBoost); per-CVE explanation uses
occlusion (not SHAP); charts are hand-written SVG (no Plotly/Streamlit).
