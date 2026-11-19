"""Stage 5: backtest of all six strategies at 10/20/30% of total patch cost over many inventories.

Time-machine logic: the exploit model was trained on CVEs published up to the train/val cut-off;
the inventories contain only the later (test-period) CVEs; the selected patches are scored on which of
those CVEs were added to KEV within 12 months (label == 1).
"""
import time
import numpy as np
import pandas as pd
from common import load_config, ensure_dirs, RES, PROC
from simulate import build_inventory, load_scored
from optimize import (Problem, select_random, select_by_score, select_greedy, select_ilp,
                      select_nsga2, pick_from_front, build_ext, ext_benefit)

STRATS = ["random", "cvss_sorted", "epss_sorted", "ml_greedy", "ml_ilp", "ml_nsga2"]


def score_selection(x, patches, links):
    total_exploited = int(links["label"].sum())
    sel = links[links["patch_id"].isin(patches["patch_id"].to_numpy()[x])]
    return {"benefit": float(patches["benefit"].to_numpy()[x].sum()),
            "residual_risk": float(patches["benefit"].sum() - patches["benefit"].to_numpy()[x].sum()),
            "cost": float(patches["cost"].to_numpy()[x].sum()),
            "exploited_covered": int(sel["label"].sum()),
            "coverage_pct": 100.0 * sel["label"].sum() / max(total_exploited, 1)}


def run_strategies(patches, links, frac, cfg, front=None, seed=0):
    oc = cfg["optimize"]
    T, D = patches["cost"].sum(), patches["downtime"].sum()
    pb = Problem(patches, frac * T, oc["downtime_fraction"] * D)
    out = {}
    t = time.time(); out["random"] = (select_random(pb, seed), time.time() - t)
    t = time.time(); out["cvss_sorted"] = (select_by_score(pb, patches["max_cvss"].to_numpy()), time.time() - t)
    t = time.time(); out["epss_sorted"] = (select_by_score(pb, patches["sum_epss"].to_numpy()), time.time() - t)
    t = time.time(); out["ml_greedy"] = (select_greedy(pb), time.time() - t)
    t = time.time(); out["ml_ilp"] = (select_ilp(pb, oc["ilp_time_limit"]), time.time() - t)
    if front is not None:
        out["ml_nsga2"] = (pick_from_front(front[0], pb.budget), front[1])
    return pb, out


def run_extended(cves, cfg):
    """Attack-path extension: linear solvers (greedy/ILP) vs NSGA-II on the non-linear objective."""
    oc = cfg["optimize"]
    rows = []
    for k in range(cfg["evaluation"]["ext_inventories"]):
        seed = cfg["seed"] + k
        hosts, patches, links = build_inventory(cves, cfg, seed)
        T, D = patches["cost"].sum(), patches["downtime"].sum()
        pb = Problem(patches, 0.2 * T, oc["downtime_fraction"] * D)
        ext = build_ext(patches, hosts, oc["attack_path_gamma"])
        sels = {"ml_greedy": select_greedy(pb), "ml_ilp": select_ilp(pb, oc["ilp_time_limit"])}
        pb.set_ext(ext)
        t = time.time()
        fr = select_nsga2(pb, oc["nsga_pop"], oc["nsga_gens"], seed=seed)
        sels["ml_nsga2_ext"] = pick_from_front(fr, pb.budget)
        for name, x in sels.items():
            assert pb.feasible(x)
            m = score_selection(x, patches, links)
            rows.append({"inventory": k, "strategy": name, "ext_benefit": float(ext_benefit(x, ext)[0]),
                         "ext_total": float(ext_benefit(np.ones(len(x), bool), ext)[0]),
                         "linear_benefit": m["benefit"], "coverage_pct": m["coverage_pct"]})
        print(f"[ext] inventory {k + 1}/{cfg['evaluation']['ext_inventories']}")
    df = pd.DataFrame(rows)
    df["ext_pct"] = 100 * df["ext_benefit"] / df["ext_total"]
    df.to_csv(RES / "extended_runs.csv", index=False)
    df.groupby("strategy").agg(ext_pct_mean=("ext_pct", "mean"), ext_pct_std=("ext_pct", "std"),
                               coverage_mean=("coverage_pct", "mean"), coverage_std=("coverage_pct", "std")
                               ).reset_index().to_csv(RES / "extended_summary.csv", index=False)


def run_robustness(cves, cfg):
    """Planner sees noisy cost estimates; plan is judged against the true costs/budget."""
    oc = cfg["optimize"]
    rows = []
    for k in range(cfg["evaluation"]["robust_inventories"]):
        seed = cfg["seed"] + 100 + k
        hosts, patches, links = build_inventory(cves, cfg, seed)
        T, D = patches["cost"].sum(), patches["downtime"].sum()
        true_pb = Problem(patches, 0.2 * T, oc["downtime_fraction"] * D)
        ref = patches["benefit"].to_numpy()[select_ilp(true_pb, oc["ilp_time_limit"])].sum()
        for sg in cfg["evaluation"]["robust_sigmas"]:
            rng = np.random.default_rng(seed * 7 + int(sg * 100))
            noisy = patches.copy()
            noisy["cost"] = patches["cost"] * rng.lognormal(0, sg, len(patches)) if sg else patches["cost"]
            npb = Problem(noisy, 0.2 * T, oc["downtime_fraction"] * D)
            for name, x in (("ml_greedy", select_greedy(npb)), ("ml_ilp", select_ilp(npb, oc["ilp_time_limit"]))):
                m = score_selection(x, patches, links)
                over = max(0.0, patches["cost"].to_numpy()[x].sum() - 0.2 * T) / (0.2 * T) * 100
                rows.append({"inventory": k, "sigma": sg, "strategy": name, "coverage_pct": m["coverage_pct"],
                             "benefit_vs_ref_pct": 100 * m["benefit"] / ref, "budget_overshoot_pct": over})
        print(f"[robust] inventory {k + 1}/{cfg['evaluation']['robust_inventories']}")
    df = pd.DataFrame(rows)
    df.to_csv(RES / "robust_runs.csv", index=False)
    df.groupby(["sigma", "strategy"]).agg(coverage=("coverage_pct", "mean"), coverage_std=("coverage_pct", "std"),
                                          benefit_vs_ref=("benefit_vs_ref_pct", "mean"),
                                          overshoot=("budget_overshoot_pct", "mean")).reset_index().to_csv(
        RES / "robust_summary.csv", index=False)


def main():
    ensure_dirs()
    cfg = load_config()
    oc = cfg["optimize"]
    cves = load_scored()
    rows = []
    n_inv = cfg["evaluation"]["n_inventories"]
    for k in range(n_inv):
        seed = cfg["seed"] + k
        hosts, patches, links = build_inventory(cves, cfg, seed)
        T, D = patches["cost"].sum(), patches["downtime"].sum()
        # one NSGA-II run per inventory -> Pareto front; budgets are read off the same front
        pb_max = Problem(patches, max(oc["budget_fracs"]) * T, oc["downtime_fraction"] * D)
        t = time.time()
        front = (select_nsga2(pb_max, oc["nsga_pop"], oc["nsga_gens"], seed=seed), None)
        front = (front[0], time.time() - t)
        for frac in oc["budget_fracs"]:
            pb, sel = run_strategies(patches, links, frac, cfg, front, seed)
            ilp_b = patches["benefit"].to_numpy()[sel["ml_ilp"][0]].sum()
            for name, (x, rt) in sel.items():
                assert pb.feasible(x), f"{name} infeasible"
                m = score_selection(x, patches, links)
                m.update(inventory=k, n_hosts=len(hosts), n_patches=len(patches), budget_frac=frac,
                         strategy=name, runtime_s=rt, opt_gap_pct=100 * (ilp_b - m["benefit"]) / ilp_b)
                rows.append(m)
        print(f"[eval] inventory {k + 1}/{n_inv} done ({len(hosts)} hosts, {len(patches)} patches)")
    res = pd.DataFrame(rows)
    res.to_csv(RES / "backtest_runs.csv", index=False)
    summ = res.groupby(["budget_frac", "strategy"]).agg(
        coverage_mean=("coverage_pct", "mean"), coverage_std=("coverage_pct", "std"),
        residual_mean=("residual_risk", "mean"), residual_std=("residual_risk", "std"),
        gap_mean=("opt_gap_pct", "mean"), runtime_mean=("runtime_s", "mean")).reset_index()
    summ["strategy"] = pd.Categorical(summ["strategy"], STRATS, ordered=True)
    summ = summ.sort_values(["budget_frac", "strategy"])
    summ.to_csv(RES / "backtest_summary.csv", index=False)

    # curves + Pareto front on the first inventory (used by the dashboard)
    hosts, patches, links = build_inventory(cves, cfg, cfg["seed"])
    T, D = patches["cost"].sum(), patches["downtime"].sum()
    pb_max = Problem(patches, 0.4 * T, oc["downtime_fraction"] * D)
    front = select_nsga2(pb_max, oc["nsga_pop"], oc["nsga_gens"], seed=cfg["seed"])
    pd.DataFrame({"cost": front[2], "risk_reduction": front[1], "cost_pct": 100 * front[2] / T}).to_csv(
        RES / "pareto_front.csv", index=False)
    curve = []
    for frac in np.linspace(0.02, 0.4, 20):
        pb, sel = run_strategies(patches, links, frac, cfg, (front, 0.0), cfg["seed"])
        for name, (x, _) in sel.items():
            m = score_selection(x, patches, links)
            curve.append({"budget_pct": 100 * frac, "strategy": name, "coverage_pct": m["coverage_pct"],
                          "risk_reduction": m["benefit"], "residual_risk": m["residual_risk"]})
    pd.DataFrame(curve).to_csv(RES / "budget_curves.csv", index=False)

    run_extended(cves, cfg)
    run_robustness(cves, cfg)
    pd.set_option("display.width", 200)
    print("\n[eval] mean over", n_inv, "inventories (coverage % of later-KEV CVEs; SYNTHETIC data)")
    print(summ.round(2).to_string(index=False))


if __name__ == "__main__":
    main()
