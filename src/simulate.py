"""Stage 4a: network simulator, risk and cost model (synopsis Sec. 5.3.2).

risk(CVE, host)  = p_exploit x impact(C,I,A) x criticality x exposure_weight
patch benefit    = sum of risk of all CVEs removed by the patch
patch cost       = base effort hours (by software type) + downtime penalty x criticality
A patch = update product P on host H; it fixes all CVEs of P present on H.
"""
import numpy as np
import pandas as pd
from common import load_config, ensure_dirs, PROC

IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}


def load_scored():
    df = pd.read_parquet(PROC / "scored_cves.parquet")
    return df[df["split"] == "test"].reset_index(drop=True)  # the "open" CVEs at the backtest cutoff


def build_inventory(cves, cfg, seed, n_hosts=None):
    """Returns (hosts, patches, patch_cves) for one random inventory."""
    nc = cfg["network"]
    rng = np.random.default_rng(seed)
    n_hosts = int(n_hosts) if n_hosts else int(rng.integers(nc["n_hosts_min"], nc["n_hosts_max"] + 1))
    ex_names = list(nc["exposure_probs"])
    exposure = rng.choice(ex_names, n_hosts, p=list(nc["exposure_probs"].values()))
    crit = rng.integers(1, 6, n_hosts)
    hosts = pd.DataFrame({"host": [f"H{k:03d}" for k in range(n_hosts)], "exposure": exposure, "criticality": crit})
    # illustrative topology: internal hosts sit behind a DMZ host, DMZ hosts behind an internet-facing host
    inet, dmz = np.flatnonzero(exposure == "internet"), np.flatnonzero(exposure == "dmz")
    parent = np.full(n_hosts, -1)
    for i in range(n_hosts):
        pool = dmz if exposure[i] == "internal" else inet if exposure[i] == "dmz" else []
        if len(pool):
            parent[i] = int(rng.choice(pool))
    hosts["parent"] = parent

    by_prod = {pn: g for pn, g in cves.groupby("product")}
    ptype = cves.drop_duplicates("product").set_index("product")["ptype"].to_dict()
    pop = cves["product"].value_counts()
    os_prods = [p for p in by_prod if ptype[p] == "os"]
    other = [p for p in by_prod if ptype[p] != "os"]
    w = pop[other].to_numpy(float)
    w = w / w.sum()

    rows, links = [], []
    pid = 0
    lo, hi = nc["products_per_host"]
    af_lo, af_hi = nc["affected_fraction"]
    for h in hosts.itertuples():
        chosen = [rng.choice(os_prods)] + list(rng.choice(other, int(rng.integers(lo, hi + 1)) - 1, replace=False, p=w))
        os_pid = None
        for prod in chosen:
            g = by_prod[prod]
            frac = rng.uniform(af_lo, af_hi)
            sub = g[rng.random(len(g)) < frac]
            if sub.empty:
                continue
            ew = nc["exposure_weight"][h.exposure]
            impact = sum(sub[c].map(IMPACT) for c in ("c", "i", "a")) / 1.68
            risk = sub["p_exploit"].to_numpy() * impact.to_numpy() * h.criticality * ew
            t = ptype[prod]
            cost = nc["base_effort_hours"][t] + nc["downtime_penalty"] * nc["downtime_hours"][t] * h.criticality
            requires = -1
            if t == "os":
                os_pid = pid
            elif os_pid is not None and rng.random() < nc["dependency_prob"]:
                requires = os_pid
            rows.append({"patch_id": pid, "host": h.host, "product": prod, "ptype": t,
                         "benefit": float(risk.sum()), "cost": float(cost),
                         "downtime": float(nc["downtime_hours"][t]), "requires": requires,
                         "exposure": h.exposure, "criticality": int(h.criticality), "n_cves": len(sub)})
            links.append(pd.DataFrame({"patch_id": pid, "cve_id": sub["cve_id"].to_numpy(), "risk": risk,
                                       "cvss": sub["cvss"].to_numpy(), "epss": sub["epss"].to_numpy(),
                                       "p_exploit": sub["p_exploit"].to_numpy(), "label": sub["label"].to_numpy()}))
            pid += 1
    patches = pd.DataFrame(rows)
    patch_cves = pd.concat(links, ignore_index=True)
    agg = patch_cves.groupby("patch_id").agg(max_cvss=("cvss", "max"), sum_epss=("epss", "sum"))
    patches = patches.join(agg, on="patch_id")
    return hosts, patches, patch_cves


def build_from_table(cves, cfg, table, seed):
    """Build an inventory from an uploaded table [host, exposure, criticality, product] (product already canonical).
    Every open (test-period) CVE of a product is assumed present on each host that runs it."""
    nc = cfg["network"]
    rng = np.random.default_rng(seed)
    first = table.drop_duplicates("host").reset_index(drop=True)
    hosts = pd.DataFrame({"host": first["host"], "exposure": first["exposure"],
                          "criticality": first["criticality"].astype(int)})
    exposure = hosts["exposure"].to_numpy()
    inet, dmz = np.flatnonzero(exposure == "internet"), np.flatnonzero(exposure == "dmz")
    parent = np.full(len(hosts), -1)
    for i in range(len(hosts)):
        pool = dmz if exposure[i] == "internal" else inet if exposure[i] == "dmz" else []
        if len(pool):
            parent[i] = int(rng.choice(pool))
    hosts["parent"] = parent
    by_prod = {pn: g for pn, g in cves.groupby("product")}
    ptype = cves.drop_duplicates("product").set_index("product")["ptype"].to_dict()
    rows, links, pid = [], [], 0
    for h in hosts.itertuples():
        prods = list(dict.fromkeys(table.loc[table.host == h.host, "product"]))
        prods.sort(key=lambda p: ptype[p] != "os")  # OS first so dependents can reference it
        os_pid = None
        for prod in prods:
            sub = by_prod[prod]
            ew = nc["exposure_weight"][h.exposure]
            impact = sum(sub[c].map(IMPACT) for c in ("c", "i", "a")) / 1.68
            risk = sub["p_exploit"].to_numpy() * impact.to_numpy() * h.criticality * ew
            t = ptype[prod]
            cost = nc["base_effort_hours"][t] + nc["downtime_penalty"] * nc["downtime_hours"][t] * h.criticality
            requires = -1
            if t == "os":
                os_pid = pid
            elif os_pid is not None and rng.random() < nc["dependency_prob"]:
                requires = os_pid
            rows.append({"patch_id": pid, "host": h.host, "product": prod, "ptype": t, "benefit": float(risk.sum()),
                         "cost": float(cost), "downtime": float(nc["downtime_hours"][t]), "requires": requires,
                         "exposure": h.exposure, "criticality": int(h.criticality), "n_cves": len(sub)})
            links.append(pd.DataFrame({"patch_id": pid, "cve_id": sub["cve_id"].to_numpy(), "risk": risk,
                                       "cvss": sub["cvss"].to_numpy(), "epss": sub["epss"].to_numpy(),
                                       "p_exploit": sub["p_exploit"].to_numpy(), "label": sub["label"].to_numpy()}))
            pid += 1
    patches = pd.DataFrame(rows)
    patch_cves = pd.concat(links, ignore_index=True)
    agg = patch_cves.groupby("patch_id").agg(max_cvss=("cvss", "max"), sum_epss=("epss", "sum"))
    return hosts, patches.join(agg, on="patch_id"), patch_cves


def main():
    ensure_dirs()
    cfg = load_config()
    hosts, patches, links = build_inventory(load_scored(), cfg, cfg["seed"])
    hosts = hosts.merge(patches.groupby("host")["benefit"].sum().rename("host_risk"), on="host", how="left").fillna(0)
    hosts.to_csv(PROC / "hosts.csv", index=False)
    patches.to_csv(PROC / "patches.csv", index=False)
    links.to_parquet(PROC / "patch_cves.parquet", index=False)
    print(f"[sim] {len(hosts)} hosts, {len(patches)} candidate patches, total cost {patches.cost.sum():.0f}h, "
          f"total risk {patches.benefit.sum():.1f}, {int((patches.requires >= 0).sum())} with dependencies")


if __name__ == "__main__":
    main()
