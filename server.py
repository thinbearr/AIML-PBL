"""Local offline demo server for the project (standard library + project deps).
Run:  python server.py   ->  http://localhost:8000      (python server.py 8080 --no-browser)
"""
import io
import json
import mimetypes
import re
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
sys.path.insert(0, str(ROOT / "src"))
from common import PROC, RES, RAW, load_config  # noqa: E402
import model as model_mod  # noqa: E402,F401  (needed to unpickle the featurizer)
from simulate import build_inventory, build_from_table, load_scored  # noqa: E402
from data_synth import PRODUCTS  # noqa: E402
from optimize import (Problem, select_random, select_by_score, select_greedy, select_ilp,  # noqa: E402
                      select_nsga2, pick_from_front, build_ext, ext_benefit)

cfg = load_config()
LOCK = threading.RLock()
STRATS = ["random", "cvss_sorted", "epss_sorted", "ml_greedy", "ml_ilp", "ml_nsga2"]


class Inv:
    """The current simulated inventory + derived arrays."""

    def __init__(self, hosts, patches, links, seed):
        self.hosts, self.patches, self.links, self.seed = hosts.reset_index(drop=True), patches, links, seed
        self.T, self.D = float(patches.cost.sum()), float(patches.downtime.sum())
        self.total_risk = float(patches.benefit.sum())
        self.total_exploited = int(links.label.sum())
        self.top = links.sort_values("risk", ascending=False).drop_duplicates("patch_id").set_index("patch_id")
        self.hosts["initial_risk"] = self.hosts["host"].map(patches.groupby("host").benefit.sum()).fillna(0.0)
        self.ext = build_ext(patches, self.hosts, cfg["optimize"]["attack_path_gamma"])
        self.cache = {}
        self.source, self.name, self.report = "synthetic", None, None
        self.layout = self._layout()

    def _layout(self):
        h = self.hosts
        rng = np.random.default_rng(self.seed)
        band = {"internet": 0.10, "dmz": 0.48, "internal": 0.86}
        xs = np.zeros(len(h))
        inet = np.flatnonzero(h.exposure == "internet")
        xs[inet] = (np.arange(len(inet)) + 0.5) / max(len(inet), 1)
        for tier in ("dmz", "internal"):
            for i in np.flatnonzero(h.exposure == tier):
                p = h.parent[i]
                xs[i] = (xs[p] if p >= 0 else rng.random()) + rng.normal(0, 0.035 if tier == "dmz" else 0.05)
        xs = np.clip(xs, 0.01, 0.99)
        ys = np.array([band[e] for e in h.exposure]) + rng.normal(0, 0.045, len(h))
        return np.column_stack([xs, np.clip(ys, 0.02, 0.98)])


def make_inventory(seed, n_hosts=None):
    cves = load_scored()
    hosts, patches, links = build_inventory(cves, cfg, seed, n_hosts)
    return Inv(hosts, patches, links, seed)


INV = make_inventory(cfg["seed"])

# ---------------------------------------------------------------- upload: software-name matching
KNOWN = {p[0] for p in PRODUCTS}
ALIASES = {
    "windows server": "windows_server", "win server": "windows_server", "windows 10": "windows_10", "windows 11": "windows_10",
    "windows": "windows_10", "win10": "windows_10", "ubuntu": "ubuntu_linux", "debian": "ubuntu_linux", "red hat": "rhel",
    "redhat": "rhel", "rhel": "rhel", "centos": "rhel", "macos": "macos", "mac os": "macos", "os x": "macos",
    "apache http server": "apache_http", "apache httpd": "apache_http", "httpd": "apache_http", "apache": "apache_http",
    "nginx": "nginx", "iis": "iis", "internet information services": "iis", "apache tomcat": "tomcat", "tomcat": "tomcat",
    "exchange": "exchange_server", "exchange server": "exchange_server", "mysql": "mysql", "mariadb": "mysql",
    "postgres": "postgresql", "postgresql": "postgresql", "sql server": "mssql", "mssql": "mssql",
    "microsoft sql server": "mssql", "oracle database": "oracle_db", "oracle db": "oracle_db", "oracle": "oracle_db",
    "mongodb": "mongodb", "mongo": "mongodb", "google chrome": "chrome", "chrome": "chrome", "firefox": "firefox",
    "mozilla firefox": "firefox", "microsoft edge": "edge", "edge": "edge", "openssl": "openssl", "log4j": "log4j",
    "log4shell": "log4j", "zlib": "zlib", "curl": "curl", "libcurl": "curl", "glibc": "glibc", "fortios": "fortios",
    "fortigate": "fortios", "cisco ios": "cisco_ios", "ios xe": "cisco_ios", "cisco": "cisco_ios", "pan os": "pan_os",
    "pan-os": "pan_os", "palo alto": "pan_os", "junos": "junos", "juniper": "junos", "esxi": "vmware_esxi",
    "vmware esxi": "vmware_esxi", "vmware": "vmware_esxi", "wordpress": "wordpress", "jenkins": "jenkins",
    "confluence": "confluence", "atlassian confluence": "confluence", "gitlab": "gitlab", "adobe reader": "adobe_reader",
    "acrobat reader": "adobe_reader", "acrobat": "adobe_reader", "microsoft office": "office", "office": "office",
    "sharepoint": "sharepoint", "citrix adc": "citrix_adc", "citrix": "citrix_adc", "netscaler": "citrix_adc",
    "zimbra": "zimbra", "struts": "struts", "apache struts": "struts", "php": "php", "node.js": "nodejs",
    "nodejs": "nodejs", "node": "nodejs",
}
HEADERS = {"host": ("host", "hostname", "asset", "server", "name", "machine", "node", "asset_name"),
           "product": ("product", "software", "application", "app", "package", "service", "component"),
           "exposure": ("exposure", "zone", "tier", "network", "segment", "network_zone"),
           "criticality": ("criticality", "crit", "importance", "priority", "business_criticality", "asset_criticality")}


def norm_product(raw):
    s = re.sub(r"[^a-z0-9.\-]+", " ", str(raw).lower()).strip()
    nov = re.sub(r"\s+", " ", re.sub(r"(?<![a-z0-9])v?\d+(\.\d+)*[a-z]?(?![a-z0-9])", " ", s)).strip()
    for c in (s, nov):
        if c.replace(" ", "_") in KNOWN:
            return c.replace(" ", "_")
        if c in ALIASES:
            return ALIASES[c]
    best = None
    for k, v in ALIASES.items():
        if re.search(r"(?<![a-z0-9])" + re.escape(k) + r"(?![a-z0-9])", nov) and (best is None or len(k) > len(best[0])):
            best = (k, v)
    return best[1] if best else None


def norm_exposure(v):
    s = str(v).strip().lower()
    if s in ("internet", "public", "external", "internet-facing", "internet facing", "edge", "wan", "dmz-public"):
        return "internet"
    if s in ("dmz", "perimeter", "semi", "semi-trusted"):
        return "dmz"
    return "internal"


def norm_crit(v):
    s = str(v).strip().lower()
    words = {"low": 1, "minor": 1, "medium": 3, "moderate": 3, "med": 3, "high": 4, "major": 4, "critical": 5, "crown": 5}
    if s in words:
        return words[s]
    try:
        return int(min(5, max(1, round(float(s)))))
    except ValueError:
        return 3


def api_upload(body):
    text = body.get("csv", "")
    if not text.strip():
        raise ValueError("The file is empty.")
    df = pd.read_csv(io.StringIO(text), dtype=str, keep_default_na=False, sep=None, engine="python")
    df.columns = [re.sub(r"[\s\-]+", "_", str(c).strip().lower()) for c in df.columns]
    cols, notes = {}, []
    for key, names in HEADERS.items():
        hit = next((n for n in names if n in df.columns), None)
        if hit:
            cols[key] = hit
    for need in ("host", "product"):
        if need not in cols:
            raise ValueError(f"Missing a '{need}' column. Found columns: {', '.join(df.columns)}. "
                             f"Accepted names for {need}: {', '.join(HEADERS[need])}.")
    if len(df) > 20000:
        raise ValueError("Too many rows (limit 20,000).")
    t = pd.DataFrame({"host": df[cols["host"]].str.strip(), "raw": df[cols["product"]].str.strip()})
    t = t[(t.host != "") & (t.raw != "")]
    t["exposure"] = df.loc[t.index, cols["exposure"]].map(norm_exposure) if "exposure" in cols else "internal"
    t["criticality"] = df.loc[t.index, cols["criticality"]].map(norm_crit) if "criticality" in cols else 3
    if "exposure" not in cols:
        notes.append("No exposure column found - every host treated as internal.")
    if "criticality" not in cols:
        notes.append("No criticality column found - every host set to 3 (medium).")
    t["product"] = t.raw.map(norm_product)
    unmatched = t[t["product"].isna()].groupby("raw").size().sort_values(ascending=False)
    mapping = t[t["product"].notna()].groupby(["raw", "product"]).size().reset_index(name="rows").sort_values("rows", ascending=False)
    t = t[t["product"].notna()].drop_duplicates(["host", "product"])
    if t.empty:
        raise ValueError("None of the software names matched the supported products. "
                         "Supported: " + ", ".join(sorted(KNOWN)))
    if t.host.nunique() > 2000:
        raise ValueError("Too many hosts (limit 2,000).")
    hosts, patches, links = build_from_table(load_scored(), cfg, t[["host", "exposure", "criticality", "product"]], cfg["seed"])
    global INV
    inv = Inv(hosts, patches, links, cfg["seed"])
    inv.source, inv.name = "upload", body.get("name", "upload.csv")
    inv.report = {"rows": int(len(df)), "hosts": int(len(hosts)), "matched_rows": int(len(t)),
                  "unmatched": [{"raw": k, "rows": int(v)} for k, v in unmatched.head(25).items()],
                  "unmatched_total": int(unmatched.sum()), "mapping": mapping.head(40).to_dict("records"),
                  "products": int(t["product"].nunique()), "cves": int(links.cve_id.nunique()),
                  "instances": int(len(links)), "patches": int(len(patches)), "total_cost": float(patches.cost.sum()),
                  "exposure": t.drop_duplicates("host").exposure.value_counts().to_dict(),
                  "columns": {k: v for k, v in cols.items()}, "notes": notes,
                  "top_hosts": inv.hosts.sort_values("initial_risk", ascending=False).head(8)[
                      ["host", "exposure", "criticality", "initial_risk"]].round(2).to_dict("records")}
    INV = inv
    return {"report": inv.report, "meta": api_meta({})}


SCORED = pd.read_parquet(PROC / "scored_cves.parquet")
RAWDF = pd.read_parquet(RAW / "cves_synthetic.parquet")
MODEL = joblib.load(PROC / "model.joblib")
XALL = MODEL["featurizer"].transform(RAWDF)
XBG = XALL[(SCORED["split"] == "train").to_numpy()].sample(80, random_state=cfg["seed"]).reset_index(drop=True)
BASE_RAW = float(MODEL["rf"].predict_proba(XBG)[:, 1].mean())  # average forest score of a typical CVE
GROUPS = {
    "CVSS vector (AV/AC/PR/UI/S)": [c for c in XALL.columns if c.split("_")[0] in ("av", "ac", "pr", "ui", "scope")],
    "Impact (C/I/A)": [c for c in XALL.columns if c.split("_")[0] in ("c", "i", "a")],
    "CVSS base score": ["cvss"],
    "Weakness type (CWE)": [c for c in XALL.columns if c.startswith("cwe_")],
    "Vendor / product popularity": ["vendor_freq", "product_freq"],
    "Reference count": ["n_refs"],
    "Description wording": [c for c in XALL.columns if c.startswith("tf_")],
}


# ---------------------------------------------------------------- planning
def prep(inv, deps):
    p = inv.patches
    return p if deps else p.assign(requires=-1)


def solve(inv, strategy, pct, dt_frac, deps, ext):
    key = (strategy, round(pct, 2), round(dt_frac, 3), deps, ext)
    if key in inv.cache:
        return inv.cache[key]
    P = prep(inv, deps)
    pb = Problem(P, pct / 100 * inv.T, dt_frac * inv.D)
    t = time.time()
    if strategy == "random":
        x = select_random(pb, cfg["seed"])
    elif strategy == "cvss_sorted":
        x = select_by_score(pb, P.max_cvss.to_numpy())
    elif strategy == "epss_sorted":
        x = select_by_score(pb, P.sum_epss.to_numpy())
    elif strategy == "ml_greedy":
        x = select_greedy(pb)
    elif strategy == "ml_ilp":
        x = select_ilp(pb, 20)
    else:
        if ext:
            pb.set_ext(inv.ext)
        oc = cfg["optimize"]
        x = pick_from_front(select_nsga2(pb, oc["nsga_pop"], oc["nsga_gens"], seed=cfg["seed"]), pb.budget)
    out = (x, time.time() - t)
    inv.cache[key] = out
    return out


def q1(q, k, d):
    return q.get(k, [d])[0]


def params(q):
    return (q1(q, "strategy", "ml_ilp"), float(q1(q, "pct", "20")), float(q1(q, "dt", "25")) / 100,
            q1(q, "deps", "1") == "1", q1(q, "ext", "0") == "1")


def summarize(inv, x, strategy, rt):
    sel = inv.patches[x]
    lk = inv.links[inv.links.patch_id.isin(sel.patch_id)]
    return {"strategy": strategy, "runtime_s": rt, "n_selected": int(x.sum()), "cost_used": float(sel.cost.sum()),
            "downtime_used": float(sel.downtime.sum()),
            "risk_removed_pct": 100 * float(sel.benefit.sum()) / inv.total_risk,
            "ext_removed_pct": 100 * float(ext_benefit(x, inv.ext)[0] / ext_benefit(np.ones(len(x), bool), inv.ext)[0]),
            "hosts_touched": int(sel.host.nunique()), "exploited_covered": int(lk.label.sum()),
            "coverage_pct": 100 * float(lk.label.sum()) / max(inv.total_exploited, 1)}


def api_plan(q):
    inv = INV
    strategy, pct, dt, deps, ext = params(q)
    x, rt = solve(inv, strategy, pct, dt, deps, ext)
    sel = inv.patches[x]
    exp_per = inv.links[inv.links.label == 1].groupby("patch_id").size()
    rows = []
    for r in sel.sort_values("benefit", ascending=False).itertuples():
        top = inv.top.loc[r.patch_id]
        rows.append({"patch_id": int(r.patch_id), "host": r.host, "product": r.product, "ptype": r.ptype,
                     "exposure": r.exposure, "criticality": int(r.criticality), "n_cves": int(r.n_cves),
                     "benefit": round(r.benefit, 3), "cost": round(r.cost, 2), "downtime": r.downtime,
                     "requires": int(r.requires), "top_cve": top.cve_id, "top_p": round(float(top.p_exploit), 3),
                     "ratio": round(r.benefit / r.cost, 3), "exploited": int(exp_per.get(r.patch_id, 0))})
    patched = set(sel.host)
    resid = inv.patches.assign(sel=x).loc[lambda d: ~d.sel].groupby("host").benefit.sum()
    hosts = [{"i": i, "host": h.host, "exposure": h.exposure, "crit": int(h.criticality), "parent": int(h.parent),
              "x": float(inv.layout[i][0]), "y": float(inv.layout[i][1]), "initial": float(h.initial_risk),
              "residual": float(resid.get(h.host, 0.0)), "patched": h.host in patched}
             for i, h in enumerate(inv.hosts.itertuples())]
    return {**summarize(inv, x, strategy, rt), "pct": pct, "budget": pct / 100 * inv.T, "total_cost": inv.T,
            "total_exploited": inv.total_exploited, "plan": rows, "hosts": hosts}


def api_strategies(q):
    _, pct, dt, deps, ext = params(q)
    return [summarize(INV, *solve(INV, s, pct, dt, deps, ext)[:1], s, solve(INV, s, pct, dt, deps, ext)[1])
            for s in STRATS]


def api_patch(q):
    pid = int(q1(q, "id", "0"))
    inv = INV
    r = inv.patches[inv.patches.patch_id == pid].iloc[0]
    lk = inv.links[inv.links.patch_id == pid].sort_values("risk", ascending=False)
    meta = SCORED.set_index("cve_id")
    cves = [{"cve_id": c.cve_id, "p_exploit": round(float(c.p_exploit), 3), "cvss": float(c.cvss),
             "epss": round(float(c.epss), 3), "risk": round(float(c.risk), 3), "kev_later": int(c.label),
             "desc": str(meta.loc[c.cve_id, "description"]) if c.cve_id in meta.index else ""}
            for c in lk.head(25).itertuples()]
    req = None
    if r.requires >= 0:
        rr = inv.patches[inv.patches.patch_id == r.requires].iloc[0]
        req = {"patch_id": int(rr.patch_id), "product": rr.product}
    return {"patch": {k: (v.item() if hasattr(v, "item") else v) for k, v in r.to_dict().items()},
            "n_total_cves": int(len(lk)), "cves": cves, "requires": req,
            "formula": {"p_mean": float(lk.p_exploit.mean()), "sum_risk": float(lk.risk.sum())}}


def api_host(q):
    inv = INV
    hid = q1(q, "host", "H000")
    h = inv.hosts[inv.hosts.host == hid].iloc[0]
    ps = inv.patches[inv.patches.host == hid]
    return {"host": hid, "exposure": h.exposure, "criticality": int(h.criticality),
            "parent": (inv.hosts.host[h.parent] if h.parent >= 0 else None),
            "children": int((inv.hosts.parent == h.name).sum()),
            "patches": [{"patch_id": int(p.patch_id), "product": p.product, "benefit": round(p.benefit, 2),
                         "cost": round(p.cost, 2), "n_cves": int(p.n_cves), "requires": int(p.requires)}
                        for p in ps.sort_values("benefit", ascending=False).itertuples()]}


# ---------------------------------------------------------------- CVEs / model
def api_cves(q):
    df = SCORED
    s = q1(q, "split", "test")
    if s != "all":
        df = df[df.split == s]
    qq = q1(q, "q", "").strip().lower()
    if qq:
        df = df[df.cve_id.str.lower().str.contains(qq) | df["product"].str.contains(qq)]
    sort = q1(q, "sort", "p_exploit")
    df = df.sort_values(sort, ascending=False)
    page, size = int(q1(q, "page", "0")), 20
    sub = df.iloc[page * size:(page + 1) * size]
    return {"total": int(len(df)), "page": page, "rows": [
        {"cve_id": r.cve_id, "product": r.product, "published": str(r.published.date()), "cvss": float(r.cvss),
         "epss": round(float(r.epss), 3), "p_exploit": round(float(r.p_exploit), 4), "label": int(r.label),
         "split": r.split} for r in sub.itertuples()]}


def api_cve(q):
    cid = q1(q, "id", "")
    i = int(np.flatnonzero(SCORED.cve_id.to_numpy() == cid)[0])
    r, rf, iso = SCORED.iloc[i], MODEL["rf"], MODEL["iso"]
    x = XALL.iloc[[i]]
    raw_full = float(rf.predict_proba(x)[:, 1][0])
    full = float(iso.predict([raw_full])[0])
    contrib = []
    for g, cols in GROUPS.items():  # marginalise one feature group over 80 real CVEs (isotonic is a step function)
        xo = pd.concat([x] * len(XBG), ignore_index=True)
        xo[cols] = XBG[cols].to_numpy()
        contrib.append({"group": g, "delta": raw_full - float(rf.predict_proba(xo)[:, 1].mean())})
    contrib.sort(key=lambda c: -abs(c["delta"]))
    inv_rows = INV.links[INV.links.cve_id == cid]
    return {"cve_id": cid, "product": r["product"], "vendor": r.vendor, "type": r.ptype,
            "published": str(r.published.date()), "cvss": float(r.cvss), "epss": round(float(r.epss), 3),
            "p_exploit": full, "description": r.description, "cwe": int(r.cwe), "split": r.split,
            "label": int(r.label), "kev_date": (str(pd.Timestamp(r.kev_date).date()) if pd.notna(r.kev_date) else None),
            "av": r.av, "impact": f"C:{r.c} I:{r.i} A:{r.a}", "raw_score": raw_full, "baseline_raw": BASE_RAW, "contrib": contrib,
            "instances": int(len(inv_rows)), "rank_pct": float((SCORED.p_exploit >= full).mean() * 100)}


def api_threshold(q):
    ratio = float(q1(q, "ratio", "50"))
    va, te = SCORED[SCORED.split == "val"], SCORED[SCORED.split == "test"]
    ts = np.unique(np.quantile(va.p_exploit, np.linspace(0, 1, 400)))
    cost = [ratio * ((va.p_exploit < t) & (va.label == 1)).sum() + ((va.p_exploit >= t) & (va.label == 0)).sum()
            for t in ts]
    t = float(ts[int(np.argmin(cost))])
    p, y = te.p_exploit.to_numpy(), te.label.to_numpy()
    tp, fn = int(((p >= t) & (y == 1)).sum()), int(((p < t) & (y == 1)).sum())
    fp, tn = int(((p >= t) & (y == 0)).sum()), int(((p < t) & (y == 0)).sum())
    return {"ratio": ratio, "threshold": t, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "recall": tp / max(tp + fn, 1), "precision": tp / max(tp + fp, 1), "expected_cost": ratio * fn + fp,
            "naive_cost": ratio * (tp + fn)}


def api_model(_):
    return {"metrics": json.load(open(RES / "model_metrics.json")),
            "importance": pd.read_csv(RES / "feature_importance.csv").head(15).to_dict("records"),
            "calibration": pd.read_csv(RES / "calibration_curve.csv").to_dict("records"),
            "sensitivity": pd.read_csv(RES / "cost_sensitivity.csv").to_dict("records"),
            "tree": (RES / "decision_tree.txt").read_text(encoding="utf-8")}


def api_data(_):
    df = SCORED.copy()
    df["year"] = df.published.dt.year
    by_year = df.groupby("year").agg(n=("label", "size"), pos=("label", "sum")).reset_index()
    by_year["rate"] = 100 * by_year.pos / by_year.n
    bins = pd.cut(df.cvss, [0, 4, 7, 9, 10.01], labels=["Low (<4)", "Medium (4-7)", "High (7-9)", "Critical (9+)"])
    cv = df.groupby(bins, observed=True).agg(n=("label", "size"), pos=("label", "sum")).reset_index()
    cv["rate"] = 100 * cv.pos / cv.n
    cv["share"] = 100 * cv.n / len(df)
    sp = df.groupby("split").agg(n=("label", "size"), pos=("label", "sum")).reindex(["train", "val", "test"])
    d = cfg["data"]
    sample = df[df.split == "test"].sort_values("p_exploit", ascending=False).head(8)
    return {"total": int(len(df)), "positives": int(df.label.sum()), "rate": float(100 * df.label.mean()),
            "splits": [{"split": k, "n": int(v.n), "pos": int(v.pos),
                        "range": {"train": f"≤ {d['train_end']}", "val": f"{d['train_end']} → {d['val_end']}",
                                  "test": f"> {d['val_end']}"}[k]} for k, v in sp.iterrows()],
            "by_year": by_year.round(2).to_dict("records"), "by_cvss": cv.round(2).to_dict("records"),
            "download_date": d["download_date"], "label_window": d["label_window_days"],
            "sample": [{"cve_id": r.cve_id, "product": r.product, "cvss": float(r.cvss), "epss": round(float(r.epss), 3),
                        "p_exploit": round(float(r.p_exploit), 3), "label": int(r.label)} for r in sample.itertuples()],
            "features": ["CVSS vector (one-hot)", f"Top-{cfg['model']['top_cwe']} CWE categories",
                         "Vendor / product frequency", f"TF-IDF description terms ({cfg['model']['tfidf_terms']})",
                         "Reference count"]}


def api_compare(_):
    return {"curves": pd.read_csv(RES / "budget_curves.csv").to_dict("records"),
            "summary": pd.read_csv(RES / "backtest_summary.csv").to_dict("records"),
            "n_inventories": int(pd.read_csv(RES / "backtest_runs.csv").inventory.nunique())}


def api_whatif(_):
    return {"extended": pd.read_csv(RES / "extended_summary.csv").to_dict("records"),
            "robust": pd.read_csv(RES / "robust_summary.csv").to_dict("records"),
            "gamma": cfg["optimize"]["attack_path_gamma"]}


def api_pareto(q):
    pop, gens, pct = int(q1(q, "pop", "60")), int(q1(q, "gens", "60")), float(q1(q, "pct", "20"))
    snaps, inv = [], INV
    t0 = time.time()
    ext = q1(q, "ext", "0") == "1"

    def cb(g, fr):
        if g % 4 == 0 or g == gens - 1:
            snaps.append({"gen": g + 1, "cost_pct": (100 * fr[2] / inv.T).round(2).tolist(), "risk": fr[1].round(2).tolist()})

    pb = Problem(inv.patches, 0.4 * inv.T, cfg["optimize"]["downtime_fraction"] * inv.D)
    if ext:
        pb.set_ext(inv.ext)
    fr = select_nsga2(pb, pop, gens, seed=cfg["seed"], callback=cb)
    rt = time.time() - t0
    xb = pick_from_front(fr, pct / 100 * inv.T)
    P = inv.patches
    ilp_x = solve(inv, "ml_ilp", pct, cfg["optimize"]["downtime_fraction"], True, False)[0]
    if ext:
        got, ilp = float(ext_benefit(xb, inv.ext)[0]), float(ext_benefit(ilp_x, inv.ext)[0])
        total = float(ext_benefit(np.ones(len(xb), bool), inv.ext)[0])
    else:
        got, ilp, total = float(P.benefit.to_numpy()[xb].sum()), float(P.benefit.to_numpy()[ilp_x].sum()), inv.total_risk
    return {"snapshots": snaps, "runtime_s": rt, "selected": got, "ilp": ilp, "gap_pct": 100 * (ilp - got) / ilp,
            "selected_cost_pct": float(100 * P.cost.to_numpy()[xb].sum() / inv.T),
            "total": total, "pct": pct, "ext": ext, "pop": pop, "gens": gens}


def api_inventory(q):
    global INV
    seed, n = int(q1(q, "seed", str(cfg["seed"]))), q1(q, "hosts", "")
    with LOCK:
        INV = make_inventory(seed, int(n) if n else None)
    return api_meta({})


def api_meta(_):
    inv = INV
    mm = json.load(open(RES / "model_metrics.json"))["_meta"]
    return {"source": inv.source, "name": inv.name, "report": inv.report, "seed": inv.seed, "hosts": len(inv.hosts), "patches": len(inv.patches), "total_cost": inv.T,
            "total_risk": inv.total_risk, "total_exploited": inv.total_exploited,
            "dependencies": int((inv.patches.requires >= 0).sum()), "model": mm,
            "downtime_default": cfg["optimize"]["downtime_fraction"] * 100,
            "weights": cfg["network"]["exposure_weight"], "cost_ratio": cfg["model"]["cost_fn"],
            "gamma": cfg["optimize"]["attack_path_gamma"]}


ROUTES = {"/api/meta": api_meta, "/api/plan": api_plan, "/api/strategies": api_strategies, "/api/patch": api_patch,
          "/api/host": api_host, "/api/cves": api_cves, "/api/cve": api_cve, "/api/threshold": api_threshold,
          "/api/model": api_model, "/api/data": api_data, "/api/compare": api_compare, "/api/whatif": api_whatif,
          "/api/pareto": api_pareto, "/api/inventory": api_inventory}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        try:
            if u.path in ROUTES:
                with LOCK:
                    out = ROUTES[u.path](parse_qs(u.query))
                self._send(200, json.dumps(out).encode(), "application/json")
                return
            rel = "index.html" if u.path in ("/", "") else u.path.lstrip("/")
            f = (WEB / rel).resolve()
            if WEB.resolve() not in f.parents or not f.is_file():
                self._send(404, b"not found", "text/plain")
                return
            ct = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
            self._send(200, f.read_bytes(), ct + ("; charset=utf-8" if ct.startswith(("text", "application/javascript")) else ""))
        except Exception as e:
            self._send(500, json.dumps({"error": f"{type(e).__name__}: {e}"}).encode(), "application/json")

    def do_POST(self):
        u = urlparse(self.path)
        try:
            n = int(self.headers.get("Content-Length", 0))
            if u.path != "/api/upload":
                self._send(404, b"not found", "text/plain")
                return
            if n > 8_000_000:
                raise ValueError("File too large (limit 8 MB).")
            with LOCK:
                out = api_upload(json.loads(self.rfile.read(n) or b"{}"))
            self._send(200, json.dumps(out).encode(), "application/json")
        except Exception as e:
            self._send(400, json.dumps({"error": f"{type(e).__name__}: {e}" if not isinstance(e, ValueError) else str(e)}).encode(), "application/json")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(next((a for a in sys.argv[1:] if a.isdigit()), 8000))
    host = sys.argv[sys.argv.index("--host") + 1] if "--host" in sys.argv else "127.0.0.1"   # 0.0.0.0 = reachable from other devices
    class Server(ThreadingHTTPServer):
        # HTTPServer sets SO_REUSEADDR, which on Windows lets a second server silently bind a port that is
        # already in use; requests are then split between the two. Claim the port exclusively instead.
        allow_reuse_address = sys.platform != "win32"

        def server_bind(self):
            if sys.platform == "win32":
                import socket
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            super().server_bind()

    try:
        srv = Server((host, port), Handler)
    except OSError as e:
        sys.exit(f"Port {port} is already in use ({e}). Stop the other server or pass a different port.")
    # 127.0.0.1, not "localhost": localhost resolves to ::1 first and may reach a different app on that port.
    url = f"http://{'127.0.0.1' if host in ('127.0.0.1', '0.0.0.0') else host}:{port}"
    print(f"Demo running at {url}  (Ctrl+C to stop)", flush=True)
    if "--no-browser" not in sys.argv:
        webbrowser.open(url)
    srv.serve_forever()
