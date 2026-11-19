"""Stage 3: cost-sensitive, calibrated exploit-probability models (synopsis Sec. 5.3.1)."""
import json
import joblib
import numpy as np
import pandas as pd
from scipy import sparse  # noqa: F401
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss
from sklearn.tree import DecisionTreeClassifier, export_text
from common import load_config, ensure_dirs, RAW, PROC, RES

CAT = ["av", "ac", "pr", "ui", "scope", "c", "i", "a"]


def split_masks(df, cfg):
    d = cfg["data"]
    tr = df["published"] <= pd.Timestamp(d["train_end"])
    va = (df["published"] > pd.Timestamp(d["train_end"])) & (df["published"] <= pd.Timestamp(d["val_end"]))
    te = df["published"] > pd.Timestamp(d["val_end"])
    return tr, va, te


class Featurizer:
    """Only publication-time information; statistics are fitted on the training period."""

    def fit(self, df, cfg):
        m = cfg["model"]
        self.top_cwe = df["cwe"].value_counts().head(m["top_cwe"]).index.tolist()
        self.vendor_f = df["vendor"].value_counts(normalize=True).to_dict()
        self.prod_f = df["product"].value_counts(normalize=True).to_dict()
        self.tfidf = TfidfVectorizer(max_features=m["tfidf_terms"], stop_words="english").fit(df["description"])
        self.cols = list(self.transform(df).columns)
        return self

    def transform(self, df):
        parts = [pd.get_dummies(df[CAT].astype(str), dtype=float).reset_index(drop=True)]
        extra = {"cvss": df["cvss"].to_numpy(), "vendor_freq": df["vendor"].map(self.vendor_f).fillna(0).to_numpy(),
                 "product_freq": df["product"].map(self.prod_f).fillna(0).to_numpy(), "n_refs": df["n_refs"].to_numpy()}
        for w in self.top_cwe:
            extra[f"cwe_{w}"] = (df["cwe"] == w).astype(float).to_numpy()
        T = self.tfidf.transform(df["description"]).toarray()
        for k, name in enumerate(self.tfidf.get_feature_names_out()):
            extra[f"tf_{name}"] = T[:, k]
        X = pd.concat(parts + [pd.DataFrame(extra)], axis=1)
        X = X.reset_index(drop=True)
        if hasattr(self, "cols"):
            X = X.reindex(columns=self.cols, fill_value=0.0)
        return X


def recall_at_k(y, score, k=100):
    idx = np.argsort(-np.asarray(score), kind="stable")[:k]
    return float(np.asarray(y)[idx].sum() / max(np.asarray(y).sum(), 1))


def best_threshold(y, p, c_fn, c_fp):
    ts = np.unique(np.quantile(p, np.linspace(0, 1, 400)))
    costs = [c_fn * ((p < t) & (y == 1)).sum() + c_fp * ((p >= t) & (y == 0)).sum() for t in ts]
    return float(ts[int(np.argmin(costs))])


def expected_cost(y, p, t, c_fn, c_fp):
    return float(c_fn * ((p < t) & (y == 1)).sum() + c_fp * ((p >= t) & (y == 0)).sum())


def main():
    ensure_dirs()
    cfg = load_config()
    seed = cfg["seed"]
    mc = cfg["model"]
    df = pd.read_parquet(RAW / "cves_synthetic.parquet")
    tr, va, te = split_masks(df, cfg)
    fz = Featurizer().fit(df[tr], cfg)
    X = fz.transform(df)
    y = df["label"].to_numpy()
    Xtr, Xva, Xte = X[tr.to_numpy()], X[va.to_numpy()], X[te.to_numpy()]
    ytr, yva, yte = y[tr], y[va], y[te]

    models = {
        "logreg": LogisticRegression(max_iter=2000, class_weight="balanced", C=0.5),
        "decision_tree": DecisionTreeClassifier(max_depth=mc["dt_depth"], min_samples_leaf=20,
                                                class_weight="balanced", random_state=seed),
        "random_forest": RandomForestClassifier(n_estimators=mc["rf_trees"], min_samples_leaf=mc["rf_min_leaf"],
                                                class_weight="balanced_subsample", n_jobs=-1, random_state=seed),
        "gradient_boosting": HistGradientBoostingClassifier(max_depth=4, learning_rate=0.06, max_iter=200,
                                                            class_weight="balanced", random_state=seed),
    }
    metrics, calibrators, probs = {}, {}, {}
    Xs = X.copy()
    mu, sd = Xtr.mean(), Xtr.std().replace(0, 1)
    for name, mdl in models.items():
        if name == "logreg":
            mdl.fit((Xtr - mu) / sd, ytr)
            raw = mdl.predict_proba((Xs - mu) / sd)[:, 1]
        else:
            mdl.fit(Xtr, ytr)
            raw = mdl.predict_proba(Xs)[:, 1]
        iso = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1).fit(raw[va.to_numpy()], yva)
        cal = np.clip(iso.predict(raw), 1e-5, 1)
        thr = best_threshold(yva, cal[va.to_numpy()], mc["cost_fn"], mc["cost_fp"])
        pte, pte_raw = cal[te.to_numpy()], raw[te.to_numpy()]
        metrics[name] = {
            "pr_auc": float(average_precision_score(yte, pte_raw)),
            "recall@100": recall_at_k(yte, pte_raw, 100),
            "brier_raw": float(brier_score_loss(yte, np.clip(pte_raw, 0, 1))),
            "brier_calibrated": float(brier_score_loss(yte, pte)),
            "threshold": thr,
            "expected_cost": expected_cost(yte, pte, thr, mc["cost_fn"], mc["cost_fp"]),
        }
        calibrators[name], probs[name] = iso, cal

    for name, s in {"cvss_baseline": df["cvss"].to_numpy()[te.to_numpy()],
                    "epss_baseline": df["epss"].to_numpy()[te.to_numpy()]}.items():
        metrics[name] = {"pr_auc": float(average_precision_score(yte, s)), "recall@100": recall_at_k(yte, s, 100)}
    metrics["_meta"] = {"n_train": int(tr.sum()), "n_val": int(va.sum()), "n_test": int(te.sum()),
                        "test_positives": int(yte.sum()), "cost_ratio_fn_fp": f"{mc['cost_fn']}:{mc['cost_fp']}",
                        "data": "SYNTHETIC (prototype)"}

    # cost-ratio sensitivity (synopsis 5.3.1): threshold + expected cost for several FN:FP ratios
    sens = []
    for r in (10, 25, 50, 100, 200):
        t = best_threshold(yva, probs["random_forest"][va.to_numpy()], r, 1)
        sens.append({"fn_fp_ratio": r, "threshold": t,
                     "test_expected_cost": expected_cost(yte, probs["random_forest"][te.to_numpy()], t, r, 1),
                     "test_flagged": int((probs["random_forest"][te.to_numpy()] >= t).sum())})
    pd.DataFrame(sens).to_csv(RES / "cost_sensitivity.csv", index=False)

    scored = df[["cve_id", "published", "product", "vendor", "ptype", "cvss", "epss", "label",
                 "kev_date", "cwe", "description", "c", "i", "a", "av"]].copy()
    scored["p_exploit"] = probs["random_forest"]
    scored["p_decision_tree"] = probs["decision_tree"]
    scored["p_logreg"] = probs["logreg"]
    scored["p_gboost"] = probs["gradient_boosting"]
    scored["split"] = np.where(tr, "train", np.where(va, "val", "test"))
    scored.to_parquet(PROC / "scored_cves.parquet", index=False)

    rf = models["random_forest"]
    imp = pd.DataFrame({"feature": X.columns, "importance": rf.feature_importances_}).sort_values(
        "importance", ascending=False)
    imp.head(25).to_csv(RES / "feature_importance.csv", index=False)
    with open(RES / "decision_tree.txt", "w", encoding="utf-8") as f:
        f.write(export_text(models["decision_tree"], feature_names=list(X.columns), max_depth=4))
    # reliability curve of calibrated RF on test (10 quantile bins)
    pt = probs["random_forest"][te.to_numpy()]
    bins = pd.qcut(pt, 10, duplicates="drop")
    rel = pd.DataFrame({"p": pt, "y": yte}).groupby(bins, observed=True).mean().reset_index(drop=True)
    rel.columns = ["mean_predicted", "observed_rate"]
    rel.to_csv(RES / "calibration_curve.csv", index=False)
    json.dump(metrics, open(RES / "model_metrics.json", "w"), indent=2)
    joblib.dump({"featurizer": fz, "rf": rf, "dt": models["decision_tree"], "iso": calibrators["random_forest"]},
                PROC / "model.joblib")

    print("[model] test-period metrics (SYNTHETIC data)")
    print(pd.DataFrame({k: v for k, v in metrics.items() if k != "_meta"}).T[
        ["pr_auc", "recall@100", "brier_raw", "brier_calibrated", "expected_cost"]].round(4).to_string())


if __name__ == "__main__":
    main()
