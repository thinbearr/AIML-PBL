"""Stage 1-2: synthetic stand-in for NVD + CISA KEV + EPSS.

PROTOTYPE NOTE: no network access / real downloads are used. The generator mimics the
fields named in the synopsis (CVSS v3 vector, CWE, product, description, references,
publish date, KEV date, EPSS) so every later stage runs unchanged when real data is
dropped into data/raw. Exploitation is driven by a hidden latent risk, so results on
this data demonstrate that the PIPELINE works, not real-world performance.
"""
import numpy as np
import pandas as pd
from common import load_config, ensure_dirs, RAW

# (product, vendor, type, popularity)
PRODUCTS = [
    ("windows_server", "microsoft", "os", 9), ("windows_10", "microsoft", "os", 9),
    ("ubuntu_linux", "canonical", "os", 6), ("rhel", "redhat", "os", 5),
    ("macos", "apple", "os", 3), ("apache_http", "apache", "server", 6),
    ("nginx", "f5", "server", 5), ("iis", "microsoft", "server", 5),
    ("tomcat", "apache", "server", 4), ("exchange_server", "microsoft", "server", 5),
    ("mysql", "oracle", "database", 4), ("postgresql", "postgresql", "database", 3),
    ("mssql", "microsoft", "database", 4), ("oracle_db", "oracle", "database", 3),
    ("mongodb", "mongodb", "database", 2), ("chrome", "google", "browser", 8),
    ("firefox", "mozilla", "browser", 5), ("edge", "microsoft", "browser", 5),
    ("openssl", "openssl", "library", 6), ("log4j", "apache", "library", 4),
    ("zlib", "zlib", "library", 2), ("curl", "haxx", "library", 3),
    ("glibc", "gnu", "library", 3), ("fortios", "fortinet", "network", 5),
    ("cisco_ios", "cisco", "network", 6), ("pan_os", "paloalto", "network", 3),
    ("junos", "juniper", "network", 3), ("vmware_esxi", "vmware", "app", 4),
    ("wordpress", "automattic", "app", 6), ("jenkins", "jenkins", "app", 4),
    ("confluence", "atlassian", "app", 3), ("gitlab", "gitlab", "app", 3),
    ("adobe_reader", "adobe", "app", 4), ("office", "microsoft", "app", 6),
    ("sharepoint", "microsoft", "app", 3), ("citrix_adc", "citrix", "network", 3),
    ("zimbra", "synacor", "app", 2), ("struts", "apache", "library", 2),
    ("php", "php", "server", 4), ("nodejs", "nodejs", "server", 3),
]
CWES = [79, 89, 20, 22, 78, 787, 125, 416, 502, 94, 287, 200, 352, 434, 476, 119,
        798, 862, 863, 400, 611, 918, 190, 77, 269, 306, 732, 601, 59, 295, 310, 312]
HOT_CWE = {787: 0.8, 502: 1.0, 94: 0.9, 78: 0.8, 416: 0.6, 287: 0.5, 22: 0.4, 89: 0.4, 306: 0.6}
PHRASES = {
    "remote code execution": 1.3, "authentication bypass": 0.8, "privilege escalation": 0.5,
    "SQL injection": 0.4, "buffer overflow": 0.5, "path traversal": 0.3,
    "arbitrary file upload": 0.6, "deserialization of untrusted data": 0.9,
    "cross-site scripting": -0.4, "denial of service": -0.6, "information disclosure": -0.4,
    "use after free": 0.4,
}
VECTORS = ["network request", "crafted packet", "malicious document", "HTTP request",
           "local user session", "crafted file", "web interface", "API call"]


def _cvss(av, ac, pr, ui, s, c, i, a):
    AV = pd.Series(av).map({"N": .85, "A": .62, "L": .55, "P": .2}).to_numpy()
    AC = pd.Series(ac).map({"L": .77, "H": .44}).to_numpy()
    ch = np.asarray(s) == "C"
    PR = np.where(ch, pd.Series(pr).map({"N": .85, "L": .68, "H": .5}).to_numpy(),
                  pd.Series(pr).map({"N": .85, "L": .62, "H": .27}).to_numpy())
    UI = pd.Series(ui).map({"N": .85, "R": .62}).to_numpy()
    m = {"H": .56, "L": .22, "N": 0.0}
    C, I, A = (pd.Series(x).map(m).to_numpy() for x in (c, i, a))
    iss = 1 - (1 - C) * (1 - I) * (1 - A)
    imp = np.where(ch, 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15, 6.42 * iss)
    ex = 8.22 * AV * AC * PR * UI
    base = np.where(imp <= 0, 0, np.where(ch, np.minimum(1.08 * (imp + ex), 10), np.minimum(imp + ex, 10)))
    return np.ceil(base * 10) / 10


def _sigmoid(x):
    return 1 / (1 + np.exp(-x))


def generate(cfg=None):
    cfg = cfg or load_config()
    d = cfg["data"]
    rng = np.random.default_rng(cfg["seed"])
    n = d["n_cves"]
    prod_df = pd.DataFrame(PRODUCTS, columns=["product", "vendor", "ptype", "pop"])
    pw = prod_df["pop"].to_numpy(float)
    pidx = rng.choice(len(prod_df), n, p=pw / pw.sum())
    p = prod_df.iloc[pidx].reset_index(drop=True)

    days = (pd.Timestamp(d["end"]) - pd.Timestamp(d["start"])).days
    pub = pd.Timestamp(d["start"]) + pd.to_timedelta(rng.integers(0, days, n), unit="D")

    # network-facing products skew toward AV:N
    netish = p["ptype"].isin(["server", "network", "app", "browser"]).to_numpy()
    av = np.where(rng.random(n) < np.where(netish, .75, .45), "N",
                  rng.choice(["A", "L", "P"], n, p=[.1, .8, .1]))
    ac = rng.choice(["L", "H"], n, p=[.8, .2])
    pr = rng.choice(["N", "L", "H"], n, p=[.55, .35, .10])
    ui = rng.choice(["N", "R"], n, p=[.65, .35])
    s = rng.choice(["U", "C"], n, p=[.8, .2])
    c, i, a = (rng.choice(["H", "L", "N"], n, p=[.4, .35, .25]) for _ in range(3))
    cvss = _cvss(av, ac, pr, ui, s, c, i, a)
    cwe = rng.choice(CWES, n, p=np.linspace(2, 1, len(CWES)) / np.linspace(2, 1, len(CWES)).sum())
    phr_keys = list(PHRASES)
    phr = rng.choice(phr_keys, n)
    vec = rng.choice(VECTORS, n)
    n_refs = rng.poisson(4, n) + 1
    desc = [f"{pn.replace('_', ' ')} before {rng.integers(1, 30)}.{rng.integers(0, 20)} allows attackers to cause "
            f"{ph} via a {v}" for pn, ph, v in zip(p["product"], phr, vec)]

    # hidden latent exploitability (the "truth" the model must learn from observable features)
    z = (1.2 * (av == "N") + 0.7 * (ac == "L") + 0.7 * (pr == "N") + 0.5 * (ui == "N")
         + 0.5 * ((c == "H").astype(int) + (i == "H") + (a == "H")) / 3 * 3 / 3
         + np.array([HOT_CWE.get(w, 0.0) for w in cwe])
         + np.array([PHRASES[k] for k in phr])
         + 0.12 * p["pop"].to_numpy() + 0.1 * np.minimum(n_refs, 8)
         + rng.normal(0, 0.6, n)) * 2.6
    lo, hi = -80, 20
    for _ in range(60):  # tune the intercept to hit the target positive rate
        mid = (lo + hi) / 2
        if _sigmoid(z + mid).mean() > d["target_pos_rate"]:
            hi = mid
        else:
            lo = mid
    p_true = _sigmoid(z + (lo + hi) / 2)
    exploited = rng.random(n) < p_true
    kev_delay = rng.integers(5, 600, n)  # some land after 365d -> label 0 by the window rule
    kev_date = pd.Series(pub + pd.to_timedelta(kev_delay, unit="D")).where(exploited)

    # EPSS stand-in: noisy view of the truth with extra (richer) signal, as in the synopsis.
    epss = _sigmoid(np.log(p_true / (1 - p_true)) + rng.normal(0, 1.0, n))

    df = pd.DataFrame({
        "cve_id": [f"CVE-{y}-{k:05d}" for y, k in zip(pub.year, rng.permutation(n) + 1000)],
        "published": pub, "product": p["product"], "vendor": p["vendor"], "ptype": p["ptype"],
        "av": av, "ac": ac, "pr": pr, "ui": ui, "scope": s, "c": c, "i": i, "a": a,
        "cvss": cvss, "cwe": cwe, "n_refs": n_refs, "description": desc,
        "kev_date": kev_date, "epss": epss,
    })
    # Label rule: 1 if added to KEV within 365 days of publication (synopsis Sec. 5.2)
    df["label"] = ((df["kev_date"] - df["published"]).dt.days <= d["label_window_days"]).fillna(False).astype(int)
    # Censoring: keep only CVEs published >= 12 months before download date
    cutoff = pd.Timestamp(d["download_date"]) - pd.Timedelta(days=365)
    df = df[df["published"] <= cutoff].sort_values("published").reset_index(drop=True)
    return df


def main():
    ensure_dirs()
    cfg = load_config()
    df = generate(cfg)
    df.to_parquet(RAW / "cves_synthetic.parquet", index=False)
    dd = pd.DataFrame({"column": df.columns, "dtype": df.dtypes.astype(str).values})
    dd.to_csv(RAW / "data_dictionary.csv", index=False)
    print(f"[data] {len(df)} synthetic CVEs, positive rate {df.label.mean():.2%} -> {RAW}")


if __name__ == "__main__":
    main()
