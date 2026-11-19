"""Turn the raw downloads (NVD + KEV + EPSS) into data/raw/cves_real.parquet with the project's schema.
Run after src/ingest_real.py:  python src/build_real.py
"""
import gzip
import json
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import RAW, load_config  # noqa: E402
from data_synth import PRODUCTS  # noqa: E402

REAL = RAW / "real"
PTYPE = {p[0]: p[2] for p in PRODUCTS}
ALIAS = {
    ("canonical", "ubuntu_linux"): "ubuntu_linux", ("redhat", "enterprise_linux"): "rhel", ("apple", "macos"): "macos",
    ("apple", "mac_os_x"): "macos", ("apache", "http_server"): "apache_http", ("nginx", "nginx"): "nginx",
    ("f5", "nginx"): "nginx", ("microsoft", "internet_information_services"): "iis", ("microsoft", "iis"): "iis",
    ("apache", "tomcat"): "tomcat", ("microsoft", "exchange_server"): "exchange_server", ("mysql", "mysql"): "mysql",
    ("oracle", "mysql"): "mysql", ("postgresql", "postgresql"): "postgresql", ("microsoft", "sql_server"): "mssql",
    ("oracle", "database_server"): "oracle_db", ("oracle", "database"): "oracle_db", ("mongodb", "mongodb"): "mongodb",
    ("google", "chrome"): "chrome", ("mozilla", "firefox"): "firefox", ("microsoft", "edge"): "edge",
    ("microsoft", "edge_chromium"): "edge", ("openssl", "openssl"): "openssl", ("apache", "log4j"): "log4j",
    ("zlib", "zlib"): "zlib", ("haxx", "curl"): "curl", ("haxx", "libcurl"): "curl", ("gnu", "glibc"): "glibc",
    ("fortinet", "fortios"): "fortios", ("cisco", "ios"): "cisco_ios", ("cisco", "ios_xe"): "cisco_ios",
    ("paloaltonetworks", "pan-os"): "pan_os", ("juniper", "junos"): "junos", ("vmware", "esxi"): "vmware_esxi",
    ("wordpress", "wordpress"): "wordpress", ("automattic", "wordpress"): "wordpress", ("jenkins", "jenkins"): "jenkins",
    ("atlassian", "confluence_server"): "confluence", ("atlassian", "confluence_data_center"): "confluence",
    ("atlassian", "confluence"): "confluence", ("gitlab", "gitlab"): "gitlab", ("adobe", "acrobat_reader"): "adobe_reader",
    ("adobe", "acrobat_reader_dc"): "adobe_reader", ("adobe", "reader"): "adobe_reader", ("microsoft", "office"): "office",
    ("microsoft", "sharepoint_server"): "sharepoint", ("microsoft", "sharepoint_enterprise_server"): "sharepoint",
    ("citrix", "application_delivery_controller"): "citrix_adc", ("citrix", "netscaler_application_delivery_controller"): "citrix_adc",
    ("synacor", "zimbra_collaboration_suite"): "zimbra", ("zimbra", "collaboration"): "zimbra",
    ("zimbra", "zimbra_collaboration_suite"): "zimbra", ("apache", "struts"): "struts", ("php", "php"): "php",
    ("nodejs", "node.js"): "nodejs", ("nodejs", "nodejs"): "nodejs",
}
LET = {"av": {"NETWORK": "N", "ADJACENT_NETWORK": "A", "LOCAL": "L", "PHYSICAL": "P"}, "ac": {"LOW": "L", "HIGH": "H"},
       "pr": {"NONE": "N", "LOW": "L", "HIGH": "H"}, "ui": {"NONE": "N", "REQUIRED": "R"}, "s": {"UNCHANGED": "U", "CHANGED": "C"},
       "cia": {"HIGH": "H", "LOW": "L", "NONE": "N"}}


def canon(vendor, product, part):
    if vendor == "microsoft":
        if product.startswith("windows_server"):
            return "windows_server"
        if re.match(r"windows_(10|11|7|8)", product):
            return "windows_10"
    k = ALIAS.get((vendor, product))
    if k:
        return k
    return product


def ptype_of(product, part):
    if product in PTYPE:
        return PTYPE[product]
    return "os" if part == "o" else "network" if part == "h" else "app"


def main():
    cfg = load_config()
    rows = []
    for f in sorted((REAL / "nvd").glob("*.jsonl")):
        txt = f.read_text(encoding="utf-8").strip()
        rows += [json.loads(l) for l in txt.split("\n") if l]
    nvd = pd.DataFrame(rows).drop_duplicates("id")
    print(f"NVD: {len(nvd):,} CVEs with CVSS v3 ({nvd.published.min()} .. {nvd.published.max()})")

    kev_j = json.loads((REAL / "kev.json").read_text(encoding="utf-8"))
    kev = pd.Series({v["cveID"]: pd.Timestamp(v["dateAdded"]) for v in kev_j["vulnerabilities"]})
    kev_release = pd.Timestamp(kev_j.get("dateReleased", "today")[:10]) if kev_j.get("dateReleased") else pd.Timestamp.today()

    df = pd.DataFrame({
        "cve_id": nvd["id"], "published": pd.to_datetime(nvd["published"]),
        "product": [canon(v, p, pt) for v, p, pt in zip(nvd.vendor, nvd["product"], nvd.part)],
        "vendor": nvd.vendor, "av": nvd.av.map(LET["av"]), "ac": nvd.ac.map(LET["ac"]), "pr": nvd.pr.map(LET["pr"]),
        "ui": nvd.ui.map(LET["ui"]), "scope": nvd.s.map(LET["s"]), "c": nvd.c.map(LET["cia"]), "i": nvd.i.map(LET["cia"]),
        "a": nvd.a.map(LET["cia"]), "cvss": nvd.cvss.astype(float), "cwe": nvd.cwe.astype(int), "n_refs": nvd.refs.astype(int),
        "description": nvd.desc,
    })
    df["ptype"] = [ptype_of(p, pt) for p, pt in zip(df["product"], nvd.part)]
    df = df.dropna(subset=["av", "ac", "pr", "ui", "scope", "c", "i", "a"])
    df["kev_date"] = df["cve_id"].map(kev)
    df["label"] = ((df["kev_date"] - df["published"]).dt.days <= cfg["data"]["label_window_days"]).fillna(False).astype(int)

    # EPSS baseline: first monthly snapshot on/after publication (<= ~30 days after). Only exists for 2023+ CVEs.
    snaps = sorted(REAL.glob("epss/epss_*.csv.gz"))
    dates = np.array([pd.Timestamp(s.name[5:15]) for s in snaps], dtype="datetime64[ns]")
    df["epss"] = 0.0
    if len(snaps):
        which = np.searchsorted(dates, df["published"].to_numpy(dtype="datetime64[ns]"), side="left")
        for k, s in enumerate(snaps):
            m = which == k
            if not m.any():
                continue
            e = pd.read_csv(s, comment="#", compression="gzip").set_index("cve")["epss"]
            df.loc[m, "epss"] = df.loc[m, "cve_id"].map(e).fillna(0.0).to_numpy()
    # censoring: need a full 12 months between publication and the KEV snapshot date
    df = df[df["published"] <= kev_release - pd.Timedelta(days=365)]
    df = df.sort_values("published").reset_index(drop=True)
    out = RAW / "cves_real.parquet"
    df.to_parquet(out, index=False)
    known = df["product"].isin(PTYPE).mean()
    print(f"wrote {out}: {len(df):,} CVEs, exploited (label=1) {df.label.sum():,} = {df.label.mean():.2%}, "
          f"{df['product'].nunique():,} products, {known:.1%} of CVEs map to the 40 enterprise products")
    print(df.groupby(df.published.dt.year).agg(n=("label", "size"), pos=("label", "sum")).to_string())


if __name__ == "__main__":
    main()
