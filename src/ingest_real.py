"""Download REAL data: NVD (official API 2.0), CISA KEV and EPSS monthly snapshots.

Resumable: finished NVD windows / EPSS files are skipped on re-run. Only the fields the project needs are kept.
Usage:  python src/ingest_real.py            (optional: set NVD_API_KEY for a faster, higher rate limit)
Sources (official):
  NVD   https://services.nvd.nist.gov/rest/json/cves/2.0
  KEV   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  EPSS  https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz   (FIRST)
"""
import gzip
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REAL = ROOT / "data" / "raw" / "real"
UA = {"User-Agent": "academic-project-ingest/1.0 (IS353IA student project)"}
KEY = os.environ.get("NVD_API_KEY")
SHARDS, SHARD = int(os.environ.get("SHARDS", "1")), int(os.environ.get("SHARD", "0"))
SLEEP = 1.5 if KEY else 6.5           # NVD public limit: 5 requests / 30 s without a key
START, END = date(2019, 1, 1), date(2024, 12, 31)
EPSS_FIRST, EPSS_LAST = date(2023, 1, 1), date(2025, 1, 1)


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def fetch(url, headers=None, tries=6, timeout=120):
    h = dict(UA, **(headers or {}))
    for k in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503):          # rate limited / busy: back off
                wait = 35 * (k + 1)
                log(f"  HTTP {e.code}, waiting {wait}s")
                time.sleep(wait)
            elif e.code == 404:
                return None
            else:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            log(f"  network error {e!r}, retry {k + 1}")
            time.sleep(10 * (k + 1))
    raise RuntimeError(f"giving up on {url}")


def parse_cve(c):
    """Reduce one NVD record to the fields we use. Returns None when there is no CVSS v3 data."""
    cv = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        ms = c.get("metrics", {}).get(key)
        if ms:
            cv = (next((x for x in ms if x.get("type") == "Primary"), ms[0]))["cvssData"]
            break
    if not cv or c.get("vulnStatus") == "Rejected":
        return None
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    cwe = 0
    for w in c.get("weaknesses", []):
        for d in w.get("description", []):
            m = re.match(r"CWE-(\d+)$", d.get("value", ""))
            if m:
                cwe = int(m.group(1))
                break
        if cwe:
            break
    cpes = Counter()

    def walk(nodes):
        for n in nodes:
            for m in n.get("cpeMatch", []):
                if m.get("vulnerable"):
                    p = m["criteria"].split(":")
                    if len(p) > 4:
                        cpes[(p[2], p[3], p[4])] += 1
            walk(n.get("nodes", []))

    for conf in c.get("configurations", []):
        walk(conf.get("nodes", []))
    part, vendor, product = cpes.most_common(1)[0][0] if cpes else ("", "unknown", "unknown")
    return {"id": c["id"], "published": c["published"][:10], "desc": desc, "cvss": cv["baseScore"],
            "av": cv["attackVector"], "ac": cv["attackComplexity"], "pr": cv["privilegesRequired"],
            "ui": cv["userInteraction"], "s": cv["scope"], "c": cv["confidentialityImpact"],
            "i": cv["integrityImpact"], "a": cv["availabilityImpact"], "cwe": cwe,
            "refs": len(c.get("references", [])), "part": part, "vendor": vendor, "product": product}


def nvd_windows():
    d = START
    while d <= END:
        e = min(d + timedelta(days=89), END)
        yield d, e
        d = e + timedelta(days=1)


def download_nvd():
    out = REAL / "nvd"
    out.mkdir(parents=True, exist_ok=True)
    wins = list(nvd_windows())
    for n, (a, b) in enumerate(wins, 1):
        f = out / f"{a}.jsonl"
        if f.exists() or (SHARDS > 1 and n % SHARDS != SHARD):   # SHARDS/SHARD split windows across parallel workers
            continue
        rows, idx, total = [], 0, None
        while total is None or idx < total:
            q = urllib.parse.urlencode({"pubStartDate": f"{a}T00:00:00.000", "pubEndDate": f"{b}T23:59:59.999",
                                        "resultsPerPage": 2000, "startIndex": idx})
            raw = fetch("https://services.nvd.nist.gov/rest/json/cves/2.0?" + q, {"apiKey": KEY} if KEY else None)
            j = json.loads(raw)
            total = j["totalResults"]
            for v in j["vulnerabilities"]:
                r = parse_cve(v["cve"])
                if r:
                    rows.append(r)
            idx += j["resultsPerPage"] if j["resultsPerPage"] else 2000
            time.sleep(SLEEP)
        tmp = f.with_suffix(".tmp")
        tmp.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
        tmp.replace(f)
        log(f"NVD window {n}/{len(wins)} {a}..{b}: {total} CVEs, {len(rows)} with CVSS v3")


def download_kev():
    f = REAL / "kev.json"
    if f.exists():
        log("KEV already present")
        return
    f.write_bytes(fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"))
    log("KEV downloaded")


def download_epss():
    out = REAL / "epss"
    out.mkdir(parents=True, exist_ok=True)
    d = EPSS_FIRST
    while d <= EPSS_LAST:
        f = out / f"epss_{d}.csv.gz"
        if not f.exists():
            raw = fetch(f"https://epss.cyentia.com/epss_scores-{d}.csv.gz")
            if raw is None:
                log(f"EPSS {d}: not available (404)")
            else:
                f.write_bytes(raw)
                log(f"EPSS snapshot {d}: {len(raw) // 1024} KB")
        d = date(d.year + (d.month == 12), d.month % 12 + 1, 1)


if __name__ == "__main__":
    REAL.mkdir(parents=True, exist_ok=True)
    download_kev()
    if os.environ.get("SKIP_EPSS") != "1":
        download_epss()
    download_nvd()
    log("ingest finished")
