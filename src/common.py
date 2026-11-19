from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
PROC = ROOT / "data" / "processed"
RES = ROOT / "results"


def load_config():
    with open(ROOT / "config.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def ensure_dirs():
    for d in (RAW, PROC, RES):
        d.mkdir(parents=True, exist_ok=True)
