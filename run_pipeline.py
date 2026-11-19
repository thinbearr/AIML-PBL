"""One-command pipeline:  python run_pipeline.py   (then: python server.py)"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
import data_synth, model, simulate, evaluate  # noqa: E402

for name, mod in [("1/4 data", data_synth), ("2/4 model", model), ("3/4 simulate", simulate), ("4/4 evaluate", evaluate)]:
    t = time.time()
    print(f"\n=== {name} ===")
    mod.main()
    print(f"({time.time() - t:.1f}s)")
