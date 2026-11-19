"""Convert exploit_model_training.py (percent format) into a Jupyter/Colab notebook.
Usage: python notebooks/make_ipynb.py
"""
import json
import re
from pathlib import Path

KEEP_TEXT = False          # True would keep the markdown explanation cells
here = Path(__file__).resolve().parent
src = (here / "exploit_model_training.py").read_text(encoding="utf-8")
chunks = re.split(r"^# %%(?: \[markdown\])?\n", src, flags=re.M)
heads = re.findall(r"^# %%( \[markdown\])?\n", src, flags=re.M)
TITLE = ("# Model Training - Exploit-Aware Vulnerability Prioritization\n"
         "**Cost-Sensitive, Exploit-Aware Vulnerability Prioritization (IS353IA)**  \n"
         "Madhur Rishi Sikarwar (1RV24IS067) - Mayur M Deekshith (1RV24IS069)")
cells = [{"cell_type": "markdown", "metadata": {}, "source": TITLE.splitlines(True)}]
for head, body in zip(heads, chunks[1:]):
    body = body.rstrip("\n")
    if head:
        if not KEEP_TEXT:      # notebook is code-only; the explanations live in the separate PDF guide
            continue
        text = "\n".join(re.sub(r"^# ?", "", ln) for ln in body.split("\n"))
        cells.append({"cell_type": "markdown", "metadata": {}, "source": text.splitlines(True)})
    else:
        cells.append({"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [],
                      "source": body.splitlines(True)})
nb = {"cells": cells, "nbformat": 4, "nbformat_minor": 5,
      "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
                   "language_info": {"name": "python"}, "colab": {"provenance": []}}}
out = here / "exploit_model_training.ipynb"
out.write_text(json.dumps(nb, indent=1), encoding="utf-8")
print(f"wrote {out} with {len(cells)} cells")
