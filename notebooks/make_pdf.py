"""Builds 'How_to_explain_the_notebook.pdf' (presenter guide for exploit_model_training.ipynb).
Usage: python notebooks/make_pdf.py
"""
from pathlib import Path
from fpdf import FPDF

HERE = Path(__file__).resolve().parent
FONTS = Path("C:/Windows/Fonts")
INK, MUT, ACC, AMB, SOFT = (28, 36, 48), (100, 110, 122), (11, 122, 108), (176, 112, 26), (232, 244, 241)


class Guide(FPDF):
    def footer(self):
        self.set_y(-12)
        self.set_font("body", "", 8)
        self.set_text_color(*MUT)
        self.cell(0, 6, f"Presenter guide - exploit_model_training.ipynb      page {self.page_no()}", align="C")


pdf = Guide(format="A4")
pdf.set_margins(18, 16, 18)
pdf.set_auto_page_break(True, 16)
pdf.add_font("body", "", str(FONTS / "arial.ttf"))
pdf.add_font("body", "B", str(FONTS / "arialbd.ttf"))
pdf.add_font("body", "I", str(FONTS / "ariali.ttf"))
pdf.add_font("code", "", str(FONTS / "consola.ttf"))
W = pdf.w - pdf.l_margin - pdf.r_margin


def h1(t):
    pdf.add_page() if pdf.get_y() > 200 else None
    pdf.ln(3)
    pdf.set_font("body", "B", 17);  pdf.set_text_color(*ACC)
    pdf.multi_cell(W, 8, t, new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(*ACC);  pdf.set_line_width(0.5)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + 40, pdf.get_y());  pdf.ln(3)


def h2(t):
    if pdf.get_y() > 245:
        pdf.add_page()
    pdf.ln(2)
    pdf.set_font("body", "B", 12.5);  pdf.set_text_color(*INK)
    pdf.multi_cell(W, 6.5, t, new_x="LMARGIN", new_y="NEXT");  pdf.ln(0.5)


def label(t, color=AMB):
    pdf.set_font("body", "B", 8.5);  pdf.set_text_color(*color)
    pdf.cell(0, 5, t.upper(), new_x="LMARGIN", new_y="NEXT")


def p(t, size=10.5, italic=False, color=INK):
    pdf.set_font("body", "I" if italic else "", size);  pdf.set_text_color(*color)
    pdf.multi_cell(W, 5.4, t, new_x="LMARGIN", new_y="NEXT");  pdf.ln(1)


def bullets(items, size=10.5):
    pdf.set_font("body", "", size);  pdf.set_text_color(*INK)
    for it in items:
        pdf.set_x(pdf.l_margin + 4)
        pdf.multi_cell(W - 4, 5.4, "-  " + it, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)


def box(t, color=SOFT, size=10.5, title=None):
    pdf.set_fill_color(*color);  pdf.set_text_color(*INK)
    if title:
        pdf.set_font("body", "B", 9);  pdf.set_text_color(*ACC)
        pdf.multi_cell(W, 6, "  " + title.upper(), fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("body", "", size);  pdf.set_text_color(*INK)
    pdf.multi_cell(W, 5.6, t, fill=True, new_x="LMARGIN", new_y="NEXT", padding=(2, 3, 2, 3));  pdf.ln(2)


def code(t):
    pdf.set_font("code", "", 9);  pdf.set_fill_color(242, 244, 246);  pdf.set_text_color(40, 50, 60)
    pdf.multi_cell(W, 4.8, t, fill=True, new_x="LMARGIN", new_y="NEXT", padding=(2, 3, 2, 3));  pdf.ln(2)


def cell_block(n, title, what, say, point, ask=None):
    h2(f"Cell {n}  -  {title}")
    label("What it does", ACC);  p(what)
    label("Say this");  p(say, italic=True)
    label("Point at", ACC);  p(point)
    if ask:
        label("If asked", MUT);  p(ask, color=MUT)


# ------------------------------------------------------------------ cover
pdf.add_page()
pdf.set_font("body", "B", 24);  pdf.set_text_color(*ACC)
pdf.multi_cell(W, 11, "How to explain the notebook", new_x="LMARGIN", new_y="NEXT")
pdf.set_font("body", "", 13);  pdf.set_text_color(*MUT)
pdf.multi_cell(W, 7, "exploit_model_training.ipynb  -  presenter guide", new_x="LMARGIN", new_y="NEXT");  pdf.ln(4)
p("Cost-Sensitive, Exploit-Aware Vulnerability Prioritization (IS353IA)\nMadhur Rishi Sikarwar (1RV24IS067)  -  Mayur M Deekshith (1RV24IS069)", 10.5, color=MUT)
pdf.ln(2)
box("The notebook is code only on purpose: the explanations are in this guide, so you talk while the cells run.\n"
    "Run it top to bottom (Kernel > Restart & Run All, about one minute). The LAST cell is interactive: it asks you "
    "for a CVE, then prints the probability and the step-by-step calculation.\n"
    "Cell numbers in this guide count code cells only (the title cell at the very top is not counted).", title="How to use this guide")
h1("1.  The 30-second opening")
p("\"Teams cannot patch every vulnerability. The usual shortcut is to sort by CVSS severity, but CVSS says how bad a flaw could be, "
  "not how likely it is to be attacked, and only about 1-2% of CVEs are ever exploited. This notebook is the machine-learning half of "
  "our system: it trains a model that predicts, for every CVE, the probability that it will be exploited. That probability is the only "
  "thing our patch optimiser needs from the model.\"", italic=True)
p("Then say the plan out loud, in this order:")
bullets(["Build the data and label it (exploited within a year = 1).", "Split by date, never randomly.",
         "Build features known at publication time.", "Train four models with class weights.",
         "Calibrate the scores into real probabilities.", "Choose a cost-sensitive threshold.",
         "Evaluate against CVSS-only and EPSS.", "Finale: type a CVE and see exactly how its score is calculated."])
box("The CVE data in this prototype is SYNTHETIC: it has the real fields (CVSS vector, CWE, product, description, KEV date, EPSS) but is "
    "generated by our own code. So the notebook proves the training method works - it does not prove real-world accuracy. Say this "
    "early; it protects you from every awkward question later.", color=(251, 241, 217), title="Say this up front")

# ------------------------------------------------------------------ cells
h1("2.  Cell-by-cell script")
cell_block(0, "Imports and settings",
           "Loads numpy, pandas and scikit-learn and defines one settings dictionary (CFG): dataset size, dates for the split, the 50:1 cost ratio, "
           "number of trees, number of text features.",
           "Everything tunable is in one place, and the random seed is fixed at 42 so every run gives the same numbers.",
           "CFG: train_end 2021-12-31, val_end 2022-12-31, cost_fn=50, cost_fp=1.")
cell_block(1, "Build the dataset",
           "Creates 15,000 CVEs with the same fields as NVD + CISA KEV + EPSS: CVSS v3 vector, weakness type (CWE), product, description, reference "
           "count, publish date, KEV date and EPSS. It implements the real CVSS v3.1 base-score formula. A hidden 'true' exploit probability depends on "
           "observable features, and the label is built from it.",
           "We cannot download real NVD/KEV here, so we generate a stand-in with the same columns. The label rule is the one from our synopsis: a CVE is 1 "
           "if it is added to KEV within 365 days of publication. We also drop CVEs younger than 12 months at the download date, because they have not "
           "had a full year to be added (that is censoring).",
           "The printed line: 15,000 CVEs with a positive rate of 1.83% - the severe class imbalance.",
           "Why synthetic? Real data is the main Phase 3 task; the code only needs a DataFrame with the same columns (see section 6).")
cell_block(2, "Time-based split",
           "Splits by publication date: train up to 2021, validation 2022, test 2023 onwards. Prints counts and exploit rates.",
           "We split by date, not randomly. A random split would let the model learn from CVEs published after the ones it is tested on - that is future "
           "leakage and would inflate every metric. Train fits the models, validation calibrates and picks the threshold, test is touched only at the end.",
           "Table: train 7,418 CVEs, validation 2,480, test 5,102 with 88 later-exploited CVEs (rate about 1.7%).")
cell_block(3, "Feature engineering",
           "A Featurizer class turns each CVE into 146 numbers: the CVSS vector one-hot encoded, the CVSS score, the 20 most common weakness types, "
           "vendor and product frequency, 100 TF-IDF word features from the description, and the reference count.",
           "Only information known on the publication date is used. The word list, the CWE list and the frequencies are learned from the training period only, "
           "so nothing leaks from later data. EPSS and KEV status are never features: EPSS is a competing baseline and KEV is the label.",
           "The printed feature matrix shape (15000, 146).")
cell_block(4, "Train the four models",
           "Trains logistic regression, a decision tree, a random forest (200 trees) and gradient boosting, all with balanced class weights.",
           "Only about 1.8% of CVEs are positive, so we weight the rare exploited class more heavily - that is the first half of 'cost-sensitive'. "
           "The random forest is our main model; the decision tree is there because its rules can be read; logistic regression is the simple baseline; "
           "gradient boosting is a stronger boosted-tree stand-in for XGBoost.",
           "The four 'trained ...' lines. Mention the hyper-parameters were set by hand: no search, no cross-validation.",
           "Why not deep learning? Tabular data with about 150 features and a few hundred positives suits tree models; deep nets would overfit and be hard to explain.")
cell_block(5, "Calibration",
           "Fits isotonic regression on the validation period to map each model's raw score to a real probability, then prints the Brier score before "
           "and after on the test period.",
           "Balanced class weights push raw scores far above the true rate: a forest score of 0.3 does not mean 30%. Our optimiser multiplies this number by "
           "impact, criticality and exposure, so it must be a real probability. Isotonic regression learns a monotone step mapping from validation data.",
           "Brier table: random forest 0.0233 raw -> 0.0164 calibrated (lower is better).",
           "Why isotonic and not Platt scaling? It makes no shape assumption and we have enough validation data; the synopsis cites Niculescu-Mizil & Caruana.")
cell_block(6, "Cost-sensitive threshold",
           "Defines best_threshold(), which picks the cut-off that minimises 50 x missed-exploits + 1 x false-alarms on the validation set, and prints a table "
           "for cost ratios 10, 25, 50, 100 and 200 to 1.",
           "A missed exploited CVE is far worse than a false alarm. Instead of the default 0.5 cut-off, we choose the one that minimises expected cost "
           "(Elkan, 2001). With calibrated probabilities the answer is close to 1/(1+50), about 2-4%.",
           "Read across a row: higher ratio -> lower threshold -> more flagged, more caught, fewer missed, but more false alarms.")
cell_block(7, "Evaluate on the test period",
           "Computes PR-AUC and recall@100 for each model, for CVSS-only and for the EPSS stand-in.",
           "We use PR-AUC because only 1.7% are positive; accuracy would reward predicting 'never exploited'. Recall@100 asks: of all exploited CVEs, how many "
           "sit in the model's top 100? That is how a patch team uses a ranked list.",
           "Random forest PR-AUC 0.104 and recall@100 14.8% vs CVSS-only 0.046 and 10.2%: we beat CVSS. The EPSS stand-in scores higher (0.214).",
           "Why does EPSS win? Real EPSS uses signals (exploit chatter, telemetry) that NVD fields cannot provide. The synopsis commits to reporting that openly. "
           "Here the stand-in is also built from the hidden truth, so it is stronger by construction.")
cell_block(8, "Plots",
           "Draws the precision-recall curves, a PR-AUC bar chart and the calibration curve. It needs matplotlib; if that is missing the cell just prints a note.",
           "The calibration plot should sit near the diagonal: predicted probability roughly equals observed rate.",
           "The curves for random forest vs CVSS vs EPSS, and the dashed base-rate line.")
cell_block(9, "Explainability",
           "Prints the 12 most important random-forest features and the top levels of the decision tree as readable rules.",
           "The forest leans on whether the flaw is network-reachable, the CVSS score, product popularity and certain description words - the same things an "
           "analyst would use. The tree gives rules a human can challenge.",
           "Top of the importance list and the first few if/else lines of the tree.")
cell_block(10, "The hand-off table",
           "Builds scored_cves: one calibrated probability p_exploit per CVE, and saves it as scored_cves.csv next to the notebook.",
           "This table is the interface between the machine-learning stage and the optimisation stage. The network simulator multiplies p_exploit by impact, "
           "criticality and exposure to get host-level risk, which Greedy, ILP and NSGA-II then use to choose patches.",
           "The ten highest-scored test CVEs.")
cell_block(11, "The explain function (no output)",
           "Defines explain_cve(), which scores one CVE and prints the seven calculation steps. This cell produces no output.",
           "This is the engine for the finale; it just defines the function.", "Nothing to show - move straight to the last cell.")

# ------------------------------------------------------------------ finale
h1("3.  The live finale: the last cell (cell 12)")
p("Scroll to the last cell and run it. It prints example CVE ids and asks for input. Type into the box that appears under the cell, then press Enter.")
box("1.  Press Enter on the first question to accept the default (the highest-scored CVE).\n"
    "2.  Run the cell again and type one of the 'lowest scored' ids it printed - to contrast.\n"
    "3.  Run it again, type NEW and describe a CVE of your own. Pressing Enter on every question gives a Log4Shell-style remote-code-execution flaw.\n"
    "4.  For a low-risk contrast, type NEW and enter: product zlib, vector L, complexity H, privileges H, interaction R, scope U, impact N / N / L, CWE 400, 2 references.",
    title="What to type")
h2("How to read the output (the seven steps)")
p("Use the real numbers from the default run (CVE-2023-10502, a Chrome flaw):")
bullets([
    "Result line: model exploit probability 10.2% and the decision 'patch candidate'. CVSS shows 8.6, so the model and CVSS are two different views.",
    "Step 1 - CVSS: the real CVSS v3.1 formula. Exploitability = 8.22 x AV x AC x PR x UI; impact comes from C/I/A; base score is their rounded-up sum. This number is one of the model's inputs.",
    "Step 2 - Features: the CVE becomes 146 numbers (24 non-zero here). The list shows the active ones that the forest relies on most, e.g. network attack vector, CVSS score, product popularity, certain words.",
    "Step 3 - Random forest: 200 decision trees each output a probability. In this example 61 trees say 50%+ and 139 say under 5%; the average, 0.278, is the raw score.",
    "Step 4 - Calibration: raw scores between about 0.27 and 0.73 were exploited 10.2% of the time in validation data, so raw 0.278 becomes 10.2%. This is why the output is a real probability.",
    "Step 5 - Decision: expected cost of ignoring it is 50 x 0.102 = 5.09; expected cost of patching it is 1 x 0.898 = 0.90. Ignoring costs far more, so it is flagged. The learned threshold is 3.7%.",
    "Step 6 - Rank: top 4.6% of all 15,000 CVEs.",
    "Step 7 - Breakdown: each feature group is swapped for values from 80 real CVEs and the change in raw score is measured. Plus means that group pushes the risk up, minus pushes it down. "
    "Here the CVSS vector, product popularity and wording push it up.",
])
box("Step 7 is a simple SHAP-like method (group marginalisation), not exact SHAP. Real SHAP values are listed as a Phase 3 upgrade. The raw forest scores in steps 3-4 are "
    "deliberately inflated by the class weights; that is the reason calibration exists.", color=(251, 241, 217), title="Be precise about")
box("\"Same CVE, two views: CVSS says 8.6 out of 10. Our model says a 10% chance of exploitation - which is about six times the average CVE, and above our 3.7% "
    "patch threshold. Here is exactly how: the CVSS formula, 146 features, 200 trees voting, a calibration step, and a cost comparison.\"", color=SOFT, title="One-line takeaway")

# ------------------------------------------------------------------ numbers
h1("4.  Numbers to remember (fixed seed 42, synthetic data)")
bullets(["Dataset: 15,000 CVEs, positive rate 1.83%. Features: 146.",
         "Split: train 7,418 (146 positives)  -  validation 2,480 (40)  -  test 5,102 (88).",
         "PR-AUC on test: EPSS stand-in 0.214, random forest 0.104, gradient boosting 0.092, logistic regression 0.091, CVSS-only 0.046, decision tree 0.036.",
         "Recall@100: EPSS stand-in 25.0%, gradient boosting 15.9%, random forest 14.8%, logistic regression 14.8%, CVSS-only 10.2%, decision tree 2.3%.",
         "Brier score (test): random forest 0.0233 raw -> 0.0164 calibrated; all four models end near 0.0165 after calibration.",
         "Cost ratio 50:1 gives a learned threshold of about 3.7% on the calibrated random-forest probability.",
         "Random baseline for PR-AUC equals the base rate, about 0.017."])

# ------------------------------------------------------------------ Q&A
h1("5.  Questions you may get - and answers")
qa = [
    ("Why not a random train/test split?", "Because CVEs published later would leak into training. Real use is always 'predict the future from the past', so we split by date."),
    ("Why class weights AND a threshold - isn't that double counting?", "They do different jobs. Class weights change how the model learns from a rare class. The threshold decides what to do with a finished probability, using the real costs of each error."),
    ("Why calibrate?", "The optimiser multiplies p_exploit by impact, criticality and exposure, so the value must act as a probability, not just a ranking. Raw scores from a class-weighted forest are inflated."),
    ("Why PR-AUC and not accuracy or ROC-AUC?", "With about 1.7% positives, accuracy is 98% for a model that never flags anything. PR-AUC focuses on the rare class (Saito & Rehmsmeier)."),
    ("Your model loses to EPSS. Is that a problem?", "It is expected and reported. EPSS uses richer signals than NVD fields; here the stand-in is also derived from the hidden truth. The claim is that we beat CVSS-only and that our value is the budgeted selection that follows."),
    ("Is the data real?", "No - synthetic with the real schema, so the pipeline can be shown offline. Real NVD, KEV and EPSS downloads and a retrain are the first Phase 3 item."),
    ("Is this overfitting?", "Test data is a later period never used for fitting, calibration or the threshold. Hyper-parameters were not tuned, so there is little to overfit to. With only 88 test positives the numbers still have wide error bars."),
    ("Why random forest as the main model?", "Strong on tabular data, handles mixed features, gives feature importances and, with calibration, usable probabilities. The tree is kept for interpretability."),
    ("How does this connect to the optimiser?", "scored_cves gives p_exploit; the simulator turns it into host-level risk = p_exploit x impact x criticality x exposure weight; Greedy, ILP and NSGA-II then choose patches under budget, downtime and dependency limits."),
    ("How exactly is the score 'calculated'?", "200 trees each give a probability; the mean is the raw score; isotonic regression maps it to a calibrated probability; a cost comparison against the learned threshold gives the decision. The breakdown measures how much each feature group moves the raw score."),
]
for q, a in qa:
    h2(q)
    p(a)

# ------------------------------------------------------------------ limits + real data
h1("6.  Limits, and how to use real data")
bullets(["Synthetic data: the notebook shows the method, not real-world performance.",
         "Hyper-parameters are hand-set; there is no cross-validation or search.",
         "The explanation in step 7 is group marginalisation, not exact SHAP.",
         "Only 88 positives in the test period, so small differences between models are not statistically meaningful.",
         "KEV is biased toward US-government-relevant and widely deployed software, so a CVE missing from KEV may still have been exploited."])
box("Replace the 'df = generate(CFG)' line in cell 1 with a DataFrame that has one row per CVE and these columns: cve_id, published, description, n_refs, cwe, product, "
    "vendor, ptype (from NVD); av, ac, pr, ui, scope, c, i, a, cvss (CVSS v3 metric letters and score, from NVD); kev_date (empty if never listed, from CISA KEV); "
    "epss (value as of the backtest cutoff, baseline only). Recompute the label with the 365-day rule, apply the 12-month censoring rule, and run the remaining cells unchanged.",
    title="Using real data (Phase 3)")

out = HERE / "How_to_explain_the_notebook.pdf"
pdf.output(str(out))
print("wrote", out, "pages:", pdf.page_no())
