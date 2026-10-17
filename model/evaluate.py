#!/usr/bin/env python3
"""
Scamouflage — model/evaluate.py  (owner: Vaishnavi)       MODEL_SPEC §6.4

Scores the held-out 20% test set (and test_future.csv if present) with the trained Stage 1 model.
These are the honest numbers for the documentation: the model never saw these names.

    ~/snapml-venv/bin/python model/evaluate.py

Writes reports/stage1_eval.json and reports/stage1_eval.md

What is measured = what the live system does WITHOUT certificates and WITHOUT Stage 0/3:
    flagged  <=>  passes the brand gate  AND  Stage 1 score >= T_high
(Stage 0 is left out on purpose: test scams are on the known list, so using it would be cheating.
 Stage 2 needs certificates and Stage 3 needs live lookups, so they only ever add on top of this.)
"""
import csv
import json
import os
import sys
import time
from collections import defaultdict

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from model import features as F  # noqa: E402
from model.stage1 import Stage1, _default_dir  # noqa: E402

DATA = os.path.join(ROOT, "data")
REPORTS = os.path.join(ROOT, "reports")
FOCUS = ("toll", "delivery", "gov")


def read_rows(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def pct(x):
    return f"{x:.1%}"


def evaluate(rows, s1, th):
    from sklearn.metrics import average_precision_score, roc_auc_score
    y = np.array([int(r["label"]) for r in rows])
    cats = np.array([r["category"] for r in rows])
    gate = np.array([F.brand_gate(r["host"])[0] for r in rows])
    s = np.array(s1)
    high = gate & (s >= th["t_high"])
    maybe = gate & (s >= th["t_low"]) & ~high

    def prf(pred, mask=None):
        m = np.ones(len(y), bool) if mask is None else mask
        tp = int((pred & (y == 1) & m).sum())
        fp = int((pred & (y == 0) & m).sum())
        fn = int((~pred & (y == 1) & m).sum())
        return {"tp": tp, "fp": fp, "fn": fn,
                "precision": tp / (tp + fp) if tp + fp else 0.0,
                "recall": tp / (tp + fn) if tp + fn else 0.0}

    out = {"rows": len(rows), "scam": int(y.sum()), "normal": int((y == 0).sum())}
    if 0 < y.sum() < len(y):
        out["pr_auc"] = round(float(average_precision_score(y, s)), 4)
        out["roc_auc"] = round(float(roc_auc_score(y, s)), 4)
    out["system_at_t_high"] = prf(high)
    out["system_at_t_low"] = prf(high | maybe)
    out["baseline_brand_word_rule"] = prf(gate)          # "brand word present -> scam"
    out["by_category_recall_at_t_high"] = {}
    for c in sorted(set(cats[y == 1])):
        m = (cats == c) & (y == 1)
        out["by_category_recall_at_t_high"][c] = {"n": int(m.sum()), "recall": round(float(high[m].mean()), 4),
                                                   "recall_incl_maybe": round(float((high | maybe)[m].mean()), 4)}
    focus = np.isin(cats, FOCUS) & (y == 1)
    out["toll_delivery_gov"] = {"n": int(focus.sum()),
                                "recall_at_t_high": round(float(high[focus].mean()), 4) if focus.any() else None,
                                "recall_incl_maybe": round(float((high | maybe)[focus].mean()), 4) if focus.any() else None}
    neg = y == 0
    neg_gated = neg & gate
    fpr_all = float(high[neg].mean()) if neg.any() else 0.0
    fpr_gated = float(high[neg_gated].mean()) if neg_gated.any() else 0.0
    out["normals"] = {"n": int(neg.sum()), "n_gated": int(neg_gated.sum()),
                      "fpr_all": fpr_all, "fpr_gated": fpr_gated,
                      "est_false_alarms_per_day": round(th["unique_names_per_day"] * th["gate_rate"] * fpr_gated, 1)}
    examples = defaultdict(list)
    order = np.argsort(-s)
    for i in order:
        r, k = rows[i], None
        if high[i] and y[i] == 1:
            k = "caught"
        elif high[i] and y[i] == 0:
            k = "false_alarm"
        elif not high[i] and y[i] == 1 and cats[i] in FOCUS:
            k = "missed_toll_delivery_gov"
        if k and len(examples[k]) < 20:
            examples[k].append({"host": r["host"], "category": r["category"], "s1": round(float(s[i]), 3),
                                "gate": bool(gate[i])})
    out["examples"] = dict(examples)
    return out


def main():
    model_dir = _default_dir()
    with open(os.path.join(model_dir, "thresholds.json")) as f:
        th = json.load(f)
    st = Stage1(model_dir)
    print(f"model {st.version}  T_high {th['t_high']}  T_low {th['t_low']}")

    report = {"model_version": st.version, "thresholds": {k: th[k] for k in ("t_high", "t_low")},
              "gate_rate": th["gate_rate"], "unique_names_per_day": th["unique_names_per_day"],
              "arch": os.uname().machine}

    for name in ("test", "test_future"):
        rows = read_rows(os.path.join(DATA, f"{name}.csv"))
        if not rows:
            continue
        t0 = time.time()
        s1 = st.score_many([r["host"] for r in rows])
        secs = time.time() - t0
        res = evaluate(rows, s1, th)
        res["names_per_sec"] = round(len(rows) / secs, 0)
        report[name] = res
        a, b, t = res["system_at_t_high"], res["baseline_brand_word_rule"], res["toll_delivery_gov"]
        print(f"\n== {name}.csv: {res['rows']:,} names ({res['scam']:,} scam / {res['normal']:,} normal)")
        if "pr_auc" in res:
            print(f"   PR-AUC {res['pr_auc']}  ROC-AUC {res['roc_auc']}")
        print(f"   system  (gate + Stage 1 >= T_high): precision {pct(a['precision'])}  recall {pct(a['recall'])}")
        print(f"   baseline (brand word -> scam):      precision {pct(b['precision'])}  recall {pct(b['recall'])}")
        if t["n"]:
            print(f"   TOLL/DELIVERY/GOV recall: {pct(t['recall_at_t_high'])} at T_high, "
                  f"{pct(t['recall_incl_maybe'])} incl. MAYBE (n={t['n']:,})")
        n = res["normals"]
        print(f"   normals flagged: {n['fpr_all']:.5%} of all, {n['fpr_gated']:.4%} of brand-word normals "
              f"-> ~{n['est_false_alarms_per_day']} false alarms/day (before Stage 3)")
        print(f"   speed: {res['names_per_sec']:,.0f} names/s on {report['arch']}")

    # official sites must never be flagged (the engine's allowlist guarantees it; check the model too)
    official = sorted(F.OFFICIAL)
    s_off = st.score_many(official) if official else []
    report["official_sites"] = [{"host": h, "s1": round(v, 3)} for h, v in zip(official, s_off)]
    hi = [h for h, v in zip(official, s_off) if v >= th["t_high"]]
    print(f"\nofficial sites: {len(official)} checked; model alone would flag {len(hi)} {hi if hi else ''}"
          f"(allowlist blocks them anyway)")

    os.makedirs(REPORTS, exist_ok=True)
    with open(os.path.join(REPORTS, "stage1_eval.json"), "w") as f:
        json.dump(report, f, indent=2)
    write_md(report)
    print("\nwrote reports/stage1_eval.json and reports/stage1_eval.md")


def write_md(r):
    L = [f"# Stage 1 evaluation — {r['model_version']}", "",
         f"Trained and scored on IBM LinuxONE (`{r['arch']}`). Thresholds: T_high **{r['thresholds']['t_high']}**, "
         f"T_low **{r['thresholds']['t_low']}**. Flagged = passes brand gate AND Stage 1 ≥ T_high "
         "(no Stage 0, no certificates, no Stage 3 — those only add on top).", ""]
    for name in ("test", "test_future"):
        if name not in r:
            continue
        x = r[name]
        a, b, t, n = x["system_at_t_high"], x["baseline_brand_word_rule"], x["toll_delivery_gov"], x["normals"]
        L += [f"## {name}.csv — {x['rows']:,} names ({x['scam']:,} scam / {x['normal']:,} normal)", "",
              "| | precision | recall |", "|---|---|---|",
              f"| **Scamouflage (gate + Stage 1)** | {pct(a['precision'])} | {pct(a['recall'])} |",
              f"| Baseline: brand word → scam | {pct(b['precision'])} | {pct(b['recall'])} |", ""]
        if t["n"]:
            L.append(f"- **Toll / delivery / gov scams caught:** {pct(t['recall_at_t_high'])} at T_high, "
                     f"{pct(t['recall_incl_maybe'])} including the MAYBE zone (n = {t['n']:,})")
        L += [f"- Normal sites flagged: {n['fpr_all']:.5%} of all, {n['fpr_gated']:.4%} of brand-word normals → "
              f"~{n['est_false_alarms_per_day']} false alarms/day before Stage 3",
              f"- Speed: {x['names_per_sec']:,.0f} names/s", ""]
        if "pr_auc" in x:
            L += [f"- PR-AUC {x['pr_auc']}, ROC-AUC {x['roc_auc']}", ""]
        L += ["| category | n | recall at T_high | incl. MAYBE |", "|---|---|---|---|"]
        for c, v in x["by_category_recall_at_t_high"].items():
            L.append(f"| {c} | {v['n']:,} | {pct(v['recall'])} | {pct(v['recall_incl_maybe'])} |")
        L.append("")
        for k, ex in x["examples"].items():
            L += [f"<details><summary>{k} ({len(ex)} examples, plain text)</summary>", "", "```"]
            L += [f"{e['s1']:.3f}  {e['host']}  ({e['category']})" for e in ex] + ["```", "</details>", ""]
    with open(os.path.join(REPORTS, "stage1_eval.md"), "w") as f:
        f.write("\n".join(L))


if __name__ == "__main__":
    main()
