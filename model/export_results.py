#!/usr/bin/env python3
"""
Scamouflage — model/export_results.py  (owner: Vaishnavi)

Writes data/results.json for the dashboard's accuracy card (GET /api/results). Real test-set numbers only.

    ~/scamouflage/.venv/bin/python model/export_results.py

Scope (stated in the file so nobody misreads it): Scamouflage targets toll / delivery / government scams.
So the numbers compare TOLL/DELIVERY/GOV scams against ALL normal sites in the held-out test set
(split by scam campaign). Generic phishing (banks, Netflix, ...) is out of scope and left out.
  recall      = share of toll/delivery/gov test scams flagged (gate + Stage 1 >= T_high)
  precision   = flagged toll/delivery/gov scams / (those + flagged normal sites)
  false_alarms_per_10k = normal test sites flagged, per 10,000 normal sites
Baseline "keyword_rule" = "brand word present -> scam", same scope, same test set.
"""
import csv
import datetime as dt
import json
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from model import features as F  # noqa: E402
from model.stage1 import Stage1, _default_dir  # noqa: E402

FOCUS = ("toll", "delivery", "gov")
DATA = os.path.join(ROOT, "data")
OUT_DIR = os.environ.get("DATA_DIR") or DATA


def scores_for(pred, y, focus):
    """precision / recall / false alarms per 10k for one predictor, on focus scams vs all normals."""
    scam = focus & (y == 1)
    normal = y == 0
    tp = int((pred & scam).sum())
    fp = int((pred & normal).sum())
    n_scam, n_norm = int(scam.sum()), int(normal.sum())
    return {"recall": round(tp / n_scam, 4) if n_scam else None,
            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
            "false_alarms_per_10k": round(fp / n_norm * 10000, 3) if n_norm else None,
            "tp": tp, "fp": fp, "n_scams": n_scam, "n_normals": n_norm}


def write_atomic(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)


def main():
    from sklearn.metrics import average_precision_score
    model_dir = _default_dir()
    th = json.load(open(os.path.join(model_dir, "thresholds.json")))
    st = Stage1(model_dir)

    with open(os.path.join(DATA, "test.csv"), newline="") as f:
        rows = list(csv.DictReader(f))
    y = np.array([int(r["label"]) for r in rows])
    cats = np.array([r["category"] for r in rows])
    focus = np.isin(cats, FOCUS)
    keep = focus | (y == 0)                      # in-scope rows: focus scams + all normals
    rows = [r for r, k in zip(rows, keep) if k]
    y, focus = y[keep], focus[keep]

    gate = np.array([F.brand_gate(r["host"])[0] for r in rows])
    s1 = np.array(st.score_many([r["host"] for r in rows]))
    final = np.where(gate, s1, 0.0)              # names failing the gate score 0 in the engine
    flagged = final >= th["t_high"]
    flagged_or_maybe = final >= th["t_low"]

    model = scores_for(flagged, y, focus)
    out = {
        "precision": model["precision"],
        "recall": model["recall"],
        "recall_incl_stage3_review": scores_for(flagged_or_maybe, y, focus)["recall"],
        "pr_auc": round(float(average_precision_score(y, final)), 4),
        "false_alarms_per_10k": model["false_alarms_per_10k"],
        "baselines": {"keyword_rule": scores_for(gate, y, focus)},
        "detail": model,
        "scope": "toll/delivery/gov scams vs all normal sites, held-out test set split by scam campaign",
        "flagged_means": f"passes brand gate AND Stage 1 score >= T_high ({th['t_high']}); "
                         "before Stage 3 (which removes old real businesses)",
        "model_version": st.version,
        "t_high": th["t_high"], "t_low": th["t_low"],
        "n_test_rows": len(rows),
        "arch": os.uname().machine,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, "results.json")
    write_atomic(path, out)
    print(f"model {st.version}: recall {out['recall']:.1%} (incl. Stage 3 review {out['recall_incl_stage3_review']:.1%}), "
          f"precision {out['precision']:.1%}, false alarms {out['false_alarms_per_10k']} per 10k normal sites")
    k = out["baselines"]["keyword_rule"]
    print(f"keyword rule:  recall {k['recall']:.1%}, precision {k['precision']:.1%}, "
          f"false alarms {k['false_alarms_per_10k']} per 10k")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
