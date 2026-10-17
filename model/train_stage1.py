#!/usr/bin/env python3
"""
Scamouflage — model/train_stage1.py  (owner: Vaishnavi)       MODEL_SPEC §6

Trains the Stage 1 name model and picks the two lines (T_high, T_low).

    ~/snapml-venv/bin/python model/train_stage1.py
    ~/snapml-venv/bin/python model/train_stage1.py --names-per-day 50000000 --gate-rate 0.002
    ~/snapml-venv/bin/python model/train_stage1.py --snapml      # also time IBM Snap ML (report only)

Reads   data/train.csv                       (from labels/build_dataset.py; never test.csv)
        data/ct_sample.txt (optional)        random live-stream names -> measures gate_rate
Writes  data/models/stage1.joblib            the trained model (shared folder, not git)
        data/models/thresholds.json          T_high, T_low and the numbers behind them
        reports/thresholds.json              copy for git / documentation

How it works (plain words):
  1. Split train.csv into FIT (85%) and VALIDATION (15%) by campaign group, so lookalikes from one
     scam kit never sit on both sides.
  2. Model A reads the name as overlapping 3-5 letter chunks ("ezp", "zpa", "pas", ...) and learns
     which chunks are scammy (logistic regression on hashed character n-grams).
  3. Model B reads ~29 hand-made numbers per name (brand word? fake ".com-"? cheap ending? random
     letters? ...) and learns rules from them (gradient-boosted trees).
  4. Each model's raw output is turned into an honest probability on VALIDATION (isotonic
     calibration), then s1 = average of the two.
  5. The lines are picked on VALIDATION from false alarms per day:
        false_alarms/day = names_per_day x gate_rate x (share of brand-gated normal names >= T)
     T_high = lowest T with <= 50 false alarms/day (before Stage 3)
     T_low  = lowest T (>= 0.30) where MAYBE names stay <= 1,000/hour (what Stage 3 can check)
"""
import argparse
import csv
import datetime as dt
import json
import os
import sys
import time

import joblib
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from model import features as F  # noqa: E402
from model.stage1 import NGRAM_PARAMS, ngram_vectorizer  # noqa: E402

DATA = os.path.join(ROOT, "data")
MODEL_DIR = os.environ.get("SCAM_MODELS") or os.path.join(DATA, "models")
TARGET_FALSE_ALARMS_PER_DAY = 50
MAX_MAYBE_PER_HOUR = 1000
T_LOW_FLOOR = 0.30
T_HIGH_FLOOR = 0.50


def log(msg):
    print(f"[{dt.datetime.now():%H:%M:%S}] {msg}", flush=True)


def read_rows(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def featurize(hosts, every=50000):
    X = np.zeros((len(hosts), len(F.FEATURE_NAMES)), dtype=np.float32)
    t0 = time.time()
    for i, h in enumerate(hosts):
        X[i] = F.name_vector(h)
        if i and i % every == 0:
            log(f"  features {i:,}/{len(hosts):,} ({i / (time.time() - t0):,.0f}/s)")
    return X


def group_split(groups, val_frac, seed=42):
    from sklearn.model_selection import GroupShuffleSplit
    gss = GroupShuffleSplit(n_splits=1, test_size=val_frac, random_state=seed)
    return next(gss.split(np.zeros(len(groups)), groups=groups))


def measure_gate_rate():
    """Fraction of random live-stream names that pass OUR brand gate (data/ct_sample.txt)."""
    path = os.path.join(DATA, "ct_sample.txt")
    if not os.path.exists(path):
        return None, 0
    names = [F.clean_host(l) for l in open(path)]
    names = [n for n in names if n]
    if not names:
        return None, 0
    passed = sum(1 for n in names if F.brand_gate(n)[0])
    return passed / len(names), len(names)


def fpr_at(scores_neg, t):
    return float((scores_neg >= t).mean()) if len(scores_neg) else 0.0


def pick_thresholds(s_val, y_val, gated_val, names_per_day, gate_rate):
    neg = s_val[(y_val == 0) & gated_val]          # brand-gated NORMAL names (the hard ones)
    gated_per_day = names_per_day * gate_rate
    grid = np.round(np.arange(0.30, 0.995, 0.005), 3)

    def fa_day(t):
        return gated_per_day * fpr_at(neg, t)

    def fa_day_careful(t):
        # (mistakes + 1) / (n + 1): never claims "zero false alarms" just because validation is small
        k = int((neg >= t).sum())
        return gated_per_day * (k + 1) / (len(neg) + 1)

    t_high = None
    for t in grid:
        if t >= T_HIGH_FLOOR and fa_day_careful(t) <= TARGET_FALSE_ALARMS_PER_DAY:
            t_high = float(t)
            break
    if t_high is None:
        # validation too small to prove <= 50/day: go just above every brand-word normal we saw
        above = [float(t) for t in grid if t >= T_HIGH_FLOOR and (neg >= t).sum() == 0]
        t_high = above[0] if above else 0.99
    resolution = gated_per_day / max(len(neg), 1)   # false alarms/day that ONE validation mistake stands for

    t_low = t_high
    for t in grid:
        if t < T_LOW_FLOOR or t >= t_high:
            continue
        maybe_share = fpr_at(neg, t) - fpr_at(neg, t_high)
        if gated_per_day / 24 * maybe_share <= MAX_MAYBE_PER_HOUR:
            t_low = float(t)
            break
    return {
        "t_high": t_high,
        "t_low": t_low,
        "est_false_alarms_per_day_at_t_high": round(fa_day(t_high), 1),
        "est_maybe_per_hour": round(gated_per_day / 24 * (fpr_at(neg, t_low) - fpr_at(neg, t_high)), 1),
        "n_val_gated_normals": int(len(neg)),
        "false_alarms_per_day_per_val_mistake": round(resolution, 1),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--names-per-day", type=float, default=None,
                    help="unique names per day on the live stream (ask Shriya). Default 60,000,000 (placeholder)")
    ap.add_argument("--gate-rate", type=float, default=None,
                    help="share of live names passing the gate. Default: measured from data/ct_sample.txt")
    ap.add_argument("--val-frac", type=float, default=0.15)
    ap.add_argument("--snapml", action="store_true", help="also train IBM Snap ML boosting and report its speed")
    args = ap.parse_args()

    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.isotonic import IsotonicRegression
    from sklearn.linear_model import SGDClassifier
    from sklearn.metrics import average_precision_score, roc_auc_score

    t_start = time.time()
    rows = read_rows(os.path.join(DATA, "train.csv"))
    hosts = [r["host"] for r in rows]
    y = np.array([int(r["label"]) for r in rows], dtype=np.int8)
    groups = np.array([r["group"] for r in rows])
    cats = np.array([r["category"] for r in rows])
    log(f"train.csv: {len(rows):,} rows ({int(y.sum()):,} scam, {int((y == 0).sum()):,} normal)")

    fit_idx, val_idx = group_split(groups, args.val_frac)
    assert not set(groups[fit_idx]) & set(groups[val_idx]), "group leak between fit and validation"
    log(f"split by campaign group: fit {len(fit_idx):,} / validation {len(val_idx):,}")

    # ---- Model A: character chunks
    log("Model A (character n-grams + logistic regression): hashing names...")
    vec = ngram_vectorizer()
    Xa = vec.transform(hosts)
    clf_a = SGDClassifier(loss="log_loss", alpha=1e-6, max_iter=30, tol=1e-4,
                          class_weight="balanced", random_state=42)
    t0 = time.time()
    clf_a.fit(Xa[fit_idx], y[fit_idx])
    log(f"  trained in {time.time() - t0:.1f}s")
    raw_a = clf_a.predict_proba(Xa[val_idx])[:, 1]

    # ---- Model B: hand-made features
    log("Model B (handcrafted features + gradient boosting): computing features...")
    Xb = featurize(hosts)
    clf_b = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, max_leaf_nodes=63,
                                           class_weight="balanced", random_state=42)
    t0 = time.time()
    clf_b.fit(Xb[fit_idx], y[fit_idx])
    train_b_sec = time.time() - t0
    log(f"  trained in {train_b_sec:.1f}s")
    raw_b = clf_b.predict_proba(Xb[val_idx])[:, 1]

    snap = None
    if args.snapml:
        try:
            from snapml import BoostingMachineClassifier
            sm = BoostingMachineClassifier(num_round=300, max_depth=6, random_state=42, n_jobs=os.cpu_count())
            t0 = time.time()
            sm.fit(Xb[fit_idx], y[fit_idx].astype(np.float32))
            snap_sec = time.time() - t0
            p = sm.predict_proba(Xb[val_idx])[:, 1]
            snap = {"train_sec": round(snap_sec, 2), "sklearn_train_sec": round(train_b_sec, 2),
                    "val_pr_auc": round(float(average_precision_score(y[val_idx], p)), 4),
                    "note": "IBM Snap ML BoostingMachine on LinuxONE (CPU mode); reported only, not deployed"}
            log(f"  Snap ML: trained in {snap_sec:.1f}s (sklearn {train_b_sec:.1f}s), val PR-AUC {snap['val_pr_auc']}")
        except Exception as e:
            log(f"  Snap ML skipped ({type(e).__name__}: {e})")

    # ---- calibrate on validation, combine
    yv = y[val_idx]
    iso_a = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1).fit(raw_a, yv)
    iso_b = IsotonicRegression(out_of_bounds="clip", y_min=0, y_max=1).fit(raw_b, yv)
    pa, pb = iso_a.predict(raw_a), iso_b.predict(raw_b)
    s_val = (pa + pb) / 2

    for name, p in (("Model A", pa), ("Model B", pb), ("Stage 1 (A+B)", s_val)):
        log(f"  validation {name:14s} PR-AUC {average_precision_score(yv, p):.4f}  ROC-AUC {roc_auc_score(yv, p):.4f}")

    # ---- thresholds
    gate_rate, n_ct = (args.gate_rate, 0) if args.gate_rate else measure_gate_rate()
    gate_src = "argument" if args.gate_rate else (f"measured on {n_ct:,} live names (ct_sample.txt)" if gate_rate else None)
    if gate_rate is None:
        gate_rate, gate_src = 0.003, "PLACEHOLDER 0.003 — rerun with ct_sample.txt or --gate-rate"
    names_per_day = args.names_per_day or 60_000_000
    npd_src = "argument" if args.names_per_day else "PLACEHOLDER 60M — rerun with --names-per-day from Shriya"
    gated_val = np.array([F.brand_gate(hosts[i])[0] for i in val_idx])
    th = pick_thresholds(s_val, yv, gated_val, names_per_day, gate_rate)

    val_scam_gated = (yv == 1) & gated_val
    recall_high = float((s_val[val_scam_gated] >= th["t_high"]).mean()) if val_scam_gated.any() else 0.0
    toll = val_scam_gated & np.isin(cats[val_idx], ["toll", "delivery", "gov"])
    recall_toll = float((s_val[toll] >= th["t_high"]).mean()) if toll.any() else 0.0

    log(f"gate_rate {gate_rate:.5f} ({gate_src}); names/day {names_per_day:,.0f} ({npd_src})")
    log(f"T_high {th['t_high']}  (~{th['est_false_alarms_per_day_at_t_high']} false alarms/day before Stage 3)")
    log(f"T_low  {th['t_low']}  (~{th['est_maybe_per_hour']} MAYBE names/hour to Stage 3)")
    log(f"validation recall at T_high: gated scams {recall_high:.1%}, toll/delivery/gov {recall_toll:.1%} (n={int(toll.sum())})")
    if th["n_val_gated_normals"] < 2000:
        log(f"WARNING only {th['n_val_gated_normals']} brand-gated normal names in validation: one mistake = "
            f"~{th['false_alarms_per_day_per_val_mistake']} false alarms/day. Add ct_sample.txt for a sharper estimate.")

    # ---- save
    version = "stage1-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M")
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump({"version": version, "ngram_params": NGRAM_PARAMS, "clf_a": clf_a, "clf_b": clf_b,
                 "iso_a": iso_a, "iso_b": iso_b, "feature_names": F.FEATURE_NAMES},
                os.path.join(MODEL_DIR, "stage1.joblib"), compress=3)
    out = dict(th, model_version=version, gate_rate=gate_rate, gate_rate_source=gate_src,
               unique_names_per_day=names_per_day, names_per_day_source=npd_src,
               val_recall_gated_at_t_high=round(recall_high, 4), val_recall_toll_at_t_high=round(recall_toll, 4),
               n_train=int(len(fit_idx)), n_val=int(len(val_idx)), snapml=snap,
               trained_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
               train_minutes=round((time.time() - t_start) / 60, 1), arch=os.uname().machine)
    for path in (os.path.join(MODEL_DIR, "thresholds.json"), os.path.join(ROOT, "reports", "thresholds.json")):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(out, f, indent=2)
    log(f"saved {MODEL_DIR}/stage1.joblib + thresholds.json ({version}); "
        f"total {out['train_minutes']} min on {out['arch']}")
    log("next: python model/evaluate.py   (scores the 20% test set — the honest numbers)")


if __name__ == "__main__":
    main()
