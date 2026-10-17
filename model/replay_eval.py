#!/usr/bin/env python3
"""
Scamouflage — model/replay_eval.py  (owner: Vaishnavi)

How many alerts would Stage 1 raise on REAL live traffic? Reads a certificate-stream recording,
runs the brand gate + Stage 1 on every unique name, and counts names over each possible line.
This is the honest "alerts per day" number (an upper bound on false alarms: some flagged names are
real scams that no blocklist knows about yet).

    ~/scamouflage/.venv/bin/python model/replay_eval.py ~/tolltrap/data/recordings/ct-20261017-153717.jsonl.gz
    ... --set-t-high 0.90          # also write that line into data/models/thresholds.json

Writes reports/replay_eval.json. Never visits any site; names are printed as plain text.
"""
import argparse
import gzip
import json
import os
import sqlite3
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from model import features as F  # noqa: E402
from model.stage1 import Stage1, _default_dir  # noqa: E402

LINES = (0.30, 0.50, 0.70, 0.80, 0.85, 0.90, 0.95, 0.98)


def find_domains(obj):
    """Return the all_domains list from a certstream message, wherever it sits."""
    if isinstance(obj, dict):
        if isinstance(obj.get("all_domains"), list):
            return obj["all_domains"]
        for k in ("data", "leaf_cert", "message"):
            if k in obj:
                r = find_domains(obj[k])
                if r:
                    return r
        for v in obj.values():
            if isinstance(v, (dict, list)):
                r = find_domains(v)
                if r:
                    return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_domains(v)
            if r:
                return r
    return None


def read_recording(path):
    """Unique clean names + timestamps span (seconds) from a .jsonl.gz recording."""
    names, first_ts, last_ts, lines, bad = set(), None, None, 0, 0
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt") as f:
        for line in f:
            lines += 1
            try:
                msg = json.loads(line)
            except Exception:
                bad += 1
                continue
            for raw in find_domains(msg) or []:
                h = F.clean_host(raw)
                if h:
                    names.add(h)
            ts = None
            for k in ("seen", "ts", "time", "received_at"):
                v = msg.get(k) if isinstance(msg, dict) else None
                if v is None and isinstance(msg, dict) and isinstance(msg.get("data"), dict):
                    v = msg["data"].get(k)
                if isinstance(v, (int, float)):
                    ts = float(v)
                    break
            if ts:
                first_ts = ts if first_ts is None else min(first_ts, ts)
                last_ts = ts if last_ts is None else max(last_ts, ts)
    span = (last_ts - first_ts) if first_ts and last_ts and last_ts > first_ts else None
    return names, span, lines, bad


def known_scams(hosts):
    db = os.environ.get("SCAM_DB") or os.path.join(ROOT, "data", "labels.db")
    if not os.path.exists(db):
        return set()
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=30)
    known = set()
    hosts = list(hosts)
    for i in range(0, len(hosts), 500):
        chunk = hosts[i:i + 500]
        q = "SELECT DISTINCT host FROM labels WHERE host IN (%s)" % ",".join("?" * len(chunk))
        known.update(h for (h,) in con.execute(q, chunk))
    return known


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("recording")
    ap.add_argument("--minutes", type=float, default=None, help="recording length if timestamps are missing")
    ap.add_argument("--set-t-high", type=float, default=None, help="write this T_high into thresholds.json")
    ap.add_argument("--show", type=int, default=40, help="how many top flagged names to print")
    args = ap.parse_args()

    t0 = time.time()
    names, span, n_lines, bad = read_recording(os.path.expanduser(args.recording))
    if span is None and args.minutes:
        span = args.minutes * 60
    print(f"recording: {n_lines:,} messages ({bad} unreadable), {len(names):,} unique names"
          + (f", {span / 60:.1f} min" if span else " (length unknown — pass --minutes)"))

    gated = sorted(h for h in names if F.brand_gate(h)[0])
    print(f"brand gate: {len(gated):,} names pass ({len(gated) / max(len(names), 1):.3%})")
    st = Stage1(_default_dir())
    scores = st.score_many(gated) if gated else []
    known = known_scams(gated)
    per_day = (86400 / span) if span else None

    report = {"recording": os.path.basename(args.recording), "unique_names": len(names), "minutes": span / 60 if span else None,
              "gated": len(gated), "model_version": st.version, "lines": []}
    print("\n  line   flagged   already on a scam list   per day (scaled)   unknown flagged per day")
    for t in LINES:
        flagged = [h for h, s in zip(gated, scores) if s >= t]
        k = sum(1 for h in flagged if h in known)
        row = {"t": t, "flagged": len(flagged), "known_scams": k,
               "flagged_per_day": round(len(flagged) * per_day) if per_day else None,
               "unknown_per_day": round((len(flagged) - k) * per_day) if per_day else None}
        report["lines"].append(row)
        pd = f"{row['flagged_per_day']:>12,}" if per_day else "           ?"
        ud = f"{row['unknown_per_day']:>12,}" if per_day else "           ?"
        print(f"  {t:4.2f}   {len(flagged):7,}   {k:22,}   {pd}       {ud}")

    top = sorted(zip(scores, gated), reverse=True)[:args.show]
    report["top_flagged"] = [{"host": h, "s1": round(s, 3), "known_scam": h in known} for s, h in top]
    print(f"\ntop {len(top)} flagged names (plain text — do not open them):")
    for s, h in top:
        print(f"  {s:.3f}  {h}{'   [on a scam list]' if h in known else ''}")

    if args.set_t_high is not None:
        path = os.path.join(_default_dir(), "thresholds.json")
        th = json.load(open(path))
        th["t_high"] = float(args.set_t_high)
        th["t_low"] = min(th.get("t_low", 0.3), th["t_high"])
        th["t_high_source"] = f"set from replay_eval on {report['recording']}"
        for p in (path, os.path.join(ROOT, "reports", "thresholds.json")):
            with open(p, "w") as f:
                json.dump(th, f, indent=2)
        print(f"\nwrote T_high = {th['t_high']} into {path} (and reports/thresholds.json)")

    os.makedirs(os.path.join(ROOT, "reports"), exist_ok=True)
    with open(os.path.join(ROOT, "reports", "replay_eval.json"), "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nwrote reports/replay_eval.json ({time.time() - t0:.0f} s)")


if __name__ == "__main__":
    main()
