#!/usr/bin/env python3
"""
Scamouflage — model/lead_time.py  (owner: Vaishnavi)

"Caught before the blocklists": for every alert the engine raised on its own (stage >= 1), check whether
that site LATER showed up on a public phishing feed (labels.db, refreshed hourly by labels/feeds.py loop),
and how many hours earlier we flagged it. Writes data/leadtime.json for GET /api/leadtime.

    ~/scamouflage/.venv/bin/python model/lead_time.py
    ~/scamouflage/.venv/bin/python model/lead_time.py --alerts-db ~/tolltrap/data/scamouflage.db \
                                                     --labels-db ~/tolltrap/data/labels.db

Rules (honest by construction):
  - stage 0 alerts never count (they were already on a list when we saw them)
  - "listed" time = the first time our hourly feed check saw the site on any feed, so a lead time can be
    up to ~1 hour SHORTER than the truth, never longer
  - match = same host, or a feed lists one of its parent names (never a whole hosting platform)
Run it hourly (cron / tmux loop); numbers grow as feeds catch up with our alerts.
"""
import argparse
import datetime as dt
import json
import os
import sqlite3
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from model import features as F  # noqa: E402

DATA = os.path.join(ROOT, "data")


def to_epoch(v):
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return dt.datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def write_atomic(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts-db", default=os.environ.get("ALERTS_DB") or os.path.join(DATA, "scamouflage.db"))
    ap.add_argument("--labels-db", default=os.environ.get("SCAM_DB") or os.path.join(DATA, "labels.db"))
    ap.add_argument("--out", default=os.path.join(os.environ.get("DATA_DIR") or DATA, "leadtime.json"))
    args = ap.parse_args()

    acon = sqlite3.connect(f"file:{os.path.expanduser(args.alerts_db)}?mode=ro", uri=True, timeout=30)
    cols = {r[1] for r in acon.execute("PRAGMA table_info(alerts)")}
    if "stage" not in cols:
        out = {"n": 0, "n_alerts_new": 0, "note": "alerts table has no `stage` column yet (engine not live)"}
        write_atomic(args.out, out)
        print(out["note"])
        return
    when_col = "seen_at"
    alerts = {}
    q = (f"SELECT domain, MIN({when_col}), MAX(COALESCE(category, '')) FROM alerts WHERE stage >= 1 GROUP BY domain"
         if "category" in cols else f"SELECT domain, MIN({when_col}), '' FROM alerts WHERE stage >= 1 GROUP BY domain")
    for host, seen, cat in acon.execute(q):
        t = to_epoch(seen)
        if host and t:
            alerts[host.lower()] = (t, cat or None)

    lcon = sqlite3.connect(f"file:{os.path.expanduser(args.labels_db)}?mode=ro", uri=True, timeout=30)
    listed = {}
    for host, first in lcon.execute("SELECT host, MIN(first_seen) FROM labels GROUP BY host"):
        t = to_epoch(first)
        if host and t:
            listed[host.lower()] = t

    rows = []
    for host, (t_alert, cat) in alerts.items():
        # the host itself, or any parent name a feed listed (a.b.scam.top -> b.scam.top -> scam.top),
        # but never a whole hosting platform (weebly.com) or a bare ending
        parts = host.split(".")
        cands = [".".join(parts[i:]) for i in range(len(parts) - 1)]
        times = [listed[c] for c in cands if c in listed and (c == host or not F.on_hosting_platform(c))]
        t_list = min(times) if times else None
        if t_list is None:
            continue
        rows.append({"host": host, "category": cat, "hours_early": round((t_list - t_alert) / 3600, 2)})

    early = [r for r in rows if r["hours_early"] > 0]
    days = [r["hours_early"] / 24 for r in early]
    out = {
        "n": len(early),                                   # catches that a feed listed AFTER us
        "n_alerts_new": len(alerts),                       # all stage>=1 alerts so far
        "n_later_on_a_feed": len(rows),                    # of those, how many any feed has listed by now
        "share_before_any_feed": round(len(early) / len(rows), 4) if rows else None,
        "median_days": round(statistics.median(days), 3) if days else None,
        "min_days": round(min(days), 3) if days else None,
        "max_days": round(max(days), 3) if days else None,
        "p90_days": round(sorted(days)[int(0.9 * (len(days) - 1))], 3) if days else None,
        "examples": sorted(early, key=lambda r: -r["hours_early"])[:10],
        "method": "stage>=1 alerts vs first time our hourly feed check saw the site; stage-0 never counted; "
                  "lead times are conservative by up to ~1 h",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }
    write_atomic(args.out, out)
    if early:
        print(f"{len(early)} of our {len(alerts)} new alerts were listed by a feed LATER "
              f"(median {statistics.median([r['hours_early'] for r in early]):.1f} h earlier); "
              f"{len(rows) - len(early)} were listed before our alert")
    else:
        print(f"{len(alerts)} new alerts so far; {len(rows)} on a feed yet; none listed after us yet "
              f"(feeds take hours to days, run again later)")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
