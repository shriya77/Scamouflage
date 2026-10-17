"""
Scamouflage — model/stage2_eval.py  (owner: Shriya)

Runs Stage 2 over REAL certificates from a CT recording and writes the numbers used to tune the
points table (MODEL_SPEC §7 "tune by looking at real certs"). Read-only: never touches the
network, never visits any name it prints (plain text only).

    python -m model.stage2 explain tests/fixtures/leaf_cert_scam.json
    python -m model.stage2 eval --recording data/recordings/ct-20261017-153717.jsonl.gz \\
        --labels-db ~/tolltrap/data/labels.db --out reports/stage2_eval

For every certificate (same cert from several logs counted once, like the consumer):
  - its names are cleaned and run through the brand gate (official names skipped);
  - certificates with at least one gated name are "gated certs": only those reach Stage 2;
  - if --labels-db is given, a gated cert is "known scam" when one of its names is on the
    Stage 0 known list (outside feeds, not our own detections).
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import statistics
import time
from collections import Counter

from . import features as F
from .stage2 import FEATURE_NAMES, MAX_BOOST, POINTS, Stage2, cert_features, points


def iter_certs(path: str):
    """leaf_cert dicts from a recording, each certificate once (by sha256)."""
    seen = set()
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if msg.get("message_type") != "certificate_update":
                continue
            leaf = (msg.get("data") or {}).get("leaf_cert") or {}
            fp = leaf.get("sha256") or leaf.get("fingerprint")
            if fp:
                if fp in seen:
                    continue
                seen.add(fp)
            yield leaf


def gated_names(leaf: dict) -> list[str]:
    out = []
    for raw in leaf.get("all_domains") or []:
        h = F.clean_host(raw)
        if h and h not in out and not F.is_official(h) and F.brand_gate(h)[0]:
            out.append(h)
    return out


def _pct(values, q):
    if not values:
        return 0
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))]


def cmd_explain(args):
    with open(args.cert, encoding="utf-8") as f:
        leaf = json.load(f)
    leaf = leaf.get("data", {}).get("leaf_cert", leaf) if isinstance(leaf, dict) else leaf
    hosts = [args.host] if args.host else gated_names(leaf) or [F.clean_host(n) for n in leaf.get("all_domains", [])][:1]
    s2 = Stage2()
    print("features:", json.dumps(cert_features(leaf)))
    for h in hosts:
        e = s2.explain(h, leaf)
        print(f"{h}: boost {e['boost']:.2f}  " + ("; ".join(e["reasons"]) or "(no points)"))


def cmd_eval(args):
    known = None
    if args.labels_db:
        from .stage0 import KnownList
        known = KnownList(os.path.expanduser(args.labels_db))
    s2 = Stage2()
    t_start = time.perf_counter()
    n_certs = n_names = n_gated_names = 0
    gated = []          # one row per gated cert
    boost_time, boost_calls = 0.0, 0
    for leaf in iter_certs(args.recording):
        n_certs += 1
        n_names += len({F.clean_host(n) for n in leaf.get("all_domains") or []} - {None})
        g = gated_names(leaf)
        if g:
            n_gated_names += len(g)
            t0 = time.perf_counter()
            boosts = [s2.boost(h, leaf) for h in g]     # how the engine calls it
            boost_time += time.perf_counter() - t0
            boost_calls += len(g)
            e = s2.explain(g[0], leaf)
            is_known = bool(known) and any(
                known.check(n) for n in leaf.get("all_domains") or [])
            gated.append({"names": sorted({F.clean_host(n) for n in leaf.get("all_domains") or []} - {None}),
                          "gated": g, "boost": max(boosts), "reasons": e["reasons"],
                          "features": cert_features(leaf), "known": is_known})
        if args.n_certs and n_certs >= args.n_certs:
            break
    elapsed = time.perf_counter() - t_start

    feats = {k: [r["features"][k] for r in gated] for k in FEATURE_NAMES}
    hist = Counter(round(r["boost"], 2) for r in gated)
    rules = Counter()
    for r in gated:
        if r["features"]["official_on_cert"]:
            rules["official_on_cert (boost forced to 0)"] += 1
            continue
        for feat, minimum, pts, why in POINTS:
            if r["features"][feat] >= minimum:
                rules[f"{feat} >= {minimum} (+{pts})"] += 1
    known_rows = [r for r in gated if r["known"]]
    boosted = [r for r in gated if r["boost"] > 0]
    summary = {
        "recording": args.recording, "certs": n_certs, "names": n_names,
        "gated_certs": len(gated), "gated_names": n_gated_names,
        "gate_rate_names": round(n_gated_names / max(1, n_names), 6),
        "boost_histogram": {f"{k:.2f}": v for k, v in sorted(hist.items())},
        "boosted_certs": len(boosted),
        "boosted_share_of_gated": round(len(boosted) / max(1, len(gated)), 4),
        "rule_fires": dict(rules.most_common()),
        "feature_p50_p90_p99_max": {k: [_pct(v, .5), _pct(v, .9), _pct(v, .99), max(v or [0])]
                                    for k, v in feats.items()},
        "known_scam_gated_certs": len(known_rows),
        "known_scam_boosts": Counter(round(r["boost"], 2) for r in known_rows),
        "boost_us_per_call": round(1e6 * boost_time / max(1, boost_calls), 1),
        "boost_calls": boost_calls,
        "seconds": round(elapsed, 1),
        "max_boost": MAX_BOOST,
    }
    summary["known_scam_boosts"] = {f"{k:.2f}": v for k, v in sorted(summary["known_scam_boosts"].items())}
    top = sorted(boosted, key=lambda r: (-r["boost"], -len(r["gated"])))[:args.show]
    examples = [{"boost": r["boost"], "known": r["known"], "reasons": r["reasons"],
                 "n_names": r["features"]["n_names"], "names": r["names"][:12]} for r in top]
    known_examples = [{"boost": r["boost"], "reasons": r["reasons"], "names": r["names"][:12]}
                      for r in known_rows[:args.show]]

    print(json.dumps(summary, indent=1))
    print(f"\nTop {len(examples)} boosted gated certificates (plain text, do not open):")
    for ex in examples:
        print(f"  {ex['boost']:.2f} {'KNOWN ' if ex['known'] else ''}[{ex['n_names']} names] "
              f"{', '.join(ex['names'])}  <- {'; '.join(ex['reasons'])}")
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out + ".json", "w", encoding="utf-8") as f:
            json.dump({"summary": summary, "top_boosted": examples, "known_scam_certs": known_examples},
                      f, indent=1)
        print(f"\nwrote {args.out}.json")


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m model.stage2", description="Stage 2 certificate check")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("explain", help="features + boost for one leaf_cert JSON file")
    e.add_argument("cert")
    e.add_argument("host", nargs="?")
    v = sub.add_parser("eval", help="run over a CT recording and report boosts on real certs")
    v.add_argument("--recording", required=True)
    v.add_argument("--n-certs", type=int, default=0, help="stop after this many certificates (0 = all)")
    v.add_argument("--labels-db", help="labels.db: mark certs with a name on the known-scam list")
    v.add_argument("--show", type=int, default=40)
    v.add_argument("--out", help="write OUT.json")
    args = p.parse_args(argv)
    {"explain": cmd_explain, "eval": cmd_eval}[args.cmd](args)


if __name__ == "__main__":
    main()
