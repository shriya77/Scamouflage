"""Run verify() over a recording and report what happened. Use this FIRST on the VM.

    python -m verify.check ~/tolltrap/data/recordings/ct-20261017-152933.jsonl.gz --n 20000

Prints ok/fail/unknown_issuer split by precert vs cert and by algorithm, the
average time per cert, and a few failing examples (crt.sh links) to look at.
"""
import argparse
import collections
import gzip
import json
import time

from ingest.record import to_record
from verify import verify as V


def main():
    p = argparse.ArgumentParser()
    p.add_argument("file")
    p.add_argument("--n", type=int, default=20000, help="certificates to check")
    args = p.parse_args()

    by_type = collections.Counter()
    by_algo = collections.Counter()
    reasons = collections.Counter()
    fails = []
    seen = set()
    n = 0
    spent = 0.0
    opener = gzip.open if args.file.endswith(".gz") else open
    with opener(args.file, "rt") as f:
        for line in f:
            try:
                rec = to_record(json.loads(line))
            except ValueError:
                continue
            if rec is None or rec["id"] in seen:
                continue
            seen.add(rec["id"])
            t = time.perf_counter()
            r = V.verify(rec)
            spent += time.perf_counter() - t
            n += 1
            by_type[(rec["update_type"], r["status"])] += 1
            if r["status"] == "ok":
                by_algo[r["algo"]] += 1
            reasons[(r["status"], r.get("reason", ""))] += 1
            if r["status"] == "fail" and len(fails) < 5:
                fails.append((rec["update_type"], rec["log"], r.get("reason"), rec["crtsh_url"]))
            if n >= args.n:
                break

    print(f"\nchecked {n} unique certs, {1e6 * spent / max(n, 1):.0f} µs per cert, "
          f"issuer cache = {V.cache_size()} CAs\n")
    for ut in ("precert", "cert"):
        tot = sum(v for (u, _), v in by_type.items() if u == ut)
        if tot:
            parts = ", ".join(f"{s} {by_type[(ut, s)]} ({100 * by_type[(ut, s)] / tot:.1f}%)"
                              for s in ("ok", "fail", "unknown_issuer"))
            print(f"  {ut:8s} {tot:7d}: {parts}")
    print("\n  ok by algorithm:", dict(by_algo.most_common()))
    print("  status/reason:  ", {f"{s}/{r or '-'}": v for (s, r), v in reasons.most_common()})
    if fails:
        print("\n  example failures:")
        for x in fails:
            print("   ", *x)


if __name__ == "__main__":
    main()
