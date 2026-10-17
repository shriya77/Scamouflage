#!/usr/bin/env python3
"""
Scamouflage — labels/build_dataset.py  (owner: Vaishnavi)

Turns the collected data into a clean, ready-to-train dataset with 20% held back for testing.

Reads   data/positives.csv   (scam names, from feeds.py export)
        data/negatives.csv   (legitimate names, from feeds.py export)
        data/ct_sample.txt   (optional: one domain per line, random names from the live stream)

Writes  data/train.csv            80%  -> train the model on this
        data/test.csv             20%  -> NEVER train on this; final scores only
        data/test_future.csv      scams first listed after --cutoff (only if --cutoff given)
        data/dataset_summary.json counts for the documentation

    python3 labels/build_dataset.py
    python3 labels/build_dataset.py --cutoff 2026-10-17T19:00:00+00:00   # also make a "future" test set
    python3 labels/build_dataset.py --max-other 100000                    # fewer generic phishing names

Cleaning rules (each one prints how many rows it removed):
  1. lowercase, strip "www." / "*.", drop junk, IP addresses and names without a real ending
  2. one row per name (duplicates across feeds are merged)
  3. a name on BOTH lists is dropped from both (we cannot trust its label)
  4. the split is by CAMPAIGN: lookalikes from one kit (usps.com-abc.bid, usps.com-xyz.bid
     -> group 'usps.com-*.bid') never end up in both train and test. Names without a brand or
     lure word are grouped by registered domain.
  Normal examples: data/ct_sample.txt (random live-stream domains) is the most realistic source;
  export it from the stream's `seen` table and rerun.
"""
import argparse
import csv
import hashlib
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import re  # noqa: E402
from feeds import DATA, clean_host, load_brands, registered_domain  # noqa: E402

_BRANDS = [w for w, _ in load_brands()]
_LURES = {"pay", "fee", "fees", "toll", "verify", "secure", "login", "account", "update", "billing", "refund",
          "citation", "violation", "invoice", "track", "deliver", "parcel", "claim", "notice", "alert",
          "support", "confirm", "service", "unpaid", "due", "fine", "penalty", "redeliver", "customs", "package"}
_STRUCT = {"com", "gov", "org", "net", "us", "www"}


def campaign_key(host):
    """Group lookalikes from one kit: usps.com-abc.bid and usps.com-xyz.bid -> 'usps.com-*.bid'.
    Words that are brands, lure words or fake-TLD parts are kept; everything else becomes '*'.
    Returns None when the name has no brand / lure word (then the registered domain is the group)."""
    parts = re.split(r"([^a-z0-9]+)", host)
    out, signal = [], False
    for i, t in enumerate(parts):
        if i % 2:                      # separator ('.', '-')
            out.append(t)
            continue
        is_last = i == len(parts) - 1  # keep the ending (.bid, .win)
        brand = next((b for b in _BRANDS if t == b or (len(b) >= 5 and b in t) or (len(b) <= 4 and t.startswith(b))), None)
        if brand:
            out.append(brand); signal = True
        elif t in _LURES:
            out.append(t); signal = True
        elif t in _STRUCT or is_last:
            out.append(t)
        else:
            out.append("*")
    return "".join(out) if signal else None

COLUMNS = ["host", "domain", "group", "label", "category", "source", "first_listed"]


def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def in_test(domain, pct=20):
    """Same domain -> same side, every run (a stable hash, not random)."""
    return int(hashlib.sha256(domain.encode()).hexdigest(), 16) % 100 < pct


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cutoff", help="ISO time; scams first listed after this go to test_future.csv")
    ap.add_argument("--test-pct", type=int, default=20)
    ap.add_argument("--max-other", type=int, default=150000,
                    help="keep at most this many generic ('other') scam names; all toll/delivery/gov are kept")
    args = ap.parse_args()

    raw_pos = read_csv(os.path.join(DATA, "positives.csv"))
    raw_neg = read_csv(os.path.join(DATA, "negatives.csv"))
    ct_path = os.path.join(DATA, "ct_sample.txt")
    if os.path.exists(ct_path):
        raw_neg += [{"host": l.strip(), "source": "ct_stream"} for l in open(ct_path) if l.strip()]
    print(f"read {len(raw_pos):,} scam rows and {len(raw_neg):,} legitimate rows")

    def clean(rows, label):
        out, junk = {}, 0
        for r in rows:
            h = clean_host(r.get("host", ""))
            if not h or not registered_domain(h) or "." not in registered_domain(h):
                junk += 1
                continue
            if h in out:
                continue
            out[h] = {
                "host": h,
                "domain": registered_domain(h),
                "group": (campaign_key(h) if label else None) or registered_domain(h),
                "label": label,
                "category": r.get("category") or ("other" if label else "legit"),
                "source": r.get("feeds") or r.get("source") or "",
                "first_listed": r.get("first_listed") or r.get("added") or "",
            }
        return out, junk

    pos, junk_p = clean(raw_pos, 1)
    neg, junk_n = clean(raw_neg, 0)
    print(f"rule 1-2: dropped {junk_p:,} junk scam rows, {junk_n:,} junk legit rows; merged duplicates")

    both = set(pos) & set(neg)
    for h in both:
        pos.pop(h)
        neg.pop(h)
    print(f"rule 3:   dropped {len(both):,} names that were on both lists")

    # balance: keep every toll/delivery/gov scam, but only a stable sample of generic phishing
    other = sorted((h for h, r in pos.items() if r["category"] == "other"),
                   key=lambda h: hashlib.sha256(("keep" + h).encode()).hexdigest())
    for h in other[args.max_other:]:
        pos.pop(h)
    print(f"balance:  kept {min(len(other), args.max_other):,} of {len(other):,} generic phishing names "
          f"(all toll/delivery/gov kept) -> {len(pos):,} scam vs {len(neg):,} legit")

    rows = list(pos.values()) + list(neg.values())
    future = []
    if args.cutoff:
        future = [r for r in rows if r["label"] == 1 and r["first_listed"] > args.cutoff]
        fut_hosts = {r["host"] for r in future}
        rows = [r for r in rows if r["host"] not in fut_hosts]

    train = [r for r in rows if not in_test(r["group"], args.test_pct)]
    test = [r for r in rows if in_test(r["group"], args.test_pct)]
    shared_groups = {r["group"] for r in train} & {r["group"] for r in test}
    assert not shared_groups, f"leak: {list(shared_groups)[:5]}"
    shared_domains = {r["domain"] for r in train} & {r["domain"] for r in test}
    n_groups = len({r["group"] for r in rows if r["label"] == 1})
    print(f"rule 4:   split by CAMPAIGN (scams: {n_groups:,} lookalike groups) -> train {len(train):,} / test {len(test):,}")
    print(f"          0 shared groups; {len(shared_domains):,} registered domains on both sides "
          f"(shared hosting like github.io / firebaseapp.com)")
    big = Counter(r["group"] for r in rows if r["label"] == 1).most_common(5)
    print("          biggest scam groups: " + ", ".join(f"{g} ({n:,})" for g, n in big))

    def write(name, data):
        with open(os.path.join(DATA, name), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=COLUMNS)
            w.writeheader()
            w.writerows(data)

    write("train.csv", train)
    write("test.csv", test)
    if args.cutoff:
        write("test_future.csv", future)

    def counts(data):
        c = Counter((r["label"], r["category"]) for r in data)
        return {
            "rows": len(data),
            "scam": sum(1 for r in data if r["label"] == 1),
            "legit": sum(1 for r in data if r["label"] == 0),
            "scam_by_category": {k[1]: v for k, v in sorted(c.items()) if k[0] == 1},
        }

    summary = {"train": counts(train), "test": counts(test),
               "test_future": counts(future) if args.cutoff else None,
               "cutoff": args.cutoff, "test_pct": args.test_pct,
               "dropped": {"junk_scam": junk_p, "junk_legit": junk_n, "on_both_lists": len(both)}}
    with open(os.path.join(DATA, "dataset_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print("\n            rows     scam    legit   toll  delivery   gov  other")
    for name in ("train", "test", "test_future"):
        s = summary.get(name)
        if not s:
            continue
        c = s["scam_by_category"]
        print(f"{name:12s}{s['rows']:>7,}  {s['scam']:>7,}  {s['legit']:>7,}  {c.get('toll', 0):>5,}  "
              f"{c.get('delivery', 0):>8,}  {c.get('gov', 0):>4,}  {c.get('other', 0):>5,}")
    print("\nwrote data/train.csv, data/test.csv" + (", data/test_future.csv" if args.cutoff else "")
          + ", data/dataset_summary.json")


if __name__ == "__main__":
    main()
