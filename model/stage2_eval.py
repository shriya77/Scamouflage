"""
Scamouflage — model/stage2_eval.py  (owner: Shriya)

Checks Stage 2 on REAL certificates and writes reports/stage2_eval.{md,json}
(MODEL_SPEC §7 "tune by looking at real certs"). Read-only, no network, names printed as plain
text only (never links, never visited).

    # 1. gated live certificates from a CT recording (only these ever reach Stage 2)
    python -m model.stage2 dump --recording data/recordings/ct-20261017-153717.jsonl.gz \\
        --out data/stage2/gated_live.jsonl
    # 2. real certificates of known toll/delivery/gov scams (crt.sh, see model/stage2_crtsh.py)
    python -m model.stage2_crtsh --labels-db data/labels.db --out data/stage2/crtsh_scam_certs.jsonl
    # 3. the report
    python -m model.stage2 eval --live data/stage2/gated_live.jsonl \\
        --scam data/stage2/crtsh_scam_certs.jsonl --out reports/stage2_eval
    python -m model.stage2 explain tests/fixtures/leaf_cert_scam.json

Live certificates are counted once even when several CT logs send them (same as the consumer).
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import platform
import time
from collections import Counter

from . import features as F
from .stage0 import registered_domain
from .stage2 import FEATURE_NAMES, MAX_BOOST, POINTS, Stage2, cert_features, points


# ------------------------------------------------------------------------------- inputs
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
    """Names on the cert that pass the engine's brand gate (official names never reach it)."""
    out = []
    for raw in leaf.get("all_domains") or []:
        h = F.clean_host(raw)
        if h and h not in out and not F.is_official(h) and F.brand_gate(h)[0]:
            out.append(h)
    return out


def gate_reason(h: str) -> str:
    if F.brand_hits(h):
        return "brand word"
    if F.brand_typo(h):
        return "misspelled brand"
    rd = registered_domain(h) or h
    from .stage2 import is_kit_name
    return "'.com-'/'gov-' trick" if is_kit_name(h, rd) else "fake pattern 'us-'/'net-'/'org-' prefix"


def load_live(path):
    with open(path, encoding="utf-8") as f:
        meta = json.loads(f.readline())["_meta"]
        return meta, [json.loads(line) for line in f]


def load_scam(path):
    domains, certs = [], []
    with open(path, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            domains.append(r)
            for c in r.get("certs") or []:
                if c.get("all_domains"):
                    certs.append({"all_domains": c["all_domains"], "category": r["category"],
                                  "query_domain": r["query_domain"]})
    return domains, certs


def labels_kit_stats(db: str) -> dict:
    """How kit-like are KNOWN toll/delivery/gov scams? Per registered domain: how many listed names
    and how many different brands. Read-only."""
    import sqlite3
    from collections import defaultdict
    con = sqlite3.connect("file:" + os.path.abspath(os.path.expanduser(db)) + "?mode=ro",
                          uri=True, timeout=30)
    brands, names = defaultdict(set), defaultdict(set)
    for h, brand in con.execute("SELECT host, brand FROM labels "
                                "WHERE category IN ('toll','delivery','gov')"):
        h = F.clean_host(h)
        rd = registered_domain(h) if h else None
        if rd:
            names[rd].add(h)
            if brand:
                brands[rd].add(brand)
    con.close()
    multi = sorted((d for d in brands if len(brands[d]) >= 2), key=lambda d: -len(names[d]))
    return {"registered_domains": len(names),
            "with_2plus_listed_names": sum(1 for d in names if len(names[d]) >= 2),
            "with_2plus_brands": len(multi),
            "top_multi_brand_domains": [[d, len(names[d]), sorted(brands[d])] for d in multi[:8]]}


# ------------------------------------------------------------------------------- the spec's example
def spec_example_boost(leaf: dict) -> float:
    """MODEL_SPEC §7's EXAMPLE table, as first written, for comparison only: +0.25 if >=2 brand
    lookalikes (word or misspelling), +0.15 if >=4, +0.15 if >=3 registered domains with a brand
    word, +0.10 if >=2 features.fake_pattern names, +0.05 wildcard on a brand name, cap 0.6."""
    names = {}
    for raw in leaf.get("all_domains") or []:
        h = F.clean_host(raw) if isinstance(raw, str) else None
        if h:
            names[h] = names.get(h, False) or raw.strip().startswith("*.")
    look = [h for h in names if F.brand_hits(h) or F.brand_typo(h)]
    regs = {registered_domain(h) or h for h in names if F.brand_hits(h)}
    fake = sum(1 for h in names if F.fake_pattern(h))
    b = (0.25 if len(look) >= 2 else 0) + (0.15 if len(look) >= 4 else 0)
    b += (0.15 if len(regs) >= 3 else 0) + (0.10 if fake >= 2 else 0)
    b += 0.05 if any(names[h] for h in look) else 0
    return min(MAX_BOOST, round(b, 4))


# ------------------------------------------------------------------------------- scoring a set
def score_set(certs, s2):
    rows = []
    for c in certs:
        names = sorted({F.clean_host(n) for n in c["all_domains"] if isinstance(n, str)} - {None})
        hosts = c.get("gated") or gated_names(c) or names[:1]
        feats = cert_features(c)
        b, reasons = points(feats)
        rows.append({"names": names, "gated": hosts, "features": feats, "boost": b,
                     "reasons": reasons, "spec_example": spec_example_boost(c),
                     "category": c.get("category"), "query_domain": c.get("query_domain")})
    return rows


def summarize(rows):
    n = max(1, len(rows))
    fires = Counter()
    for r in rows:
        if r["features"]["official_on_cert"]:
            fires["official_on_cert (boost 0)"] += 1
        for feat, minimum, pts, _ in POINTS:
            if not r["features"]["official_on_cert"] and r["features"][feat] >= minimum:
                fires[f"{feat} >= {minimum} (+{pts})"] += 1
    boosted = [r for r in rows if r["boost"] > 0]
    spec_boosted = [r for r in rows if r["spec_example"] > 0]
    return {
        "certs": len(rows),
        "boosted": len(boosted), "boosted_share": round(len(boosted) / n, 4),
        "boost_histogram": {f"{k:.2f}": v for k, v in sorted(Counter(r["boost"] for r in rows).items())},
        "rule_fires": dict(sorted(fires.items())),
        "spec_example_boosted": len(spec_boosted),
        "spec_example_boosted_share": round(len(spec_boosted) / n, 4),
        "spec_example_histogram": {f"{k:.2f}": v for k, v in
                                   sorted(Counter(r["spec_example"] for r in rows).items())},
        "features_p50_p90_p99_max": {
            k: [sorted(v)[int(q * (len(v) - 1))] for q in (.5, .9, .99, 1.0)] if v else [0, 0, 0, 0]
            for k, v in ((k, [r["features"][k] for r in rows]) for k in FEATURE_NAMES)},
    }


def speed(rows, repeat=3):
    """us per boost() call: a cold call (new certificate) and a cached call (same certificate,
    the engine's next gated name)."""
    s2 = Stage2()
    certs = [{"all_domains": r["names"]} for r in rows] or [{"all_domains": ["a.test"]}]
    best_cold = best_hot = float("inf")
    for _ in range(repeat):
        t0 = time.perf_counter()
        for c in certs:
            s2.boost(c["all_domains"][0], c)
            s2._last_key = None
        best_cold = min(best_cold, (time.perf_counter() - t0) / len(certs))
        c = certs[0]
        s2.boost(c["all_domains"][0], c)
        t0 = time.perf_counter()
        for _ in range(len(certs)):
            s2.boost(c["all_domains"][0], c)
        best_hot = min(best_hot, (time.perf_counter() - t0) / len(certs))
    return round(best_cold * 1e6, 1), round(best_hot * 1e6, 2)


# ------------------------------------------------------------------------------- commands
def cmd_explain(args):
    with open(args.cert, encoding="utf-8") as f:
        leaf = json.load(f)
    hosts = [args.host] if args.host else (gated_names(leaf) or
                                           [F.clean_host(n) for n in leaf.get("all_domains", [])][:1])
    s2 = Stage2()
    print("features:", json.dumps(cert_features(leaf)))
    for h in hosts:
        e = s2.explain(h, leaf)
        print(f"{h}: boost {e['boost']:.2f}  " + ("; ".join(e["reasons"]) or "(no points)"))


def cmd_dump(args):
    """Gated live certificates -> JSONL (first line: {"_meta": counts}), so the points table can
    be checked in seconds instead of re-reading a 2 GB recording each time."""
    n_certs = n_names = n_gated_names = 0
    t0 = time.perf_counter()
    rows = []
    for leaf in iter_certs(args.recording):
        n_certs += 1
        n_names += len({F.clean_host(n) for n in leaf.get("all_domains") or []} - {None})
        g = gated_names(leaf)
        if g:
            n_gated_names += len(g)
            rows.append({"all_domains": leaf.get("all_domains") or [], "gated": g})
    meta = {"recording": os.path.basename(args.recording), "certs": n_certs, "names": n_names,
            "gated_certs": len(rows), "gated_names": n_gated_names,
            "seconds": round(time.perf_counter() - t0, 1)}
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(json.dumps({"_meta": meta}) + "\n")
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(json.dumps(meta))


def cmd_eval(args):
    s2 = Stage2()
    meta, live_certs = load_live(args.live)
    live = score_set(live_certs, s2)
    gate = Counter(gate_reason(h) for c in live_certs for h in c["gated"])
    report = {"generated": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
              "machine": f"{platform.machine()} {platform.python_version()}",
              "points_table": [list(p) for p in POINTS], "max_boost": MAX_BOOST,
              "live_meta": meta, "gate_reasons": dict(gate.most_common()),
              "live": summarize(live)}
    report["speed_us_cold_cached"] = speed(live)
    scam = []
    if args.scam:
        domains, scam_certs = load_scam(args.scam)
        scam = score_set(scam_certs, s2)
        report["scam_meta"] = {
            "domains_queried": len(domains),
            "domains_with_certs": sum(1 for d in domains if d.get("certs")),
            "domains_no_certs": sum(1 for d in domains if d.get("status") == "no_certs"),
            "domains_errors": sum(1 for d in domains if str(d.get("status", "")).startswith("error")),
            "certs": len(scam_certs),
            "by_category": dict(Counter(c["category"] for c in scam_certs))}
        report["scam"] = summarize(scam)
    if args.labels_db:
        report["labels_kits"] = labels_kit_stats(args.labels_db)
    boosted_live = sorted((r for r in live if r["boost"] > 0), key=lambda r: -r["boost"])
    spec_live = sorted((r for r in live if r["spec_example"] > 0), key=lambda r: -r["spec_example"])
    report["examples"] = {
        "live_boosted": [{"boost": r["boost"], "reasons": r["reasons"], "names": r["names"][:8]}
                         for r in boosted_live[:args.show]],
        "live_boosted_by_spec_example_only": [
            {"spec_example": r["spec_example"], "names": r["names"][:6]}
            for r in spec_live if r["boost"] == 0][:args.show],
        "scam": [{"boost": r["boost"], "category": r["category"], "reasons": r["reasons"],
                  "names": r["names"][:8]} for r in sorted(scam, key=lambda r: -r["boost"])[:args.show]],
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out + ".json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1)
    with open(args.out + ".md", "w", encoding="utf-8") as f:
        f.write(markdown(report))
    print(markdown(report))
    print(f"wrote {args.out}.json and {args.out}.md")


def _hist(h):
    return ", ".join(f"{k}: {v:,}" for k, v in h.items()) or "-"


def markdown(r) -> str:
    L, m, lv = [], r["live_meta"], r["live"]
    g = sum(r["gate_reasons"].values()) or 1
    L += ["# Stage 2 evaluation (certificate check, v1 points table)", "",
          f"Generated {r['generated']} on {r['machine']} by `python -m model.stage2 eval`. "
          "Era-stable features only (names on the certificate; no issuer, no dates). "
          "Names below are plain text: do not open them.", "",
          "## Points table", "", "| feature | at least | points |", "|---|---:|---:|"]
    L += [f"| `{f}` | {mn} | +{p:.2f} |" for f, mn, p, _ in r["points_table"]]
    L += ["", f"Capped at {r['max_boost']}. A certificate that also covers an official site "
          "(labels/official.txt) gets 0. Stage 2 can only raise a score: "
          "`final = 1 - (1 - s1) * (1 - boost)`.", "",
          "## Live certificates (the false-boost check)", "",
          f"Recording `{m['recording']}`: **{m['certs']:,} unique certificates**, {m['names']:,} names. "
          f"**{m['gated_certs']:,} certificates** ({m['gated_names']:,} names, "
          f"{m['gated_names'] / max(1, m['names']):.2%} of names) pass the brand gate; only these "
          "reach Stage 2. Almost all of them are ordinary sites, so a good table boosts ~none.", "",
          "| | v1 table (this PR) | spec §7 example table |", "|---|---:|---:|",
          f"| gated live certs boosted | **{lv['boosted']:,} ({lv['boosted_share']:.2%})** | "
          f"{lv['spec_example_boosted']:,} ({lv['spec_example_boosted_share']:.2%}) |",
          f"| boost histogram | {_hist(lv['boost_histogram'])} | {_hist(lv['spec_example_histogram'])} |",
          "", "Rule fires on gated live certs: " + (_hist(lv["rule_fires"])), "",
          "Why live names pass the brand gate (input for `gate_rate`, MODEL_SPEC §6.2):", "",
          "| reason | names | share |", "|---|---:|---:|"]
    L += [f"| {k} | {v:,} | {v / g:.1%} |" for k, v in r["gate_reasons"].items()]
    if "scam" in r:
        sm, sc = r["scam_meta"], r["scam"]
        L += ["", "## Known scam certificates (crt.sh)", "",
              f"Brand-tagged toll/delivery/gov scams from `labels.db` (outside feeds only). "
              f"{sm['domains_queried']} registered domains queried on crt.sh: "
              f"{sm['domains_with_certs']} had certificates, {sm['domains_no_certs']} had none logged, "
              f"{sm['domains_errors']} errors. **{sm['certs']} certificates** "
              f"({_hist(sm['by_category'])}).", "",
              "| | v1 table | spec example |", "|---|---:|---:|",
              f"| scam certs boosted | **{sc['boosted']} ({sc['boosted_share']:.1%})** | "
              f"{sc['spec_example_boosted']} ({sc['spec_example_boosted_share']:.1%}) |",
              f"| boost histogram | {_hist(sc['boost_histogram'])} | {_hist(sc['spec_example_histogram'])} |",
              "", "Rule fires: " + _hist(sc["rule_fires"]), "",
              "Names per scam certificate (p50/p90/p99/max): "
              + "/".join(str(x) for x in sc["features_p50_p90_p99_max"]["n_names"])]
    if "labels_kits" in r:
        k = r["labels_kits"]
        L += ["", "## How kit-like are known scams? (labels.db)", "",
              f"Of {k['registered_domains']:,} registered domains with toll/delivery/gov scams, "
              f"{k['with_2plus_listed_names']:,} have 2+ listed names and {k['with_2plus_brands']:,} "
              "have 2+ different brands. The multi-brand ones are mostly shared hosting, not kits: "
              + ", ".join(f"{d} ({n} names: {'/'.join(b)})" for d, n, b in k["top_multi_brand_domains"])
              + ". So most real scams are one name on one throwaway domain: Stage 2 rarely fires, "
              "and when it can't tell, it adds nothing (a plain certificate is neutral)."]
    cold, hot = r["speed_us_cold_cached"]
    L += ["", "## Speed", "", f"`boost()`: {cold} µs for a new certificate, {hot} µs for the next "
          "name on the same certificate (cached), one core. Only gated names reach it "
          f"({m['gated_names']:,} in the whole recording).", ""]
    ex = r["examples"]
    L += ["## Examples (plain text)", "", "Live certificates boosted by v1:", ""]
    L += [f"- {e['boost']:.2f}: {', '.join(e['names'])} ({'; '.join(e['reasons'])})"
          for e in ex["live_boosted"]] or ["- none"]
    L += ["", "Live certificates the spec example table would boost but v1 does not (first few):", ""]
    L += [f"- {e['spec_example']:.2f}: {', '.join(e['names'])}" for e in ex["live_boosted_by_spec_example_only"][:12]] or ["- none"]
    if ex["scam"]:
        L += ["", "Known scam certificates:", ""]
        L += [f"- {e['boost']:.2f} [{e['category']}]: {', '.join(e['names'])}"
              + (f" ({'; '.join(e['reasons'])})" if e["reasons"] else "") for e in ex["scam"]]
    return "\n".join(L) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m model.stage2", description="Stage 2 certificate check")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("dump", help="gated live certificates from a recording -> JSONL")
    d.add_argument("--recording", required=True)
    d.add_argument("--out", required=True)
    e = sub.add_parser("explain", help="features + boost for one leaf_cert JSON file")
    e.add_argument("cert")
    e.add_argument("host", nargs="?")
    v = sub.add_parser("eval", help="report on gated live certs (+ known scam certs)")
    v.add_argument("--live", required=True, help="output of `dump`")
    v.add_argument("--scam", help="output of model/stage2_crtsh.py")
    v.add_argument("--labels-db", help="labels.db: also report how kit-like known scams are")
    v.add_argument("--show", type=int, default=25)
    v.add_argument("--out", default="reports/stage2_eval")
    args = p.parse_args(argv)
    {"explain": cmd_explain, "eval": cmd_eval, "dump": cmd_dump}[args.cmd](args)


if __name__ == "__main__":
    main()
