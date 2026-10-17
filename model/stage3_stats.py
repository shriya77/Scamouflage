"""
Scamouflage — model/stage3_stats.py  (owner: Shadow)

Evidence statistics for the presentation slide deck (MODEL_SPEC §13 step 11).
Evaluates domain age and registrar distribution over brand-tagged scam domains
from labels.db (metadata only via RDAP, never contacts the sites).

    python -m model.stage3_stats --db ~/tolltrap/data/labels.db --limit 150 --normals 50

Emits:
    reports/stage3_evidence.json
    reports/stage3_evidence.md

Samples (real data only, MODEL_SPEC §2 rule 1; nothing is made up if the DB is missing):
  - scams:   brand-tagged toll / delivery / gov rows of the `labels` table (outside feeds), one
             entry per REGISTERED domain (bundled PSL, private domains on). Names on shared
             hosting (x.github.io, x.pages.dev) are counted and left out: RDAP would describe
             the platform, not the scam.
  - normals: brand-word sites from the `negatives` table (Tranco) plus labels/official.txt.
Every number states its N. Lookups that fail are counted by error, never dropped silently.
"""
import argparse
import datetime as dt
import hashlib
import json
import logging
import os
import sqlite3
import statistics
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model import features as F  # noqa: E402
from model.stage3 import _extract_domain, _parse_iso_datetime, verify  # noqa: E402

log = logging.getLogger("scamouflage.stage3_stats")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REPORTS_DIR = os.path.join(ROOT, "reports")

# Unit 42 smishing triad published figures for comparison
UNIT42_BENCHMARK = {
    "Dominet (HK)": 68.06,
    "NameSilo": 11.85,
    "Gname": 7.94,
    "Others": 12.15,
}


def find_db_path(given: str | None) -> str:
    for c in (given, os.environ.get("LABELS_DB"), os.path.expanduser("~/tolltrap/data/labels.db"),
              os.path.join(ROOT, "data", "labels.db")):
        if c and os.path.exists(os.path.expanduser(c)):
            return os.path.expanduser(c)
    sys.exit("error: no labels.db found (pass --db or set LABELS_DB). No data is made up.")


def _stable(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _ro(db_path: str) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{os.path.abspath(db_path)}?mode=ro", uri=True, timeout=30)


def collect_scam_domains(db_path: str, limit: int = 150) -> tuple[list[dict], dict]:
    """One entry per registered domain: earliest first_seen, its brand and category."""
    conn = _ro(db_path)
    rows = conn.execute("SELECT host, brand, category, first_seen, feed FROM labels "
                        "WHERE brand IS NOT NULL AND category IN ('toll','delivery','gov')").fetchall()
    conn.close()
    by_rd, shared, junk = {}, set(), 0
    for host, brand, cat, first_seen, feed in rows:
        h = F.clean_host(host)
        if not h:
            junk += 1
            continue
        rd, is_shared = _extract_domain(h)
        if not rd:
            junk += 1
            continue
        if is_shared:
            shared.add(rd)
            continue
        cur = by_rd.get(rd)
        if cur is None or (first_seen or "") < (cur["first_seen"] or ""):
            by_rd[rd] = {"domain": rd, "brand": brand, "category": cat,
                         "first_seen": first_seen, "feed": feed}
    order = sorted(by_rd, key=_stable)          # stable, not "newest first"
    meta = {"label_rows": len(rows), "registered_domains": len(by_rd),
            "shared_hosting_names_left_out": len(shared), "junk_rows": junk}
    return [by_rd[d] for d in order[:limit]], meta


def collect_normals(db_path: str, limit: int = 50) -> list[str]:
    """Brand-word sites from Tranco (negatives table) + every official site."""
    conn = _ro(db_path)
    try:
        hosts = [h for (h,) in conn.execute("SELECT host FROM negatives WHERE source = 'tranco'")]
    except sqlite3.OperationalError:
        hosts = []
    conn.close()
    picked = set()
    for h in hosts:
        h = F.clean_host(h)
        if h and F.brand_hits(h):
            rd, is_shared = _extract_domain(h)
            if rd and not is_shared:
                picked.add(rd)
    out = sorted(picked, key=_stable)[:limit]
    return sorted(set(out) | {o for o in F.OFFICIAL if "." in o})


def _days_between(later_iso: str | None, earlier_iso: str | None) -> float | None:
    a, b = _parse_iso_datetime(later_iso), _parse_iso_datetime(earlier_iso)
    if a is None or b is None:
        return None
    return round((a - b).total_seconds() / 86400.0, 2)


def _group(registrar: str | None) -> str:
    low = (registrar or "").lower()
    for key, name in (("dominet", "Dominet (HK)"), ("namesilo", "NameSilo"), ("gname", "Gname")):
        if key in low:
            return name
    return "Others"


def _pct(n, d):
    return round(100.0 * n / d, 1) if d else 0.0


def run_evidence_study(scam_sample: list[dict], normal_sample: list[str]) -> dict:
    print(f"Running RDAP verification study over {len(scam_sample)} scam domains...")
    t0 = time.time()
    scam_results = []
    for idx, item in enumerate(scam_sample):
        v = verify(item["domain"])
        at_first = _days_between(item.get("first_seen"), v.get("registered_at")) if v["ok"] else None
        scam_results.append(dict(item, rdap=v, age_at_first_seen=at_first))
        if (idx + 1) % 25 == 0 or (idx + 1) == len(scam_sample):
            print(f"  Processed {idx + 1}/{len(scam_sample)} domains...")

    print(f"Running RDAP verification over {len(normal_sample)} normal control domains...")
    normal_results = [{"domain": d, "rdap": verify(d)} for d in normal_sample]

    ok = [r for r in scam_results if r["rdap"]["ok"]]
    ages_now = [r["rdap"]["age_days"] for r in ok]
    ages_first = [r["age_at_first_seen"] for r in ok if r["age_at_first_seen"] is not None]
    errors = Counter(r["rdap"]["error"] for r in scam_results if not r["rdap"]["ok"])
    regs = [r["rdap"]["registrar"] for r in ok if r["rdap"].get("registrar")]
    reg_counts = Counter(_group(x) for x in regs)
    risky = sum(1 for r in ok if r["rdap"].get("risky_registrar"))

    n_ok = [r for r in normal_results if r["rdap"]["ok"]]
    n_ages = [r["rdap"]["age_days"] for r in n_ok]

    def under(ages, days):
        c = sum(1 for a in ages if a < days)
        return {"count": c, "pct": _pct(c, len(ages))}

    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration_seconds": round(time.time() - t0, 2),
        "scams": {
            "n_total": len(scam_results),
            "n_ok": len(ok),
            "n_failed_by_error": dict(errors),
            "age_now_median_days": round(statistics.median(ages_now), 2) if ages_now else None,
            "age_at_first_seen_n": len(ages_first),
            "age_at_first_seen_median_days": round(statistics.median(ages_first), 2) if ages_first else None,
            "age_at_first_seen_under": {f"{d}_days": under(ages_first, d) for d in (3, 7, 30, 365)},
            "registrar_n": len(regs),
            "registrar_counts": dict(reg_counts),
            "registrar_shares_pct": {k: _pct(v, len(regs)) for k, v in reg_counts.items()},
            "risky_registrar": {"count": risky, "pct": _pct(risky, len(ok))},
            "unit42_benchmark_pct": UNIT42_BENCHMARK,
            "by_category": dict(Counter(r["category"] for r in scam_results)),
        },
        "normals": {
            "n_total": len(normal_results),
            "n_ok": len(n_ok),
            "n_failed_by_error": dict(Counter(r["rdap"]["error"] for r in normal_results if not r["rdap"]["ok"])),
            "median_age_years": round(statistics.median(n_ages) / 365.0, 2) if n_ages else None,
            "under_365_days": under(n_ages, 365),
            "risky_registrar": sum(1 for r in n_ok if r["rdap"].get("risky_registrar")),
        },
        "live_alerts": None,   # HIGH removed / MAYBE rescued: needs live alerts (not yet)
        "sample_evidence": [
            {"domain": r["domain"], "brand": r.get("brand"), "category": r.get("category"),
             "first_seen": r.get("first_seen"), "registered_at": r["rdap"].get("registered_at"),
             "age_at_first_seen": r["age_at_first_seen"], "age_days": r["rdap"].get("age_days"),
             "registrar": r["rdap"].get("registrar"), "risky_registrar": r["rdap"].get("risky_registrar"),
             "error": r["rdap"].get("error")}
            for r in scam_results[:20]
        ],
    }


def write_reports(study: dict, sample_meta: dict, out_dir: str = REPORTS_DIR) -> tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    study = dict(study, sample=sample_meta)
    json_path = os.path.join(out_dir, "stage3_evidence.json")
    md_path = os.path.join(out_dir, "stage3_evidence.md")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(study, f, indent=2)

    s, n, m = study["scams"], study["normals"], sample_meta
    fails = ", ".join(f"{k}: {v}" for k, v in s["n_failed_by_error"].items()) or "none"
    nfails = ", ".join(f"{k}: {v}" for k, v in n["n_failed_by_error"].items()) or "none"
    u42_scam = round(sum(s["registrar_shares_pct"].get(k, 0.0) for k in ("Dominet (HK)", "NameSilo", "Gname")), 1)
    u42_ref = round(100.0 - UNIT42_BENCHMARK["Others"], 2)
    au = s["age_at_first_seen_under"]

    def fmt_days(x):
        return "-" if x is None else f"{x:,.1f} days"

    lines = [
        "# Stage 3 Domain Verifier Evidence Report", "",
        f"**Generated:** {study['generated_at']} by `python -m model.stage3_stats` "
        "(cached, rate-limited RDAP via rdap.org; registry metadata only, no site is contacted).  ",
        f"**Scam sample:** {s['n_total']} registered domains, picked in a stable hash order from "
        f"{m['registered_domains']:,} brand-tagged toll/delivery/gov registered domains in `labels.db` "
        f"({m['label_rows']:,} label rows; {m['shared_hosting_names_left_out']:,} names on shared "
        "hosting left out because RDAP would describe the platform). "
        f"Categories: {', '.join(f'{k} {v}' for k, v in s['by_category'].items())}.  ",
        f"**Normal sample:** {n['n_total']} brand-word sites from Tranco (`negatives`) plus "
        "`labels/official.txt`.", "",
        "## 1. Key findings (computed, for the slides)", "",
        f"- **Age when we first saw it on a feed:** median **{fmt_days(s['age_at_first_seen_median_days'])}** "
        f"(N={s['age_at_first_seen_n']}); **{au['3_days']['count']} of {s['age_at_first_seen_n']}** "
        f"({au['3_days']['pct']}%) were under 3 days old, {au['30_days']['count']} ({au['30_days']['pct']}%) "
        "under 30 days.",
        f"- **Normal brand-word sites:** median age **{n['median_age_years']} years** (N={n['n_ok']}); "
        f"{n['under_365_days']['count']} of {n['n_ok']} are under a year old.",
        f"- **Registrars:** {u42_scam}% of our scam domains (N={s['registrar_n']}) use the three "
        f"Unit 42 registrars (Dominet, NameSilo, Gname), against {u42_ref}% in Unit 42's Smishing "
        "Triad data. Our sample covers all toll/delivery/gov phishing in the feeds, not only that "
        "one group, so it is far more spread out.",
        f"- **Lookups that failed:** {fails} (of {s['n_total']}). They are counted, not dropped.",
        "",
        "Note: `first_seen` is when OUR feeds loop first saw the name on a list. The loop started on "
        "2026-10-17, so for names that were already listed before then this is an upper bound on "
        "the age at listing, not the age at first listing.", "",
        "## 2. Domain age", "",
        f"| | Scam domains | Normal brand-word sites |", "|---|---:|---:|",
        f"| RDAP answered | {s['n_ok']} of {s['n_total']} | {n['n_ok']} of {n['n_total']} |",
        f"| Median age today | {fmt_days(s['age_now_median_days'])} | "
        f"{n['median_age_years']} years |",
        f"| Median age when first seen on a feed | {fmt_days(s['age_at_first_seen_median_days'])} | - |",
    ]
    for d in (3, 7, 30, 365):
        k = f"{d}_days"
        lines.append(f"| Under {d} days when first seen | {au[k]['count']} ({au[k]['pct']}%) | - |")
    lines += [f"| Under 365 days today | - | {n['under_365_days']['count']} "
              f"({n['under_365_days']['pct']}%) |",
              f"| Failed lookups | {fails} | {nfails} |", "",
              "## 3. Registrar distribution vs Unit 42", "",
              f"| Registrar group | Scamouflage measured (N={s['registrar_n']}) | Unit 42 Smishing Triad |",
              "|---|---:|---:|"]
    for k in ("Dominet (HK)", "NameSilo", "Gname", "Others"):
        lines.append(f"| {k} | {s['registrar_shares_pct'].get(k, 0.0)}% "
                     f"({s['registrar_counts'].get(k, 0)}) | {UNIT42_BENCHMARK[k]}% |")
    lines += ["", f"Risky registrar (labels/risky_registrars.txt) among answered scam domains: "
              f"{s['risky_registrar']['count']} of {s['n_ok']} ({s['risky_registrar']['pct']}%); "
              f"among normal sites: {n['risky_registrar']} of {n['n_ok']}.", "",
              "## 4. Live alerts", "",
              "HIGH removed / MAYBE rescued counts need live alerts from the engine; not available yet.", "",
              "## 5. Sample (plain text, do not open)", "",
              "| Registered domain | Brand | First seen | Registered | Age when first seen | Registrar |",
              "|---|---|---|---|---:|---|"]
    for it in study.get("sample_evidence", []):
        lines.append(f"| {it['domain']} | {it['brand']} | {(it['first_seen'] or '')[:10]} | "
                     f"{(it['registered_at'] or it['error'] or '')[:10]} | {fmt_days(it['age_at_first_seen'])} | "
                     f"{it['registrar'] or '-'} |")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return json_path, md_path


def main():
    p = argparse.ArgumentParser(description="Generate Stage 3 Evidence Stats for Presentation Slides")
    p.add_argument("--db", default=None, help="Path to labels.db (default $LABELS_DB, ~/tolltrap/data/labels.db)")
    p.add_argument("--limit", type=int, default=150, help="Number of scam registered domains to sample")
    p.add_argument("--normals", type=int, default=50, help="Number of normal brand-word sites to sample")
    p.add_argument("--out-dir", default=REPORTS_DIR, help="Where to save reports")
    args = p.parse_args()

    db_path = find_db_path(args.db)
    print(f"Using database: {db_path}")
    scam_sample, meta = collect_scam_domains(db_path, limit=args.limit)
    if not scam_sample:
        sys.exit("error: no brand-tagged toll/delivery/gov rows in labels.db. No data is made up.")
    study = run_evidence_study(scam_sample, collect_normals(db_path, args.normals))
    json_path, md_path = write_reports(study, meta, args.out_dir)
    print("\nEvidence reports successfully written:")
    print(f"  JSON: {json_path}")
    print(f"  Markdown: {md_path}")


if __name__ == "__main__":
    main()
