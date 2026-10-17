"""
Scamouflage — model/stage2_crtsh.py  (owner: Shriya)

Real certificates of KNOWN toll / delivery / gov scam sites, for tuning and checking Stage 2
(MODEL_SPEC §4.4 "Positives (b): crt.sh lookups for brand-tagged known-scam hosts").

    python -m model.stage2_crtsh --labels-db ~/tolltrap/data/labels.db \\
        --out ~/tolltrap/data/stage2/crtsh_scam_certs.jsonl --domains 120 --per-domain 2

For each brand-tagged known-scam REGISTERED domain (from the labels table, i.e. confirmed by
outside feeds, never our own detections):
  1. ask crt.sh which certificates exist for it  (https://crt.sh/?q=<domain>&output=json);
  2. take the newest `--per-domain` certificates (one per serial: precert and cert are the same);
  3. download each certificate (https://crt.sh/?d=<id>) and read its full SAN list.

Safety: the ONLY host contacted is crt.sh. The scam domain is a search term; it is never
resolved or visited. Output goes to the data folder (git-ignored), never to the repo.
Resumable: domains already in --out are skipped. Polite: one request every --pause seconds,
retries with backoff on 429 / 5xx / timeouts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography import x509

from .stage0 import registered_domain
from .features import clean_host

UA = "Scamouflage-research/1.0 (IBM Z Datathon; CT log search only)"
CRTSH = "https://crt.sh/"


def fetch(url: str, timeout: float, tries: int = 3, pause: float = 5.0) -> bytes:
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 504) or attempt == tries - 1:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == tries - 1:
                raise
        time.sleep(pause * (2 ** attempt))
    raise RuntimeError("unreachable")


def scam_domains(db: str, n: int) -> list[tuple[str, str, str]]:
    """[(registered domain, category, brand)], brand-tagged known scams, stable order mixing
    categories (sha256 of the domain), one entry per registered domain."""
    con = sqlite3.connect("file:" + os.path.abspath(db) + "?mode=ro", uri=True, timeout=30)
    rows = con.execute("SELECT host, category, brand FROM labels "
                       "WHERE category IN ('toll','delivery','gov') AND brand IS NOT NULL").fetchall()
    con.close()
    by_rd = {}
    for host, cat, brand in rows:
        h = clean_host(host)
        rd = registered_domain(h) if h else None
        if rd and rd not in by_rd:
            by_rd[rd] = (cat, brand)
    order = sorted(by_rd, key=lambda d: hashlib.sha256(d.encode()).hexdigest())
    return [(d, *by_rd[d]) for d in order[:n]]


def sans_of(pem: bytes) -> list[str]:
    cert = x509.load_pem_x509_certificate(pem)
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return [n.lower() for n in ext.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        return []


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--labels-db", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--domains", type=int, default=120, help="how many scam registered domains")
    p.add_argument("--per-domain", type=int, default=2, help="newest certificates per domain")
    p.add_argument("--pause", type=float, default=3.0, help="seconds between crt.sh requests")
    p.add_argument("--timeout", type=float, default=90.0)
    args = p.parse_args(argv)

    done = set()
    if os.path.exists(args.out):
        with open(args.out, encoding="utf-8") as f:
            for line in f:
                try:
                    done.add(json.loads(line)["query_domain"])
                except (ValueError, KeyError):
                    pass
    todo = [t for t in scam_domains(os.path.expanduser(args.labels_db), args.domains) if t[0] not in done]
    print(f"{len(done)} domains already done, {len(todo)} to fetch", flush=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    n_certs = 0
    with open(args.out, "a", encoding="utf-8") as out:
        for i, (rd, cat, brand) in enumerate(todo, 1):
            status, certs = "ok", []
            try:
                q = CRTSH + "?" + urllib.parse.urlencode({"q": rd, "output": "json"})
                rows = json.loads(fetch(q, args.timeout) or b"[]")
                time.sleep(args.pause)
                newest, serials = [], set()
                for r in sorted(rows, key=lambda r: r.get("not_before") or "", reverse=True):
                    if r.get("serial_number") in serials:
                        continue
                    serials.add(r.get("serial_number"))
                    newest.append(r)
                    if len(newest) >= args.per_domain:
                        break
                for r in newest:
                    pem = fetch(CRTSH + "?" + urllib.parse.urlencode({"d": r["id"]}), args.timeout)
                    time.sleep(args.pause)
                    certs.append({"crtsh_id": r["id"], "not_before": r.get("not_before"),
                                  "all_domains": sans_of(pem)})
                if not rows:
                    status = "no_certs"
            except Exception as e:  # keep going; record what failed
                status = f"error: {type(e).__name__}"
            rec = {"query_domain": rd, "category": cat, "brand": brand, "status": status, "certs": certs}
            out.write(json.dumps(rec) + "\n")
            out.flush()
            n_certs += len(certs)
            print(f"{i}/{len(todo)} {rd} [{cat}] {status}: {len(certs)} certs "
                  f"({', '.join(str(len(c['all_domains'])) for c in certs)} names)", flush=True)
    print(f"done: {n_certs} certificates written to {args.out}")


if __name__ == "__main__":
    sys.exit(main())
