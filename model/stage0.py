"""
Scamouflage — model/stage0.py  (owner: Shriya)

Stage 0: is this name already on a known-scam list? (MODEL_SPEC §3, §4.3, §5)

    kl = KnownList(default_db_path())    # loads every listed host into memory (once)
    kl.check("pay.ezpass.com-abc.test")  # {"brand": .., "category": .., "feed": ..} or None
    kl.refresh()                         # every 15 min: reads only rows added since the last read

Match rule (§4.3): a name is a hit if
  (a) the cleaned name itself is listed ("exact"), or
  (b) its REGISTERED domain is itself listed as a host ("registered-domain").
The registered domain comes from tldextract with the private part of the Public Suffix List on,
so x.github.io / x.pages.dev / x.firebaseapp.com are their own registered domains: one listed
github.io site never flags the others. Only the bundled PSL snapshot is used (never downloaded).
A name whose ending is not on the PSL at all (new TLDs, .test) uses its last two labels.

Guards against poisoned feeds (phishing feeds sometimes list big legitimate names):
  - public_suffix: a listed name that is itself a public suffix (github.io, co.uk) is skipped.
  - official:      a listed name that is, or is under, a site in labels/official.txt is skipped.
  - both_lists:    a listed name that is also in the `negatives` table (Tranco + official) is
                   skipped, the same rule as labels/build_dataset.py.
  - tranco_top:    a listed name that is itself in the optional `tranco_top` table (Tranco's top N
                   by rank, NOT minus the scam lists) is skipped. So a noisy feed listing a big site
                   (nflxvideo.net) cannot flag every name under it. A listed name UNDER a top site
                   (evil.weebly.com) is kept and still matches exactly. No table: no guard.
  - rule (b) never fires through a registered domain that is in `negatives` (as a host or as a
    negative's domain) or in official.txt. The name itself still matches exactly. Rule (b) only
    fires through a registered domain that is itself listed, and a tranco_top name is never in
    the list, so rule (b) never fires through one either.

Refresh column: `rowid`. feeds.py inserts new rows with INSERT OR IGNORE (rowid only grows) and
rewrites `last_seen` on EVERY existing row each pull, so "last_seen > last refresh" would re-read
almost the whole table every hour. `first_seen` is stamped when a pull starts but committed when
it ends, so a refresh in between could miss rows. If the table shrinks or is replaced (rowid going
backwards, row count not adding up, a different file, tranco_top changed), refresh() falls back
to a full reload.

SQLite is opened read-only (mode=ro, timeout=30) for each load and closed straight after, so the
feeds loop can keep writing (the DB is in WAL mode; readers never block it). Never queried per
certificate. No network: no HTTP, DNS or RDAP anywhere in this module.

CLI (prints names as plain text, never links):
    python -m model.stage0 stats [--db PATH]
    python -m model.stage0 check [--db PATH] host1 host2 ...
    python -m model.stage0 bench [--db PATH] --names FILE_OR_RECORDING [--n 200000]
"""
from __future__ import annotations

import argparse
import functools
import gzip
import json
import logging
import os
import pathlib
import re
import sqlite3
import sys
import time
from collections import Counter

import tldextract

from .features import ROOT, clean_host

log = logging.getLogger("scamouflage.stage0")

REFRESH_COLUMN = "rowid"
OFFICIAL_FILE = os.path.join(ROOT, "labels", "official.txt")
GUARDS = ("public_suffix", "official", "both_lists", "tranco_top")

# Bundled PSL snapshot only (suffix_list_urls=()), no disk cache, private domains on.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                                 include_psl_private_domains=True)


def _psl_sets():
    plain, wild, exc = set(), set(), set()
    for s in _EXTRACT.tlds:
        s = s.lower()
        if s.startswith("*."):
            wild.add(s[2:])
        elif s.startswith("!"):
            exc.add(s[1:])
        else:
            plain.add(s)
    return plain, wild, exc


_PSL, _PSL_WILD, _PSL_EXC = _psl_sets()


def default_db_path() -> str:
    """$LABELS_DB if set, else the shared ~/scamouflage-data/labels.db."""
    return os.path.expanduser(os.environ.get("LABELS_DB") or "~/scamouflage-data/labels.db")


def is_public_suffix(host: str) -> bool:
    """True for names like "github.io" or "co.uk" that nobody can register as a site."""
    if host in _PSL:
        return True
    if host in _PSL_EXC:
        return False
    parent = host.partition(".")[2]
    return bool(parent) and parent in _PSL_WILD


@functools.lru_cache(maxsize=1 << 16)
def registered_domain(host: str) -> str | None:
    """pay.ezpass.com-abc.win -> ezpass.com-abc.win, evil.github.io -> evil.github.io.
    None if the name is itself a public suffix."""
    e = _EXTRACT(host)
    if e.suffix:
        return f"{e.domain}.{e.suffix}" if e.domain else None
    parts = host.rsplit(".", 2)  # ending not on the PSL: last two labels
    return ".".join(parts[-2:]) if len(parts) >= 2 else None


def _parents(host: str):
    """a.b.c.d -> b.c.d, c.d  (every parent with at least two labels)."""
    i = host.find(".")
    while i != -1:
        rest = host[i + 1:]
        if "." not in rest:
            return
        yield rest
        i = host.find(".", i + 1)


_ALREADY_CLEAN = re.compile(r"[a-z0-9.-]*[a-z-][a-z0-9.-]*")


def clean(raw) -> str | None:
    """features.clean_host (the engine's cleaning), with a fast path for names that are already
    clean: lowercase [a-z0-9.-] with a letter or hyphen (so never an IP address), no leading
    "www.", no trailing dot, no "..". For those clean_host returns the name unchanged, so the
    result is identical; it just skips ~4 us of work per name. Everything else goes to clean_host."""
    if (type(raw) is str and _ALREADY_CLEAN.fullmatch(raw) and "." in raw and ".." not in raw
            and not raw.endswith(".") and not raw.startswith(("www.", "."))):
        return raw
    return clean_host(raw)


def rss_mb() -> tuple[float, str]:
    """(megabytes, "current" | "peak"). Linux reads /proc; elsewhere only the peak is known."""
    try:
        with open("/proc/self/statm") as f:
            return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE") / 1e6, "current"
    except (OSError, ValueError):
        import resource
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return (r / 1e6 if sys.platform == "darwin" else r / 1e3), "peak"


class KnownList:
    def __init__(self, db_path: str | None = None, official_file: str = OFFICIAL_FILE):
        self.db_path = os.path.abspath(os.path.expanduser(db_path or default_db_path()))
        if not os.path.exists(self.db_path):
            raise FileNotFoundError(f"no labels DB at {self.db_path} (set LABELS_DB or pass db_path)")
        self.official_file = official_file
        t0 = time.perf_counter()
        self._reset()
        con = self._connect()
        try:
            con.execute("BEGIN")  # one consistent snapshot while the feeds loop writes
            neg_hosts, self._neg_fp = self._table_hosts(con, "negatives")
            if self._neg_fp is None:
                log.warning("Stage 0: no negatives table; both_lists guard is off")
            top, self._top_fp = self._table_hosts(con, "tranco_top")
            if self._top_fp is None:
                log.info("Stage 0: no tranco_top table; tranco_top guard is off")
            self.n_negatives, self.n_tranco_top = len(neg_hosts), len(top)
            self._read_rows(con, 0, neg_hosts, top)
            del neg_hosts, top
            self._rd_blocked = self._blocked_among(con, self.hosts)
        finally:
            con.close()
        self.load_seconds = time.perf_counter() - t0
        log.info("Stage 0: %d hosts from %d rows in %.1f s", len(self.hosts), self.rows_seen,
                 self.load_seconds)

    # ------------------------------------------------------------------ loading
    def _reset(self):
        # host -> (brand, category, feed). The tuples are shared: one per distinct combination,
        # so 500k+ hosts cost one dict slot each, not one object each. (Measured on the VM: a
        # dict with shared values is smaller than a set of the same strings.)
        self.hosts: dict[str, tuple] = {}
        self._meta: dict[tuple, tuple] = {}
        self._rd_blocked: set[str] = set()   # listed, but rule (b) must not fire through them
        self._removed: dict[str, str] = {}   # host -> guard that removed it
        self.removed_rows = Counter()        # guard -> rows removed
        self.rows_seen = 0                   # rows read so far (everything up to the watermark)
        self.junk_rows = 0                   # host empty / an IP / not a name after cleaning
        self.duplicate_rows = 0              # same host from another feed
        self.watermark = 0                   # highest rowid read
        self._neg_fp = None                  # (count, max rowid, max added) of negatives
        self._top_fp = None                  # same for tranco_top (None: no such table)
        self.n_negatives = 0
        self.n_tranco_top = 0
        self._official = self._read_official()
        self._inode = os.stat(self.db_path).st_ino

    def _connect(self) -> sqlite3.Connection:
        uri = pathlib.Path(self.db_path).as_uri() + "?mode=ro"
        return sqlite3.connect(uri, uri=True, timeout=30, isolation_level=None)

    def _meta_for(self, brand, category, feed) -> tuple:
        key = (brand or None, category or None, feed or None)
        m = self._meta.get(key)
        if m is None:
            m = self._meta[key] = tuple(sys.intern(x) if x else None for x in key)
        return m

    def _read_official(self) -> frozenset:
        out = set()
        if self.official_file and os.path.exists(self.official_file):
            with open(self.official_file, encoding="utf-8") as f:
                for line in f:
                    h = clean(line.split("#", 1)[0])
                    if h:
                        out.add(h)
        return frozenset(out)

    @staticmethod
    def _table_fp(con, table: str):
        """(row count, max rowid, max added) of a guard table, or None if there is no such table.
        `added` matters: a rebuild (DELETE + INSERT) of the same size reuses rowids from 1."""
        try:
            return tuple(con.execute(f"SELECT COUNT(*), MAX(rowid), MAX(added) FROM {table}")
                         .fetchone())
        except sqlite3.OperationalError:
            return None

    def _table_hosts(self, con, table: str) -> tuple[set, tuple | None]:
        """Cleaned hosts of a guard table (negatives ~300k, tranco_top ~100k names), and its
        fingerprint. Only held while loading. (empty set, None) if there is no such table."""
        out = set()
        try:
            for (h,) in con.execute(f"SELECT host FROM {table}"):
                h = clean(h)
                if h:
                    out.add(h)
        except sqlite3.OperationalError:
            return out, None
        return out, self._table_fp(con, table)

    def _blocked_among(self, con, pool) -> set:
        """Listed hosts (in pool) that are some negative's registered domain: rule (b) must not
        fire through them. Streams the table instead of holding another 300k-name set."""
        out = set()
        try:
            for (d,) in con.execute("SELECT domain FROM negatives"):
                d = clean(d)
                if d and d in pool:
                    out.add(d)
        except sqlite3.OperationalError:
            pass
        return out

    def _drop_reason(self, h: str, neg_hosts: set, top: set) -> str | None:
        if is_public_suffix(h):
            return "public_suffix"
        official = self._official
        if h in official or any(p in official for p in _parents(h)):
            return "official"
        if h in neg_hosts:
            return "both_lists"
        # Only the name itself: tenants under a top site (evil.weebly.com) keep their exact match.
        # Dropping the top site is also what keeps rule (b) from firing through it.
        if h in top:
            return "tranco_top"
        return None

    def _read_rows(self, con, after_rowid: int, neg_hosts: set, top: set, added_hosts=None) -> int:
        """Load rows with rowid > after_rowid. Returns how many new hosts were added."""
        hosts, added = self.hosts, 0
        rows = con.execute("SELECT rowid, host, brand, category, feed FROM labels "
                           "WHERE rowid > ? ORDER BY rowid", (after_rowid,))
        for rowid, raw, brand, category, feed in rows:
            self.rows_seen += 1
            self.watermark = rowid
            h = clean(raw)
            if not h:
                self.junk_rows += 1
                continue
            old = hosts.get(h)
            if old is not None:
                self.duplicate_rows += 1
                if old[0] is None and brand:  # keep the branded row's metadata
                    hosts[h] = self._meta_for(brand, category, old[2])
                continue
            reason = self._removed.get(h) or self._drop_reason(h, neg_hosts, top)
            if reason:
                self.removed_rows[reason] += 1
                self._removed[h] = reason
                continue
            hosts[h] = self._meta_for(brand, category, feed)
            added += 1
            if added_hosts is not None:
                added_hosts.append(h)
        return added

    # ------------------------------------------------------------------ refresh
    def refresh(self) -> int:
        """Load only rows added since the last read. Returns how many new hosts were added.
        Safe while the feeds loop writes (short read-only snapshot). Never raises."""
        try:
            if os.stat(self.db_path).st_ino != self._inode:
                return self._full_reload("the DB file was replaced")
            if self._read_official() != self._official:
                return self._full_reload("labels/official.txt changed")
            con = self._connect()
            try:
                con.execute("BEGIN")
                max_rowid, total = con.execute("SELECT MAX(rowid), COUNT(*) FROM labels").fetchone()
                max_rowid = max_rowid or 0
                if max_rowid < self.watermark:
                    return self._full_reload(f"max rowid went back ({max_rowid} < {self.watermark})")
                new = con.execute("SELECT COUNT(*) FROM labels WHERE rowid > ?",
                                  (self.watermark,)).fetchone()[0]
                if total != self.rows_seen + new:
                    return self._full_reload(f"row count {total} != {self.rows_seen} read + {new} new")
                if self._table_fp(con, "tranco_top") != self._top_fp:  # rebuilt, added or dropped
                    return self._full_reload("the tranco_top table changed")
                neg_changed = self._table_fp(con, "negatives") != self._neg_fp
                if new == 0 and not neg_changed:
                    return 0
                neg_hosts, self._neg_fp = self._table_hosts(con, "negatives")
                self.n_negatives = len(neg_hosts)
                if neg_changed:  # a listed host may now be a known-good site
                    for h in neg_hosts:
                        if self.hosts.pop(h, None) is not None:
                            self._removed[h] = "both_lists"
                top = self._table_hosts(con, "tranco_top")[0] if new else set()
                new_hosts = []
                added = self._read_rows(con, self.watermark, neg_hosts, top, new_hosts)
                del neg_hosts, top
                if neg_changed:
                    self._rd_blocked = self._blocked_among(con, self.hosts)
                elif new_hosts:
                    self._rd_blocked |= self._blocked_among(con, set(new_hosts))
            finally:
                con.close()
            log.info("Stage 0 refresh: +%d hosts (%d now), watermark rowid %d",
                     added, len(self.hosts), self.watermark)
            return added
        except Exception:
            log.exception("Stage 0 refresh failed; keeping the current list")
            return 0

    def _full_reload(self, why: str) -> int:
        log.warning("Stage 0: full reload because %s", why)
        fresh = KnownList(self.db_path, self.official_file)
        before = len(self.hosts)
        self.__dict__.update(fresh.__dict__)  # swap in one step; check() keeps working
        return max(0, len(self.hosts) - before)

    # ------------------------------------------------------------------ check
    def explain(self, host) -> tuple[dict | None, str | None, str | None]:
        """(result, rule, listed name). rule is "exact" or "registered-domain". Never raises."""
        try:
            if not isinstance(host, str):
                return None, None, None
            h = clean(host)
            if not h:
                return None, None, None
            hosts = self.hosts
            meta = hosts.get(h)
            if meta is not None:
                return self._out(meta), "exact", h
            # Rule (b). The registered domain is always one of the parents, so ask the PSL only
            # when some parent is listed at all (almost never), and then only once (cached).
            for p in _parents(h):
                if p in hosts:
                    rd = registered_domain(h)
                    if rd and rd != h and rd not in self._rd_blocked:
                        meta = hosts.get(rd)
                        if meta is not None:
                            return self._out(meta), "registered-domain", rd
                    break
            return None, None, None
        except Exception:
            return None, None, None

    def check(self, host: str) -> dict | None:
        """{"brand": str|None, "category": str|None, "feed": str|None} if known, else None."""
        return self.explain(host)[0]

    @staticmethod
    def _out(meta: tuple) -> dict:
        return {"brand": meta[0], "category": meta[1], "feed": meta[2]}

    def __len__(self):
        return len(self.hosts)

    def __contains__(self, host):
        return self.check(host) is not None

    def summary(self) -> dict:
        removed_hosts = Counter(self._removed.values())
        return {
            "db": self.db_path, "rows_read": self.rows_seen, "unique_hosts": len(self.hosts),
            "duplicate_rows": self.duplicate_rows, "junk_rows": self.junk_rows,
            "removed_rows": {g: self.removed_rows[g] for g in GUARDS},
            "removed_hosts": {g: removed_hosts[g] for g in GUARDS},
            "rule_b_blocked_hosts": len(self._rd_blocked),
            "negatives_hosts": self.n_negatives,
            "tranco_top_hosts": self.n_tranco_top if self._top_fp is not None else None,
            "official_hosts": len(self._official),
            "watermark_rowid": self.watermark, "refresh_column": REFRESH_COLUMN,
            "load_seconds": round(self.load_seconds, 2),
        }


# ---------------------------------------------------------------------- CLI
def _iter_certs(path: str):
    """Lists of names: one per certificate from a CT recording (.jsonl / .jsonl.gz), or one
    single-name list per line of a text file."""
    if ".jsonl" in os.path.basename(path):
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
                yield list(leaf.get("all_domains") or [])
    else:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    yield [line]


def _load(db: str) -> tuple[KnownList, float, float, str]:
    before, kind = rss_mb()
    try:
        kl = KnownList(db)
    except FileNotFoundError as e:
        sys.exit(f"error: {e}")
    after, _ = rss_mb()
    return kl, before, after, kind


def cmd_stats(args):
    kl, before, after, kind = _load(args.db)
    s = kl.summary()
    print(f"DB:                 {s['db']}")
    print(f"rows read:          {s['rows_read']:,}  (watermark rowid {s['watermark_rowid']:,}, "
          f"refresh column: {s['refresh_column']})")
    print(f"unique hosts:       {s['unique_hosts']:,}")
    print(f"duplicate rows:     {s['duplicate_rows']:,}  (same host on another feed)")
    print(f"junk rows:          {s['junk_rows']:,}  (not a usable name after cleaning)")
    print("guards (rows removed / unique hosts removed):")
    for g in GUARDS:
        print(f"  {g:14s}    {s['removed_rows'][g]:>8,} / {s['removed_hosts'][g]:,}")
    print(f"  rule (b) off for  {s['rule_b_blocked_hosts']:>8,} listed hosts that are a negative's "
          f"registered domain (still match exactly)")
    top = s["tranco_top_hosts"]
    print(f"guard inputs:       {s['negatives_hosts']:,} negatives hosts, "
          + (f"{top:,} tranco_top hosts, " if top is not None else "no tranco_top table (guard off), ")
          + f"{s['official_hosts']} official hosts, {len(_PSL):,} PSL suffixes "
          f"(tldextract {tldextract.__version__}, bundled)")
    cats = Counter(m[1] for m in kl.hosts.values())
    brands = Counter(m[0] for m in kl.hosts.values() if m[0])
    feeds = Counter(m[2] for m in kl.hosts.values())
    print("categories (unique hosts): " + ", ".join(f"{c} {n:,}" for c, n in cats.most_common()))
    print(f"branded hosts: {sum(brands.values()):,}; top brands: "
          + ", ".join(f"{b} {n:,}" for b, n in brands.most_common(12)))
    print("feed (first listed by): " + ", ".join(f"{f} {n:,}" for f, n in feeds.most_common(8)))
    print(f"distinct metadata tuples: {len(kl._meta):,}")
    print(f"load time:          {s['load_seconds']:.2f} s")
    print(f"memory (RSS, {kind}): {before:,.1f} MB before load -> {after:,.1f} MB after "
          f"(+{after - before:,.1f} MB)")
    t0 = time.perf_counter()
    n = kl.refresh()
    print(f"refresh():          +{n:,} hosts in {time.perf_counter() - t0:.2f} s")


def cmd_check(args):
    kl, *_ = _load(args.db)
    for raw in args.hosts:
        res, rule, listed = kl.explain(raw)
        if res:
            via = f" via {listed}" if rule == "registered-domain" else ""
            print(f"HIT   {raw}  rule={rule}{via}  brand={res['brand']}  category={res['category']}  "
                  f"feed={res['feed']}")
        else:
            print(f"miss  {raw}")


def cmd_bench(args):
    kl, before, after, kind = _load(args.db)
    names, cert_of = [], []  # cert_of[i] = which certificate names[i] came from
    t0 = time.perf_counter()
    for c, cert in enumerate(_iter_certs(args.names)):
        for name in cert[:args.n - len(names)]:
            names.append(name)
            cert_of.append(c)
        if len(names) >= args.n:
            break
    n_certs = cert_of[-1] + 1 if cert_of else 0
    print(f"read {len(names):,} names ({len(set(names)):,} unique) from {n_certs:,} certificates "
          f"in {args.names} in {time.perf_counter() - t0:.1f} s")
    registered_domain.cache_clear()  # cold cache: the honest number
    check, hits, hit_idx = kl.check, [], []
    t0 = time.perf_counter()
    for i, n in enumerate(names):
        if check(n) is not None:
            hits.append(n)
            hit_idx.append(i)
    dt = time.perf_counter() - t0
    print(f"checks/s:  {len(names) / dt:,.0f}  ({len(names):,} checks in {dt:.2f} s, one core)")
    print(f"hits:      {len(hits):,}  ({len(set(hits)):,} unique names)  "
          f"hit rate {len(hits) / max(1, len(names)):.4%}")
    hit_certs = len({cert_of[i] for i in hit_idx})
    print(f"certificates with a known name: {hit_certs:,} of {n_certs:,} "
          f"({hit_certs / max(1, n_certs):.4%})")
    rules = Counter(kl.explain(h)[1] for h in hits)
    print("by rule:   " + (", ".join(f"{r} {c:,}" for r, c in rules.most_common()) or "-"))
    cats = Counter(kl.check(h)["category"] for h in hits)
    print("by category: " + (", ".join(f"{c} {n:,}" for c, n in cats.most_common()) or "-"))
    print(f"memory (RSS, {kind}): {before:,.1f} -> {after:,.1f} MB for the list; "
          f"rd cache {registered_domain.cache_info().currsize:,} entries")
    print(f"first {min(args.show, len(set(hits)))} unique hits (plain text, do not open):")
    seen = set()
    for h in hits:
        if h in seen:
            continue
        seen.add(h)
        res, rule, listed = kl.explain(h)
        via = f" via {listed}" if rule == "registered-domain" else ""
        print(f"  {h}  [{rule}{via}; {res['category']}; {res['brand'] or '-'}; {res['feed']}]")
        if len(seen) >= args.show:
            break


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m model.stage0", description="Stage 0 known-scam list")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("stats", "check", "bench"):
        sp = sub.add_parser(name)
        sp.add_argument("--db", default=default_db_path(), help="labels.db (default: $LABELS_DB "
                        "or ~/scamouflage-data/labels.db)")
        if name == "check":
            sp.add_argument("hosts", nargs="+")
        if name == "bench":
            sp.add_argument("--names", required=True, help="text file (one name per line) or "
                            "a CT recording ct-*.jsonl.gz")
            sp.add_argument("--n", type=int, default=200_000)
            sp.add_argument("--show", type=int, default=20, help="how many unique hits to print")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    {"stats": cmd_stats, "check": cmd_check, "bench": cmd_bench}[args.cmd](args)


if __name__ == "__main__":
    main()
