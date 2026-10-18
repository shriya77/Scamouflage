#!/usr/bin/env python3
"""
Scamouflage — labels/feeds.py  (owner: Vaishnavi)

Collects REAL, public lists of known phishing sites, keeps the toll / delivery /
government lures, and stores them as labelled examples for the model.

    python3 labels/feeds.py peek          # download every feed once, print counts (no saving)
    python3 labels/feeds.py pull          # download every feed once and save ALL phishing names
    python3 labels/feeds.py history       # one-time: add Unit 42's published smishing domains
    python3 labels/feeds.py loop          # pull every hour forever (run inside tmux)
    python3 labels/feeds.py negatives     # build legitimate examples from the Tranco top-1M list
    python3 labels/feeds.py crtsh 300     # look up certificate times on crt.sh for 300 positives (slow)
    python3 labels/feeds.py export        # write data/positives.csv and data/negatives.csv
    python3 labels/feeds.py stats         # print what is in the database
    python3 labels/feeds.py tranco 100000 # popular-site guard table tranco_top for Stage 0
    python3 labels/feeds.py platforms 20  # write labels/hosting_platforms.txt for Stage 3

Safety: this script only downloads TEXT LISTS. It never visits a scam site.
Do not open any domain it prints in a browser.
"""
import csv
import datetime as dt
import io
import json
import os
import random
import re
import sqlite3
import sys
import time
import urllib.parse
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.environ.get("SCAM_DATA", os.path.join(ROOT, "data"))
DB_PATH = os.environ.get("SCAM_DB", os.path.join(DATA, "labels.db"))
BRANDS_FILE = os.path.join(ROOT, "labels", "brands.txt")
UA = "Scamouflage-research/1.0 (IBM Z Datathon; lists only)"

# Live feeds: plain text or CSV. Every URL / domain inside is pulled out with a regex,
# so the exact column layout of each feed does not matter.
FEEDS = {
    "openphish":          "https://openphish.com/feed.txt",
    "phishunt":           "https://phishunt.io/feed.txt",
    "phishing_database":  "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    "phishing_db_mirror": "https://phish.co.za/latest/phishing-domains-ACTIVE.txt",
    "phishing_army":      "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "malware_filter":     "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt",
    "cert_pl":            "https://hole.cert.pl/domains/domains.txt",
}

# One-time history: Unit 42 (Palo Alto Networks) published smishing IOCs on GitHub.
# These are the same "Smishing Triad" toll / USPS / DMV campaigns. `history` also asks
# GitHub for EVERY smishing file in that repo, not just these two.
UNIT42_API = "https://api.github.com/repos/PaloAltoNetworks/Unit42-timely-threat-intel/contents"
HISTORY = {
    "unit42_2025_03": "https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2025-03-06-IOCs-for-smishing-activity.txt",
    "unit42_2025_04": "https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2025-04-23-IOCs-for-smishing-activity-update.txt",
}

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

HOST_RE = re.compile(r"(?:[a-z][a-z0-9+.\-]*://)?((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9\-]{1,62})", re.I)


# ----------------------------------------------------------------------------- helpers
def now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def log(msg):
    print(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def fetch(url, timeout=90):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def load_brands():
    """brands.txt lines look like:  ezpass,toll   (word, category). # = comment."""
    brands = []
    with open(BRANDS_FILE) as f:
        for line in f:
            line = line.split("#", 1)[0].strip().lower()
            if not line:
                continue
            word, _, cat = line.partition(",")
            brands.append((word.strip(), (cat.strip() or "other")))
    return sorted(brands, key=lambda b: -len(b[0]))  # most specific word wins


try:
    import tldextract
    _EXTRACT = tldextract.TLDExtract(
        suffix_list_urls=(),
        cache_dir=os.path.join(DATA, ".tld_cache"),
        include_psl_private_domains=True
    )
except Exception:  # package missing: crude fallback, good enough for most names
    _EXTRACT = None


def registered_domain(host):
    """ezpass.com-xyz.win -> com-xyz.win   (the part someone actually bought)."""
    if _EXTRACT is not None:
        e = _EXTRACT(host)
        if e.domain and e.suffix:
            return f"{e.domain}.{e.suffix}"
    parts = host.split(".")
    two_level = {"co.uk", "com.au", "com.br", "co.in", "com.cn", "co.jp", "com.mx", "co.za"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in two_level:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def clean_host(raw):
    h = raw.strip().strip(".").lower()
    if h.startswith("www."):
        h = h[4:]
    if h.startswith("*."):
        h = h[2:]
    try:
        h = h.encode("idna").decode("ascii") if not h.isascii() else h
    except Exception:
        return None
    if len(h) > 253 or "." not in h or re.fullmatch(r"[\d.]+", h):
        return None
    return h


def refang(text):
    return (text.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
                .replace("hxxp", "http").replace("[:]", ":"))


def hosts_in(text):
    out = set()
    for m in HOST_RE.finditer(refang(text)):
        h = clean_host(m.group(1))
        if h and (_EXTRACT is None or _EXTRACT(h).suffix):
            out.add(h)
    return out


def match_brand(host, brands):
    """Return (brand, category) or None. Short words must start a token so 'irs' does not match 'first'."""
    tokens = [t for t in re.split(r"[^a-z0-9]+", host) if t]
    for word, cat in brands:
        if len(word) <= 4:
            if any(t == word or t.startswith(word) for t in tokens):
                return word, cat
        elif word in host:
            return word, cat
    return None


# ----------------------------------------------------------------------------- database
def db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript("""
    CREATE TABLE IF NOT EXISTS labels (
        host        TEXT NOT NULL,          -- full name, e.g. ezpass.com-xyz.win
        domain      TEXT NOT NULL,          -- registered part, e.g. com-xyz.win
        brand       TEXT,                   -- matched brand word
        category    TEXT,                   -- toll / delivery / gov / other
        feed        TEXT NOT NULL,          -- which list it came from
        first_seen  TEXT NOT NULL,          -- when WE first saw it on that list (UTC)
        last_seen   TEXT NOT NULL,
        PRIMARY KEY (host, feed)
    );
    CREATE INDEX IF NOT EXISTS labels_domain ON labels(domain);
    CREATE TABLE IF NOT EXISTS negatives (
        host TEXT PRIMARY KEY, domain TEXT, source TEXT, added TEXT
    );
    CREATE TABLE IF NOT EXISTS crtsh (
        host TEXT PRIMARY KEY, first_cert TEXT, n_certs INTEGER, checked TEXT
    );
    CREATE TABLE IF NOT EXISTS pulls (
        feed TEXT, at TEXT, http_ok INTEGER, hosts INTEGER, brand_hits INTEGER, new_rows INTEGER
    );
    """)
    return con


def save_hosts(con, feed, hosts, brands):
    """Save EVERY phishing name (the model learns general 'phishy' patterns from all of them).
    brand/category are filled in when a toll / delivery / gov word matches, else category='other'."""
    ts, hits, new = now(), 0, 0
    for h in hosts:
        b = match_brand(h, brands)
        hits += bool(b)
        cur = con.execute(
            "INSERT OR IGNORE INTO labels(host, domain, brand, category, feed, first_seen, last_seen) "
            "VALUES (?,?,?,?,?,?,?)",
            (h, registered_domain(h), b[0] if b else None, b[1] if b else "other", feed, ts, ts))
        if cur.rowcount == 1:
            new += 1
        else:
            con.execute("UPDATE labels SET last_seen=? WHERE host=? AND feed=?", (ts, h, feed))
    con.commit()
    return hits, new


# ----------------------------------------------------------------------------- commands
def pull(sources, save=True):
    brands = load_brands()
    con = db() if save else None
    total_new = 0
    for name, url in sources.items():
        try:
            text = fetch(url).decode("utf-8", "replace")
            ok = 1
        except Exception as e:
            log(f"{name:18s} FAILED to download: {type(e).__name__}: {e}")
            if con:
                con.execute("INSERT INTO pulls VALUES (?,?,?,?,?,?)", (name, now(), 0, 0, 0, 0))
                con.commit()
            continue
        hosts = hosts_in(text)
        if save:
            hits, new = save_hosts(con, name, hosts, brands)
            con.execute("INSERT INTO pulls VALUES (?,?,?,?,?,?)", (name, now(), ok, len(hosts), hits, new))
            con.commit()
            total_new += new
            log(f"{name:18s} {len(hosts):>8,} phishing names | {hits:>6,} toll/delivery/gov | {new:>7,} new")
        else:
            matched = sorted(h for h in hosts if match_brand(h, brands))
            log(f"{name:18s} {len(hosts):>8,} phishing names | {len(matched):>6,} toll/delivery/gov")
            for h in matched[:5]:
                print(f"{'':22s}e.g. {h}")
    if save:
        log(f"done: {total_new:,} new scam names saved to {DB_PATH}")


def unit42_sources():
    """Every smishing IOC file in Unit 42's public GitHub repo (falls back to the two known ones)."""
    try:
        items = json.loads(fetch(UNIT42_API))
        found = {f"unit42_{i['name'][:10]}_{n}": i["download_url"] for n, i in enumerate(items)
                 if i.get("type") == "file" and re.search(r"smish|toll|usps|triad", i["name"], re.I)}
        if found:
            log(f"found {len(found)} smishing files in the Unit 42 repo")
            return found
    except Exception as e:
        log(f"could not list the Unit 42 repo ({type(e).__name__}); using the two known files")
    return HISTORY


def loop(every=3600):
    while True:
        try:
            pull(FEEDS)
        except Exception as e:  # never die overnight
            log(f"pull crashed: {e!r}")
        log(f"sleeping {every // 60} minutes (Ctrl+C to stop)")
        time.sleep(every)


def negatives(n=30000, seed=7):
    """Legitimate examples: a random sample of real popular sites (Tranco top 1M), plus the
    official toll / postal / government sites from labels/official.txt.
    Sites that contain a brand word are KEPT on purpose (e.g. a real 'usps' tracking site),
    so the model learns that a brand word alone does not mean scam. Anything already on a
    phishing list is removed."""
    con = db()
    log("downloading Tranco top-1M list (about 10 MB)...")
    raw = fetch(TRANCO_URL, timeout=300)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        rows = z.read(z.namelist()[0]).decode().splitlines()
    names = [r.split(",", 1)[1].strip().lower() for r in rows if "," in r]
    # remove only names that are themselves on a scam list (not all of github.io or firebaseapp.com)
    positives = {r[0] for r in con.execute("SELECT DISTINCT host FROM labels")}
    random.Random(seed).shuffle(names)
    added, ts = 0, now()
    for h in names:
        if added >= n:
            break
        h = clean_host(h)
        if not h or h in positives:
            continue
        con.execute("INSERT OR IGNORE INTO negatives VALUES (?,?,?,?)", (h, registered_domain(h), "tranco", ts))
        added += 1
    official = os.path.join(ROOT, "labels", "official.txt")
    n_off = 0
    if os.path.exists(official):
        for line in open(official):
            h = clean_host(line.split("#", 1)[0])
            if h:
                con.execute("INSERT OR REPLACE INTO negatives VALUES (?,?,?,?)", (h, registered_domain(h), "official", ts))
                n_off += 1
    con.commit()
    log(f"saved {added:,} legitimate examples from Tranco + {n_off} official sites")


def tranco(n=100000):
    """Popular-site guard for Stage 0: table tranco_top(host, rank, added) = the Tranco top-N names.
    Stage 0 drops a known-scam entry if that exact name is a top site (e.g. nflxvideo.net, rank ~400, which a
    feed listed by mistake). Rebuilt in one transaction, so Stage 0 never sees a half-written table."""
    con = db()
    log(f"downloading Tranco top-1M list to keep the top {n:,}...")
    raw = fetch(TRANCO_URL, timeout=300)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        rows = z.read(z.namelist()[0]).decode().splitlines()
    top, ts = [], now()
    for r in rows:
        if "," not in r:
            continue
        rank, name = r.split(",", 1)
        h = clean_host(name)
        if h and rank.strip().isdigit() and int(rank) <= n:
            top.append((h, int(rank), ts))
    with con:
        con.execute("CREATE TABLE IF NOT EXISTS tranco_top (host TEXT PRIMARY KEY, rank INTEGER, added TEXT)")
        con.execute("DELETE FROM tranco_top")
        con.executemany("INSERT OR IGNORE INTO tranco_top VALUES (?,?,?)", top)
    log(f"tranco_top: {len(top):,} popular names saved (ranks 1-{n:,})")


def platforms(min_hosts=20):
    """Write labels/hosting_platforms.txt: registered domains hosting >= min_hosts DIFFERENT known scam names
    (weebly.com, 000webhostapp.com, ...). Stage 3 must not treat these domains' age as proof of a real business."""
    con = db()
    rows = con.execute("SELECT domain, COUNT(DISTINCT host) AS n FROM labels WHERE domain IS NOT NULL "
                       "GROUP BY domain HAVING n >= ? ORDER BY n DESC", (min_hosts,)).fetchall()
    path = os.path.join(ROOT, "labels", "hosting_platforms.txt")
    with open(path, "w") as f:
        f.write(f"# generated by `labels/feeds.py platforms {min_hosts}` on {now()}\n")
        f.write(f"# registered domains hosting >= {min_hosts} different known scam names (count after #)\n")
        for d, k in rows:
            f.write(f"{d}  # {k}\n")
    log(f"wrote {path}: {len(rows):,} platforms; top: " + ", ".join(f"{d} ({k:,})" for d, k in rows[:8]))


def crtsh(limit=300, pause=13):
    """When was the first certificate for each scam name issued? crt.sh allows ~5 requests/minute."""
    con = db()
    todo = [r[0] for r in con.execute(
        "SELECT DISTINCT l.host FROM labels l LEFT JOIN crtsh c ON c.host=l.host "
        "WHERE c.host IS NULL AND l.brand IS NOT NULL ORDER BY l.first_seen DESC LIMIT ?", (limit,))]
    log(f"{len(todo)} names to look up on crt.sh, one every {pause}s (~{len(todo) * pause // 60} min)")
    for i, h in enumerate(todo, 1):
        try:
            data = json.loads(fetch(f"https://crt.sh/?q={urllib.parse.quote(h)}&output=json", timeout=60) or b"[]")
            times = sorted(d.get("entry_timestamp") or d.get("not_before") for d in data if d)
            con.execute("INSERT OR REPLACE INTO crtsh VALUES (?,?,?,?)", (h, times[0] if times else None, len(data), now()))
            con.commit()
            log(f"{i}/{len(todo)} {h}: {len(data)} certs, first {times[0] if times else '-'}")
        except Exception as e:
            log(f"{i}/{len(todo)} {h}: {type(e).__name__} (will retry next run)")
        time.sleep(pause)


def export():
    con = db()
    os.makedirs(DATA, exist_ok=True)
    pos = con.execute("""
        SELECT l.host, l.domain, l.brand, l.category,
               GROUP_CONCAT(DISTINCT l.feed) AS feeds, COUNT(DISTINCT l.feed) AS n_feeds,
               MIN(l.first_seen) AS first_listed, c.first_cert
        FROM labels l LEFT JOIN crtsh c ON c.host = l.host
        GROUP BY l.host ORDER BY first_listed""").fetchall()
    with open(os.path.join(DATA, "positives.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["host", "domain", "brand", "category", "feeds", "n_feeds", "first_listed", "first_cert", "label"])
        for r in pos:
            w.writerow(list(r) + [1])
    neg = con.execute("SELECT host, domain, source, added FROM negatives").fetchall()
    with open(os.path.join(DATA, "negatives.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["host", "domain", "source", "added", "label"])
        for r in neg:
            w.writerow(list(r) + [0])
    log(f"wrote data/positives.csv ({len(pos):,} rows) and data/negatives.csv ({len(neg):,} rows)")


def stats():
    con = db()
    print("\nScam names by feed:")
    for r in con.execute("SELECT feed, COUNT(*), MIN(first_seen), MAX(last_seen) FROM labels GROUP BY feed ORDER BY 2 DESC"):
        print(f"  {r[0]:18s} {r[1]:>7,}   first {r[2]}   last {r[3]}")
    print("\nBy category:")
    for r in con.execute("SELECT category, COUNT(DISTINCT host) FROM labels GROUP BY category ORDER BY 2 DESC"):
        print(f"  {r[0]:10s} {r[1]:>7,}")
    print("\nTop brands:")
    for r in con.execute("SELECT brand, COUNT(DISTINCT host) FROM labels WHERE brand IS NOT NULL GROUP BY brand ORDER BY 2 DESC LIMIT 12"):
        print(f"  {r[0]:12s} {r[1]:>7,}")
    u = con.execute("SELECT COUNT(DISTINCT host), COUNT(DISTINCT domain) FROM labels").fetchone()
    n = con.execute("SELECT COUNT(*) FROM negatives").fetchone()[0]
    c = con.execute("SELECT COUNT(*), COUNT(first_cert) FROM crtsh").fetchone()
    print(f"\nUnique scam names: {u[0]:,} ({u[1]:,} registered domains) | legitimate: {n:,} | crt.sh checked: {c[0]:,} ({c[1]:,} with a cert)\n")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "peek"
    arg = int(sys.argv[2]) if len(sys.argv) > 2 else None
    if cmd == "peek":
        pull({**FEEDS, **unit42_sources()}, save=False)
    elif cmd == "pull":
        pull(FEEDS)
    elif cmd == "history":
        pull(unit42_sources())
    elif cmd == "loop":
        loop()
    elif cmd == "negatives":
        negatives(arg or 30000)
    elif cmd == "crtsh":
        crtsh(arg or 300)
    elif cmd == "export":
        export()
    elif cmd == "stats":
        stats()
    elif cmd == "tranco":
        tranco(arg or 100000)
    elif cmd == "platforms":
        platforms(arg or 20)
    else:
        print(__doc__)
