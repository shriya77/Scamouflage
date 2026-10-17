"""
Tests for model/stage0.py (the known-scam list). Builds a tiny labels.db with the same schema as
labels/feeds.py. Every test name is a reserved name (.test / .example / .invalid) or a public
suffix (github.io): fixtures, not data, and never real scam domains.
Run:  python3 -m pytest tests/test_stage0.py -q      (or: python3 tests/test_stage0.py)
"""
import os
import shutil
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from model import stage0  # noqa: E402
from model.stage0 import KnownList, default_db_path  # noqa: E402

# Same CREATE TABLE statements as labels/feeds.py db().
SCHEMA = """
CREATE TABLE IF NOT EXISTS labels (
    host        TEXT NOT NULL,
    domain      TEXT NOT NULL,
    brand       TEXT,
    category    TEXT,
    feed        TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
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
"""

TS = "2026-10-17T15:00:00+00:00"

# (host, brand, category, feed) as feeds.py stores them: category "other" when no brand.
LABELS = [
    ("ezpass.com-abc.test", "ezpass", "toll", "cert_pl"),
    ("ezpass.com-abc.test", None, "other", "phishing_army"),   # same host, second feed
    ("bad.test", None, "other", "phishing_database"),           # a listed registered domain
    ("x.sib.test", None, "other", "openphish"),                 # a listed SUBdomain only
    ("evil.github.io", None, "other", "phishunt"),              # one tenant of shared hosting
    ("github.io", None, "other", "phishing_army"),              # poisoned: a public suffix
    ("bigplatform.test", None, "other", "malware_filter"),      # poisoned: also a negative
    ("hosting.example", None, "other", "cert_pl"),              # registered domain of a negative
    ("ezdrive.test", "ezdrive", "toll", "cert_pl"),             # poisoned: an official site
    ("pay.ezdrive.test", "ezdrive", "toll", "cert_pl"),         # poisoned: under an official site
    ("WWW.Mixed.TEST.", None, "other", "cert_pl"),              # needs cleaning on load
    ("usps.com-track.invalid", "usps", "delivery", "unit42_2025-03-06_264"),
    ("1.2.3.4", None, "other", "cert_pl"),                      # junk: an IP
]
NEGATIVES = [
    ("bigplatform.test", "bigplatform.test", "tranco"),
    ("docs.hosting.example", "hosting.example", "tranco"),
    ("ezdrive.test", "ezdrive.test", "official"),
]
OFFICIAL = "# test allowlist\nezdrive.test\n"


class Fixture:
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="stage0-test-")
        self.db = os.path.join(self.dir, "labels.db")
        self.official = os.path.join(self.dir, "official.txt")
        with open(self.official, "w") as f:
            f.write(OFFICIAL)
        con = self.connect()
        con.executescript(SCHEMA)
        for h, b, c, feed in LABELS:
            self.add(h, b, c, feed, con)
        for h, d, src in NEGATIVES:
            con.execute("INSERT INTO negatives VALUES (?,?,?,?)", (h, d, src, TS))
        con.commit()
        con.close()

    def connect(self):
        con = sqlite3.connect(self.db, timeout=30)
        con.execute("PRAGMA journal_mode=WAL")  # like feeds.py
        return con

    def add(self, host, brand=None, category="other", feed="cert_pl", con=None):
        own = con is None
        con = con or self.connect()
        con.execute("INSERT OR IGNORE INTO labels VALUES (?,?,?,?,?,?,?)",
                    (host, host, brand, category, feed, TS, TS))
        if own:
            con.commit()
            con.close()

    def known(self):
        return KnownList(self.db, official_file=self.official)

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def with_fixture(fn):
    def run():
        fx = Fixture()
        try:
            fn(fx)
        finally:
            fx.close()
    run.__name__ = fn.__name__
    return run


@with_fixture
def test_exact_hit(fx):
    kl = fx.known()
    assert kl.check("ezpass.com-abc.test") == {"brand": "ezpass", "category": "toll", "feed": "cert_pl"}
    assert kl.explain("ezpass.com-abc.test")[1] == "exact"
    assert kl.check("usps.com-track.invalid")["category"] == "delivery"


@with_fixture
def test_registered_domain_hit(fx):
    kl = fx.known()
    res, rule, listed = kl.explain("sub.bad.test")
    assert res == {"brand": None, "category": "other", "feed": "phishing_database"}
    assert (rule, listed) == ("registered-domain", "bad.test")
    assert kl.explain("a.b.c.bad.test")[1] == "registered-domain"
    # a subdomain of the exact-listed toll scam also matches through its registered domain? No:
    # its registered domain is com-abc.test, which is not listed.
    assert kl.check("pay.ezpass.com-abc.test") is None


@with_fixture
def test_unlisted_sibling_is_miss(fx):
    kl = fx.known()
    assert kl.check("good.test") is None
    assert kl.check("bad2.test") is None
    # x.sib.test is listed, but sib.test (its registered domain) is not: siblings stay clean
    assert kl.check("x.sib.test") is not None
    assert kl.check("y.sib.test") is None
    assert kl.check("sib.test") is None


@with_fixture
def test_shared_hosting_does_not_spread(fx):
    kl = fx.known()
    assert kl.explain("evil.github.io")[1] == "exact"
    assert kl.check("www.evil.github.io") is not None    # www. is cleaned off
    assert kl.check("other.github.io") is None
    assert kl.check("deep.other.github.io") is None
    # "github.io" itself was listed (poisoned feed) and must be dropped as a public suffix
    assert kl.check("github.io") is None
    assert kl.summary()["removed_rows"]["public_suffix"] == 1


@with_fixture
def test_negatives_and_official_guards(fx):
    kl = fx.known()
    s = kl.summary()
    # on both the scam list and the negatives table -> dropped (as in build_dataset.py)
    assert kl.check("bigplatform.test") is None
    assert kl.check("login.bigplatform.test") is None
    assert s["removed_rows"]["both_lists"] == 1
    # official site and a name under it -> dropped
    assert kl.check("ezdrive.test") is None
    assert kl.check("pay.ezdrive.test") is None
    assert s["removed_rows"]["official"] == 2
    # hosting.example is a negative's registered domain: still an exact hit,
    # but rule (b) must not flag every name under it
    assert kl.explain("hosting.example")[1] == "exact"
    assert kl.check("phish.hosting.example") is None
    assert s["rule_b_blocked_hosts"] == 1
    assert s["negatives_hosts"] == 3 and s["official_hosts"] == 1


@with_fixture
def test_cleaning_wildcard_www_uppercase(fx):
    kl = fx.known()
    for raw in ("*.ezpass.com-abc.test", "www.ezpass.com-abc.test", "EZPASS.COM-ABC.TEST",
                "ezpass.com-abc.test.", "  Ezpass.Com-Abc.Test  ", "*.WWW.ezpass.com-abc.test"):
        assert kl.check(raw) is not None, raw
    # the stored row "WWW.Mixed.TEST." was cleaned when loading
    assert kl.explain("mixed.test")[1] == "exact"
    assert kl.check("www.MIXED.test") is not None


@with_fixture
def test_counts(fx):
    s = fx.known().summary()
    assert s["rows_read"] == len(LABELS)
    assert s["junk_rows"] == 1            # 1.2.3.4
    assert s["duplicate_rows"] == 1       # ezpass.com-abc.test on a second feed
    # 13 rows - 1 junk - 1 duplicate - 4 guarded = 7 hosts
    assert s["unique_hosts"] == 7, s


@with_fixture
def test_branded_metadata_wins_for_duplicates(fx):
    fx.add("track.com-zzz.test", None, "other", "phishing_army")
    fx.add("track.com-zzz.test", "usps", "delivery", "cert_pl")
    kl = fx.known()
    assert kl.check("track.com-zzz.test") == {"brand": "usps", "category": "delivery",
                                               "feed": "phishing_army"}


@with_fixture
def test_refresh_adds_only_new_rows(fx):
    kl = fx.known()
    n = len(kl)
    assert kl.refresh() == 0
    assert kl.check("new-scam.test") is None
    fx.add("new-scam.test", "ezpass", "toll", "phishunt")
    assert kl.refresh() == 1
    assert kl.check("new-scam.test") == {"brand": "ezpass", "category": "toll", "feed": "phishunt"}
    assert len(kl) == n + 1
    assert kl.refresh() == 0
    # same host from another feed, and a last_seen update: nothing new
    fx.add("new-scam.test", None, "other", "cert_pl")
    con = fx.connect()
    con.execute("UPDATE labels SET last_seen='2026-10-18T00:00:00+00:00'")
    con.commit()
    con.close()
    assert kl.refresh() == 0
    # new rows still go through the guards
    fx.add("login.ezdrive.test")
    assert kl.refresh() == 0 and kl.check("login.ezdrive.test") is None


@with_fixture
def test_refresh_while_writer_is_busy(fx):
    kl = fx.known()
    writer = fx.connect()
    writer.execute("BEGIN IMMEDIATE")
    writer.execute("INSERT INTO labels VALUES (?,?,?,?,?,?,?)",
                   ("pending.test", "pending.test", None, "other", "cert_pl", TS, TS))
    assert kl.refresh() == 0                  # not committed yet: not visible, no blocking
    writer.commit()
    writer.close()
    assert kl.refresh() == 1
    assert kl.check("pending.test") is not None


@with_fixture
def test_refresh_falls_back_to_full_reload(fx):
    kl = fx.known()
    con = fx.connect()
    con.execute("DELETE FROM labels WHERE host='bad.test'")
    con.commit()
    con.close()
    kl.refresh()                              # row count no longer adds up -> full reload
    assert kl.check("bad.test") is None
    assert kl.check("ezpass.com-abc.test") is not None


@with_fixture
def test_new_negative_removes_listed_host(fx):
    kl = fx.known()
    assert kl.check("bad.test") is not None
    con = fx.connect()
    con.execute("INSERT INTO negatives VALUES ('bad.test','bad.test','tranco',?)", (TS,))
    con.commit()
    con.close()
    assert kl.refresh() == 0
    assert kl.check("bad.test") is None and kl.check("sub.bad.test") is None


@with_fixture
def test_garbage_input_returns_none(fx):
    kl = fx.known()
    for bad in ("", None, "....", ".", "*.", "   ", "a..b.test", "1.2.3.4", "no-dot", 123, b"bad.test",
                ["bad.test"], "bad test.test", "\x00.test"):
        assert kl.check(bad) is None, repr(bad)


def test_missing_db_and_default_path():
    try:
        KnownList(os.path.join(tempfile.gettempdir(), "does-not-exist-stage0.db"))
        raise AssertionError("expected FileNotFoundError")
    except FileNotFoundError:
        pass
    old = os.environ.pop("LABELS_DB", None)
    try:
        assert default_db_path() == os.path.expanduser("~/scamouflage-data/labels.db")
        os.environ["LABELS_DB"] = "/tmp/x/labels.db"
        assert default_db_path() == "/tmp/x/labels.db"
    finally:
        os.environ.pop("LABELS_DB", None)
        if old is not None:
            os.environ["LABELS_DB"] = old


def test_fast_clean_matches_engine_clean():
    import random
    from model.features import clean_host
    cases = ["ezpass.com-abc.test", "EZPASS.com-abc.test", "*.a.test", "*.*.a.test", "www.a.test",
             "*.www.a.test", "a.test.", ".a.test", "-a.test", "a..test", "1.2.3.4", "1.2.3",
             "::1", "a.test ", " a.test", "www.", "*.", "", None, 7, "xn--bcher-kva.test", "a_b.test"]
    rnd = random.Random(0)
    alphabet = "ab1.-*wW_ :"
    cases += ["".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 12))) for _ in range(20000)]
    for c in cases:
        assert stage0.clean(c) == clean_host(c), repr(c)


def test_registered_domain_helper():
    rd = stage0.registered_domain
    assert rd("evil.github.io") == "evil.github.io"
    assert rd("a.evil.github.io") == "evil.github.io"
    assert rd("github.io") is None
    assert rd("sub.bad.test") == "bad.test"      # not on the PSL: last two labels
    assert stage0.is_public_suffix("github.io") and not stage0.is_public_suffix("evil.github.io")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok ", fn.__name__)
    print(f"{len(fns)} passed")
