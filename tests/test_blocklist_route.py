"""
backend/blocklist_route.py: entries for flagged names, and the tranco_top guard.
Run:  python3 -m pytest tests/test_blocklist_route.py -q
"""
import json
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import blocklist_route as B  # noqa: E402

TOP = {"windows-ppe.net", "ups.com"}


def names(payload, wildcard):
    """Entry hashes back to names, using the hostnames the test knows about."""
    known = ["login.windows-ppe.net", "windows-ppe.net", "mobileproxy.inside.ups.com", "inside.ups.com",
             "ups.com", "ezpass.com-xk2.win", "com-xk2.win", "evil.pages.dev"]
    by_hash = {B.sha256_hex(n): n for n in known}
    return sorted(by_hash[e["h"]] for e in payload["entries"] if e["match_subdomains"] == wildcard)


def rows(*hosts):
    return [(h, 1.0, json.dumps(["Already on a known scam list (feed)"]), 1792245600.0) for h in hosts]


def test_targets_for_unchanged_without_top_sites():
    assert B.targets_for("ezpass.com-xk2.win", set()) == [("ezpass.com-xk2.win", False), ("com-xk2.win", True)]
    assert B.targets_for("login.windows-ppe.net", set()) == [("login.windows-ppe.net", False), ("windows-ppe.net", True)]
    assert B.targets_for("evil.pages.dev", set(), TOP) == [("evil.pages.dev", False), ("evil.pages.dev", False)]


def test_a_top_site_is_never_flagged_whole():
    assert B.targets_for("login.windows-ppe.net", set(), TOP) == [("login.windows-ppe.net", False)]
    assert B.targets_for("mobileproxy.inside.ups.com", set(), TOP) == [("mobileproxy.inside.ups.com", False)]
    assert B.targets_for("ups.com", set(), TOP) == [("ups.com", False)]
    assert B.targets_for("ezpass.com-xk2.win", set(), TOP) == [("ezpass.com-xk2.win", False), ("com-xk2.win", True)]


def test_build_payload_with_top_sites():
    r = rows("login.windows-ppe.net", "mobileproxy.inside.ups.com", "ezpass.com-xk2.win")
    before = B.build_payload(r, set(), set(), now=0)
    after = B.build_payload(r, set(), set(), now=0, top_sites=TOP)
    assert names(before, True) == ["com-xk2.win", "ups.com", "windows-ppe.net"]
    assert names(after, True) == ["com-xk2.win"]
    assert names(after, False) == ["ezpass.com-xk2.win", "login.windows-ppe.net", "mobileproxy.inside.ups.com"]


def test_read_top_sites():
    d = tempfile.mkdtemp(prefix="bl-")
    path = os.path.join(d, "labels.db")
    assert B.read_top_sites(path) == set()                      # no file
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE labels (host TEXT)")
    con.commit()
    assert B.read_top_sites(path) == set()                      # no table
    con.execute("CREATE TABLE tranco_top (host TEXT PRIMARY KEY, rank INTEGER, added TEXT)")
    con.executemany("INSERT INTO tranco_top VALUES (?, ?, ?)", [("UPS.com", 638, "t"), ("windows-ppe.net", 14288, "t")])
    con.commit()
    con.close()
    assert B.read_top_sites(path) == TOP


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok ", fn.__name__)
    print(f"{len(fns)} passed")
