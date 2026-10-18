"""
Tests for the computed risk fields on /api/alerts (api/server.py): risk = score x freshness x
brand weight, risk_level, risk_reasons, campaign_size and ?sort=risk.
Run:  python3 -m pytest tests/test_risk.py -q      (or: python3 tests/test_risk.py)
"""
import os
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tests.test_api import make_db, run, with_dir  # noqa: E402

import api.server as S  # noqa: E402  (pure functions; reloaded per endpoint test by load_server)


def test_freshness_buckets():
    cases = [(0, 1.0), (0.99, 1.0), (1, 0.9), (6.99, 0.9), (7, 0.75), (29.9, 0.75), (30, 0.55),
             (364.9, 0.55), (365, 0.35), (4000, 0.35),
             (None, 0.7), ("abc", 0.7), (-1, 0.7), (float("nan"), 0.7), ("2.5", 0.9)]
    for age, want in cases:
        assert S.freshness(age) == want, (age, S.freshness(age), want)


def test_brand_weight_and_names():
    for brand in ("ezpass", "E-ZPass", "e-zpass", "EPASS", "SunPass", "txtag", "NTTA", "I-PASS",
                  "usps", "UPS", "FedEx", "dhl", "IRS", "dmv"):
        assert S.brand_key(brand) in S.BIG_BRANDS, brand
    for brand in ("parcel", "toll", "paypal", "", None):
        assert S.brand_key(brand) not in S.BIG_BRANDS, brand


def test_risk_math_example():
    # 0.97 x 1.0 (9 hours old) x 1.0 (DHL) = 97
    r = S.risk_fields({"score": 0.97, "age_days": 9 / 24, "brand": "dhl"})
    assert r == {"risk": 97, "risk_level": "High",
                 "risk_reasons": ["Model 0.97", "Registered 9h ago", "Big brand: DHL"]}
    # 0.9 x 0.75 (10 days) x 0.8 (not a big brand) = 54
    r = S.risk_fields({"score": 0.9, "age_days": 10, "brand": "parcel"})
    assert (r["risk"], r["risk_level"]) == (54, "Medium")
    assert r["risk_reasons"] == ["Model 0.90", "Registered 10 days ago"]
    # unknown age 0.7, no brand 0.8: 0.95 x 0.7 x 0.8 = 53.2 -> 53
    r = S.risk_fields({"score": 0.95})
    assert r["risk"] == 53 and r["risk_reasons"] == ["Model 0.95", "Registration date unknown"]
    # old domain: 1.0 x 0.35 x 1.0 = 35
    r = S.risk_fields({"score": 1.0, "age_days": 800, "brand": "E-ZPass"})
    assert (r["risk"], r["risk_level"]) == (35, "Low")
    assert r["risk_reasons"] == ["Model 1.00", "Registered 2 years ago", "Big brand: E-ZPass"]


def test_risk_levels_at_the_edges():
    fresh_big = {"age_days": 0, "brand": "usps"}  # freshness 1.0, weight 1.0: risk = score x 100
    for score, risk, level in ((0.80, 80, "High"), (0.79, 79, "Medium"), (0.50, 50, "Medium"),
                               (0.49, 49, "Low"), (1.0, 100, "High"), (0.0, 0, "Low")):
        r = S.risk_fields({"score": score, **fresh_big})
        assert (r["risk"], r["risk_level"]) == (risk, level), (score, r)


def test_risk_is_clamped_and_tolerant():
    assert S.risk_fields({"score": 1.7, "age_days": 0, "brand": "dhl"})["risk"] == 100
    assert S.risk_fields({"score": -3})["risk"] == 0
    assert S.risk_fields({"score": None})["risk"] == 0
    assert S.risk_fields({"score": "x"})["risk"] == 0


def test_age_text():
    assert [S.age_text(a) for a in (0.001, 0.5, 1, 1.9, 2, 364, 365, 731)] == \
        ["1h", "12h", "1 day", "1 day", "2 days", "364 days", "1 year", "2 years"]


def test_registered_site_and_campaign_size():
    assert S.registered_site("pay.ezpass.com-xk2.win") == "com-xk2.win"
    assert S.registered_site("*.Track.Parcel-UK.co.uk.") == "parcel-uk.co.uk"
    assert S.registered_site("a.dhl1.pages.dev") == "dhl1.pages.dev"
    rows = [{"domain": d, "score": 0.9} for d in
            ("a.com-xk2.win", "b.com-xk2.win", "com-xk2.win", "x.pages.dev", "y.pages.dev")]
    S.add_risk(rows)
    assert [r["campaign_size"] for r in rows] == [3, 3, 3, 1, 1]


def add_risk_columns(d):
    """make_db's alerts table plus brand/age_days, and a third alert on usps-pay.test's site."""
    con = sqlite3.connect(os.path.join(d, "scamouflage.db"))
    con.execute("ALTER TABLE alerts ADD COLUMN brand TEXT")
    con.execute("ALTER TABLE alerts ADD COLUMN age_days REAL")
    con.execute("UPDATE alerts SET brand = 'usps', age_days = 0.1 WHERE id = 1")   # 0.97 -> 97
    con.execute("UPDATE alerts SET brand = NULL, age_days = 500 WHERE id = 2")     # 1.0 x 0.35 x 0.8 = 28
    con.execute("INSERT INTO alerts VALUES (3, 'ccc', 'www.usps-pay.test', '[]', 0.6, '[]', 3.0, 2, "
                "'delivery', 'c2ln', 'ed25519:x', 'usps', 3)")                      # 0.6 x 0.9 = 54
    con.commit()
    con.close()


@with_dir
def test_alerts_endpoint_adds_fields_and_keeps_order(d):
    make_db(d)
    add_risk_columns(d)

    async def check(c, server):
        body = await (await c.get("/api/alerts")).json()
        items = body["items"]
        assert body["source"] == "live" and [a["id"] for a in items] == [3, 2, 1]   # newest first
        by_id = {a["id"]: a for a in items}
        assert (by_id[1]["risk"], by_id[1]["risk_level"]) == (97, "High")
        assert by_id[1]["risk_reasons"] == ["Model 0.97", "Registered 2h ago", "Big brand: USPS"]
        assert (by_id[2]["risk"], by_id[2]["risk_level"]) == (28, "Low")
        assert (by_id[3]["risk"], by_id[3]["risk_level"]) == (54, "Medium")
        assert [by_id[i]["campaign_size"] for i in (1, 2, 3)] == [2, 1, 2]
        # existing fields unchanged
        assert by_id[1]["reasons"] == ["Pretends to be USPS"] and by_id[1]["score"] == 0.97
        assert by_id[1]["domain"] == "usps-pay.test" and by_id[1]["sig"] == "c2ln"
        # explicit newest is the same as the default
        same = (await (await c.get("/api/alerts?sort=newest")).json())["items"]
        assert [a["id"] for a in same] == [3, 2, 1]
    run(check, d)


@with_dir
def test_alerts_sort_by_risk(d):
    make_db(d)
    add_risk_columns(d)
    con = sqlite3.connect(os.path.join(d, "scamouflage.db"))   # a tie with id 1 (risk 97), but newer
    con.execute("INSERT INTO alerts VALUES (4, 'ddd', 'tie.test', '[]', 0.97, '[]', 4.0, 2, "
                "'delivery', 'c2ln', 'ed25519:x', 'dhl', 0.2)")
    con.commit()
    con.close()

    async def check(c, server):
        items = (await (await c.get("/api/alerts?sort=risk")).json())["items"]
        assert [(a["id"], a["risk"]) for a in items] == [(4, 97), (1, 97), (3, 54), (2, 28)]
        items = (await (await c.get("/api/alerts?sort=risk&limit=2")).json())["items"]
        assert [a["id"] for a in items] == [4, 3]       # sorts the newest `limit` alerts
        items = (await (await c.get("/api/alerts?sort=risk&stage=0")).json())["items"]
        assert [a["id"] for a in items] == [2]
        r = await c.get("/api/alerts?sort=bogus")
        assert r.status == 400 and "sort" in (await r.json())["error"]
    run(check, d)


@with_dir
def test_alerts_without_brand_or_age_columns(d):
    make_db(d)   # older DB: no brand / age_days columns at all

    async def check(c, server):
        items = (await (await c.get("/api/alerts")).json())["items"]
        by_id = {a["id"]: a for a in items}
        assert by_id[1]["risk"] == round(0.97 * 0.7 * 0.8 * 100) == 54
        assert by_id[1]["risk_reasons"] == ["Model 0.97", "Registration date unknown"]
        assert all(a["campaign_size"] == 1 for a in items)
    run(check, d)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok ", fn.__name__)
    print(f"{len(fns)} passed")
