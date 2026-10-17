"""
Tests for model/stage2.py (the certificate check). Uses the two leaf_cert fixtures and small
certificates built from reserved names (.test / .example). No network.
Run:  python3 -m pytest tests/test_stage2.py -q      (or: python3 tests/test_stage2.py)
"""
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from model import stage2  # noqa: E402
from model.engine import Engine  # noqa: E402
from model.stage2 import MAX_BOOST, Stage2, cert_features, points  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def fixture(name):
    with open(os.path.join(FIX, name)) as f:
        return json.load(f)


def cert(*names, **extra):
    return dict({"all_domains": list(names)}, **extra)


def test_scam_fixture_kit_certificate():
    leaf = fixture("leaf_cert_scam.json")
    f = cert_features(leaf)
    assert f["n_names"] == 4                      # "*.ezpass..." and "ezpass..." count once
    assert f["brand_names_on_cert"] == 4 and f["distinct_brands_on_cert"] == 4
    assert f["fake_pattern_names_on_cert"] == 4 and f["risky_tld_names_on_cert"] == 4
    assert f["wildcard"] == 1 and f["wildcard_brand"] == 1 and f["official_on_cert"] == 0
    s2 = Stage2()
    for h in ("ezpass.com-xk2.win", "sunpass.com-xk2.win", "*.ezpass.com-xk2.win"):
        e = s2.explain(h, leaf)
        assert e["boost"] == 0.55, (h, e)          # 0.25 + 0.15 + 0.10 + 0.05
        assert any("lookalikes" in r for r in e["reasons"])


def test_normal_fixture_no_boost():
    leaf = fixture("leaf_cert_normal.json")
    assert Stage2().boost("dallas-pizza.com", leaf) == 0.0
    assert Stage2().boost("www.dallas-pizza.com", leaf) == 0.0


def test_missing_cert_or_host_not_on_cert():
    s2 = Stage2()
    leaf = fixture("leaf_cert_scam.json")
    for bad in (None, {}, {"all_domains": []}, {"all_domains": None}, [], "cert"):
        assert s2.boost("ezpass.com-xk2.win", bad) == 0.0, bad
    assert s2.boost("other-site.test", leaf) == 0.0          # host must be on the certificate
    assert s2.boost(None, leaf) == 0.0


def test_official_site_on_cert_means_no_boost():
    # a CA only issues a cert covering usps.com to the real owner: not a kit
    leaf = cert("usps.com", "usps-track.test", "usps-help.test", "usps-pay.test", "usps-parcel.test")
    f = cert_features(leaf)
    assert f["official_on_cert"] == 1 and f["brand_names_on_cert"] == 4
    assert Stage2().boost("usps-track.test", leaf) == 0.0
    leaf2 = cert("tools.usps.com", "usps-track.test", "usps-help.test")   # under an official site
    assert Stage2().boost("usps-track.test", leaf2) == 0.0


def test_single_brand_name_among_unrelated_names():
    # shared / multi-customer certificates: one brand word among unrelated sites earns nothing
    leaf = cert("ezpass-info.test", "bakery.test", "garden.example", "plumber.test", "cafe.example")
    assert cert_features(leaf)["brand_names_on_cert"] == 1
    assert Stage2().boost("ezpass-info.test", leaf) == 0.0


def test_two_lookalikes():
    leaf = cert("ezpass-pay.test", "sunpass-pay.test")
    e = Stage2().explain("ezpass-pay.test", leaf)
    assert e["boost"] == 0.25, e


def test_brand_names_on_three_registered_domains():
    leaf = cert("ezpass-pay.test", "sunpass-pay.test", "txtag-pay.test")
    f = cert_features(leaf)
    assert f["brand_registered_domains"] == 3 and f["n_registered_domains"] == 3
    assert Stage2().boost("txtag-pay.test", leaf) == 0.40   # 0.25 + 0.15


def test_misspelled_brand_counts_as_lookalike():
    leaf = cert("ezpas-toll.test", "sunpas-help.test")
    assert cert_features(leaf)["brand_names_on_cert"] == 2
    assert Stage2().boost("ezpas-toll.test", leaf) == 0.25


def test_fake_pattern_names():
    leaf = cert("pay.com-abc.test", "help.com-abc.test")      # no brand word, two ".com-" names
    f = cert_features(leaf)
    assert f["fake_pattern_names_on_cert"] == 2 and f["brand_names_on_cert"] == 0
    assert Stage2().boost("pay.com-abc.test", leaf) == 0.10


def test_cap_never_above_max_and_never_negative():
    names = [f"*.{b}.com-kit.test" for b in ("ezpass", "sunpass", "txtag", "ntta", "usps")]
    names += [f"{b}-toll.test" for b in ("ezpass", "sunpass", "txtag")]
    leaf = cert(*names)
    b, reasons = points(cert_features(leaf))
    assert b == MAX_BOOST == 0.6 and len(reasons) == 5      # 0.70 of points, capped
    for leaf in (fixture("leaf_cert_normal.json"), cert("a.test"), cert()):
        assert 0.0 <= Stage2().boost("a.test", leaf) <= MAX_BOOST


def test_era_stable_issuer_and_dates_do_not_matter():
    leaf = fixture("leaf_cert_scam.json")
    other = dict(leaf, issuer={"O": "Some Other CA", "CN": "X1"}, not_before=1, not_after=10 ** 10)
    assert Stage2().boost("ezpass.com-xk2.win", leaf) == Stage2().boost("ezpass.com-xk2.win", other)


def test_cache_follows_the_certificate():
    s2 = Stage2()
    kit = fixture("leaf_cert_scam.json")
    plain = cert("ezpass.com-xk2.win")
    assert s2.boost("ezpass.com-xk2.win", kit) == 0.55
    assert s2.boost("ezpass.com-xk2.win", plain) == 0.0
    assert s2.boost("ezpass.com-xk2.win", kit) == 0.55


def test_garbage_input_never_raises():
    s2 = Stage2()
    for leaf in (cert(None, 5, "", "....", "*.", b"x.test"), {"all_domains": "ezpass.test"},
                 {"all_domains": [["nested"]]}):
        assert s2.boost("ezpass.test", leaf) == 0.0


def test_internal_error_returns_zero_and_logs_once(caplog=None):
    s2 = Stage2()
    real = stage2.cert_features
    calls = []

    def boom(leaf):
        calls.append(1)
        raise RuntimeError("boom")

    stage2.cert_features = boom
    handler = _ListHandler()
    logging.getLogger("scamouflage.stage2").addHandler(handler)
    try:
        assert s2.boost("ezpass.com-xk2.win", fixture("leaf_cert_scam.json")) == 0.0
        assert s2.boost("x.test", cert("x.test", "y.test")) == 0.0
    finally:
        stage2.cert_features = real
        logging.getLogger("scamouflage.stage2").removeHandler(handler)
    assert len(calls) == 2 and len(handler.records) == 1


class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


class _FixedS1:
    version = "fixed"

    def score_many(self, hosts):
        return [0.5] * len(hosts)


def test_engine_combines_boost_upward():
    eng = Engine(stage1=_FixedS1(), stage2=Stage2(), thresholds={"t_high": 0.9, "t_low": 0.5})
    ds = {d["host"]: d for d in eng.decide_cert(fixture("leaf_cert_scam.json"))}
    d = ds["ezpass.com-xk2.win"]
    assert d["s2_boost"] == 0.55
    assert d["score"] == round(1 - (1 - 0.5) * (1 - 0.55), 4)       # 0.775, up from 0.5
    plain = eng.decide_cert(fixture("leaf_cert_normal.json"))
    assert all(x["s2_boost"] in (None, 0.0) for x in plain)          # gated out or no boost


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok ", fn.__name__)
    print(f"{len(fns)} passed")
