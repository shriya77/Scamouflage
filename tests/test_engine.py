"""
Tests for model/engine.py — the worked examples from MODEL_SPEC §3, with fake stages.
Run:  python3 -m pytest tests/test_engine.py -q      (or: python3 tests/test_engine.py)
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from model.engine import Engine, load_stage3  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
TH = {"t_high": 0.60, "t_low": 0.40}


class FakeS0:
    def __init__(self, known=()):
        self.known = set(known)

    def check(self, host):
        return {"brand": "usps", "category": "delivery", "feed": "openphish"} if host in self.known else None


class FakeS1:
    version = "fake"

    def __init__(self, scores):
        self.scores = scores

    def score_many(self, hosts):
        return [self.scores.get(h, 0.0) for h in hosts]


class FakeS2:
    def __init__(self, boosts=None, value=None, boom=False):
        self.boosts, self.value, self.boom = boosts or {}, value, boom

    def boost(self, host, cert):
        if self.boom:
            raise RuntimeError("stage 2 broke")
        return self.value if self.value is not None else self.boosts.get(host, 0.0)


def ok(age, registrar="Some Registrar", risky=False):
    return {"ok": True, "age_days": age, "registrar": registrar, "risky_registrar": risky}


def engine(scores=None, boosts=None, known=(), s2=None):
    return Engine(FakeS0(known), FakeS1(scores or {}), s2 or FakeS2(boosts), TH)


def cert(*names):
    return {"all_domains": list(names)}


# ------------------------------------------------------------------ worked examples (§3)
def test_normal_site_stops_at_gate():
    d = engine({"dallas-pizza.com": 0.99}).decide_host("dallas-pizza.com")
    assert d["verdict"] == "safe" and d["stage"] == 1 and d["s1"] is None   # gate stops it, Stage 1 never runs


def test_obvious_scam_high_then_confirmed():
    e = engine({"ezpass.com-xk2.win": 0.97}, {"ezpass.com-xk2.win": 0.6})
    d = e.decide_host("ezpass.com-xk2.win")
    assert d["verdict"] == "high" and d["score"] >= 0.98 and d["category"] == "toll"
    assert e.finalize(d, ok(0.1))["verdict"] == "scam"


def test_borderline_single_domain_rescued_by_stage3():
    e = engine({"ezpas-toll.cfd": 0.55})
    d = e.decide_host("ezpas-toll.cfd")
    assert d["verdict"] == "maybe" and d["score"] == 0.55
    assert e.finalize(d, ok(0.2, "Gname.com Pte. Ltd.", risky=True))["verdict"] == "scam"


def test_old_real_business_removed_by_stage3():
    e = engine({"austin-toll-repair.com": 0.65})
    d = e.decide_host("austin-toll-repair.com")
    assert d["verdict"] == "high"
    f = e.finalize(d, ok(8 * 365))
    assert f["verdict"] == "safe" and f["verified"] and f["stage"] == 3


def test_official_site_never_flagged():
    d = engine({"ntta.org": 1.0}, known={"ntta.org"}).decide_host("ntta.org")
    assert d["verdict"] == "safe" and d["stage"] == -1


# ------------------------------------------------------------------ stage rules
def test_stage0_known_scam_is_final():
    d = engine(known={"usps-redeliver.top"}).decide_host("usps-redeliver.top")
    assert d["verdict"] == "scam" and d["stage"] == 0 and d["score"] == 1.0
    assert not Engine.needs_verify(d)


def test_stage2_only_raises_and_is_capped():
    e = engine({"ntta-pay.xin": 0.50}, s2=FakeS2(value=-5))
    assert e.decide_host("ntta-pay.xin")["score"] == 0.50          # negative boost -> 0
    e = engine({"ntta-pay.xin": 0.50}, s2=FakeS2(value=9))
    assert e.decide_host("ntta-pay.xin")["s2_boost"] == 0.6        # capped at 0.6


def test_stage2_boost_combines_upward():
    e = engine({"ezpas-toll.cfd": 0.55}, {"ezpas-toll.cfd": 0.6})
    d = e.decide_host("ezpas-toll.cfd")
    assert abs(d["score"] - 0.82) < 1e-6 and d["verdict"] == "high"   # 1-(0.45*0.4)


def test_broken_stage2_does_not_break_engine():
    e = engine({"ezpass.com-xk2.win": 0.97}, s2=FakeS2(boom=True))
    d = e.decide_host("ezpass.com-xk2.win")
    assert d["verdict"] == "high" and d["s2_boost"] == 0.0


def test_no_stage3_answer():
    e = engine({"a-toll.win": 0.9, "b-toll.win": 0.5})
    high, maybe = e.decide_host("a-toll.win"), e.decide_host("b-toll.win")
    assert e.finalize(high, None)["verdict"] == "scam"                 # trust the score
    assert e.finalize(maybe, None)["verdict"] == "safe"                # precision first
    assert e.finalize(maybe, {"ok": False, "error": "timeout"})["verdict"] == "safe"


def test_very_high_score_survives_old_domain():
    e = engine({"ezpass-toll.win": 0.995})
    d = e.decide_host("ezpass-toll.win")
    assert e.finalize(d, ok(2000))["verdict"] == "scam"


def test_whole_certificate_fixtures():
    scam = json.load(open(os.path.join(FIX, "leaf_cert_scam.json")))
    e = engine({"ezpass.com-xk2.win": 0.97, "ntta.com-xk2.win": 0.9, "txtag.com-xk2.win": 0.9,
                "sunpass.com-xk2.win": 0.9})
    ds = e.decide_cert(scam, seen_at=1792245600.5)
    assert [d["host"] for d in ds] == ["ezpass.com-xk2.win", "ntta.com-xk2.win", "txtag.com-xk2.win",
                                       "sunpass.com-xk2.win"]                     # "*." copy deduped
    assert all(d["verdict"] == "high" for d in ds) and ds[0]["cert_seen_at"].endswith("Z")
    normal = json.load(open(os.path.join(FIX, "leaf_cert_normal.json")))
    assert [d["verdict"] for d in e.decide_cert(normal)] == ["safe"]              # www. copy deduped


def test_stub_engine_runs_and_says_safe():
    e = Engine.from_disk(labels_db="/nonexistent.db", model_dir="/nonexistent-models")
    assert e.decide_host("ezpass.com-xk2.win")["verdict"] == "safe"               # stub Stage 1 = 0.0
    load_stage3()                                                                 # None or a function; never raises


def test_decision_has_every_field():
    from model.engine import DECISION_FIELDS
    d = engine().decide_host("usps-track.top")
    assert set(DECISION_FIELDS) <= set(d)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok ", fn.__name__)
    print(f"{len(fns)} passed")
