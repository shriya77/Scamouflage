"""
Tests for model/stage3.py — RDAP domain verifier (MODEL_SPEC §8, §13).
Safe domains only (ntta.org, usps.com, google.com), never touches scam sites.
Mocks network for edge cases, timeouts, and rate limits.
"""
import os
import sys
import unittest.mock as mock
import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model import stage3
from model.stage3 import verify, is_risky_registrar


# ---------------------------------------------------------------------------
# Live tests using safe official domains (MODEL_SPEC §13 step 9)
# ---------------------------------------------------------------------------
def test_safe_domains_live():
    for host in ["ntta.org", "usps.com", "google.com"]:
        res = verify(host, timeout=10.0)
        assert res["ok"] is True
        assert res["domain"] in host
        assert res["age_days"] is not None and res["age_days"] > 365.0 * 5  # older than 5 years
        assert res["registered_at"] is not None
        assert res["error"] is None
        assert res["registrar"] is not None
        assert res["risky_registrar"] is False


def test_subdomain_extraction_live():
    res = verify("pay.bills.ntta.org", timeout=10.0)
    assert res["domain"] == "ntta.org"
    assert res["ok"] is True


def test_non_existent_domain_live():
    fake = "this-is-a-definitely-fake-domain-xyz-404.example"
    res = verify(fake, timeout=10.0)
    assert res["ok"] is False
    assert res["error"] == "not_found"
    assert res["age_days"] is None


# ---------------------------------------------------------------------------
# Risky registrar matching (MODEL_SPEC §8)
# ---------------------------------------------------------------------------
def test_risky_registrar_matching():
    assert is_risky_registrar("Dominet (HK) Limited") is True
    assert is_risky_registrar("NameSilo, LLC") is True
    assert is_risky_registrar("Gname.com Pte. Ltd.") is True
    assert is_risky_registrar("MarkMonitor Inc.") is False
    assert is_risky_registrar("Network Solutions, LLC") is False
    assert is_risky_registrar(None) is False


# ---------------------------------------------------------------------------
# Mocked network tests (timeouts, 429 rate limiting, mock RDAP responses)
# ---------------------------------------------------------------------------
def test_risky_registrar_mocked_response():
    fake_rdap = {
        "events": [{"eventAction": "registration", "eventDate": "2026-10-15T10:00:00Z"}],
        "entities": [{
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Gname.com Pte. Ltd."]]]
        }]
    }

    mock_resp = mock.Mock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_rdap

    with mock.patch("requests.get", return_value=mock_resp):
        res = verify("brand-new-fake-toll.cfd", timeout=1.0)
        assert res["ok"] is True
        assert res["risky_registrar"] is True
        assert res["registrar"] == "Gname.com Pte. Ltd."
        assert res["age_days"] is not None and res["age_days"] >= 0.0


def test_timeout_mocked():
    with mock.patch("requests.get", side_effect=requests.Timeout("timed out")):
        res = verify("mocked-timeout-domain.com", timeout=1.0)
        assert res["ok"] is False
        assert res["error"] == "timeout"
        assert res["age_days"] is None


def test_rate_limited_mocked():
    mock_resp = mock.Mock()
    mock_resp.status_code = 429

    with mock.patch("requests.get", return_value=mock_resp):
        res = verify("mocked-rate-limit-domain.com", timeout=1.0)
        assert res["ok"] is False
        assert res["error"] == "rate_limited"


def test_cache_hits_without_network():
    # Verify cached entry returns immediately without calling requests.get
    verify("google.com")
    with mock.patch("requests.get", side_effect=RuntimeError("Network should not be called")):
        res = verify("google.com")
        assert res["ok"] is True
        assert res["domain"] == "google.com"


# ---------------------------------------------------------------------------
# Integration with Engine finalize (MODEL_SPEC §3, §8)
# ---------------------------------------------------------------------------
def test_engine_integration():
    from model.engine import Engine, load_stage3

    # Verify load_stage3 finds our function
    stage3_fn = load_stage3()
    assert stage3_fn is not None
    assert callable(stage3_fn)

    class DummyS0:
        def check(self, h):
            return None

    class DummyS1:
        version = "dummy"
        def score_many(self, hs):
            return [0.70] * len(hs)

    class DummyS2:
        def boost(self, h, c):
            return 0.0

    eng = Engine(DummyS0(), DummyS1(), DummyS2(), {"t_high": 0.65, "t_low": 0.45})

    # HIGH triage on old legit domain (not on allowlist) -> removed (SAFE)
    high_dec = eng.decide_host("austin-toll-repair.com")
    assert high_dec["verdict"] == "high"
    # Austin toll repair RDAP mock or mock age > 365
    mock_old_rdap = {
        "ok": True,
        "domain": "austin-toll-repair.com",
        "age_days": 8 * 365.0,
        "registered_at": "2018-01-01T00:00:00Z",
        "registrar": "Network Solutions, LLC",
        "risky_registrar": False,
        "error": None
    }
    final_dec = eng.finalize(high_dec, mock_old_rdap)
    assert final_dec["verdict"] == "safe"
    assert final_dec["verified"] is True
    assert final_dec["stage"] == 3

    # MAYBE triage on brand-new risky domain -> rescued (SCAM)
    maybe_dec = dict(high_dec, verdict="maybe", score=0.55)
    mock_young_risky = {
        "ok": True,
        "domain": "ezpas-toll.cfd",
        "age_days": 0.5,
        "registered_at": "2026-10-17T12:00:00Z",
        "registrar": "Gname.com Pte. Ltd.",
        "risky_registrar": True,
        "error": None
    }
    final_maybe = eng.finalize(maybe_dec, mock_young_risky)
    assert final_maybe["verdict"] == "scam"
    assert final_maybe["verified"] is True
    assert final_maybe["risky_registrar"] is True


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok ", fn.__name__)
    print(f"{len(fns)} passed")
