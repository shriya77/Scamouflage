"""
Tests for model/stage3.py — RDAP domain verifier (MODEL_SPEC §8, §13).
Safe domains only (ntta.org, usps.com, google.com), never touches scam sites.
Mocks network for edge cases, timeouts, and rate limits.

Every test uses its own temporary cache file (never data/rdap_cache.db, which on the VM is the
shared, live cache). The live tests need rdap.org and are skipped when it can't be reached.
Run:  python3 -m pytest tests/test_stage3.py -q      (or: python3 tests/test_stage3.py)
"""
import datetime as dt
import os
import shutil
import sys
import tempfile
import time
import unittest.mock as mock

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model import stage3  # noqa: E402
from model.stage3 import is_risky_registrar, verify  # noqa: E402


def isolated(fn):
    """Run the test against a fresh, temporary cache (and no leftover 429 pause)."""
    def run():
        d = tempfile.mkdtemp(prefix="stage3-test-")
        stage3.set_cache_path(os.path.join(d, "rdap_cache.db"))
        stage3._RATE_LIMITER._next = 0.0
        try:
            fn()
        finally:
            stage3.set_cache_path(os.path.join(d, "unused.db"))
            shutil.rmtree(d, ignore_errors=True)
    run.__name__ = fn.__name__
    return run


def rdap_ok(registrar="Gname.com Pte. Ltd.", registered="2026-10-15T10:00:00Z"):
    resp = mock.Mock()
    resp.status_code = 200
    resp.json.return_value = {
        "events": [{"eventAction": "registration", "eventDate": registered}],
        "entities": [{"roles": ["registrar"],
                      "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                               ["fn", {}, "text", registrar]]]}],
    }
    return resp


def status(code, headers=None):
    resp = mock.Mock()
    resp.status_code = code
    resp.headers = headers or {}
    return resp


def _online():
    try:
        requests.head("https://rdap.org/", timeout=5)
        return True
    except requests.RequestException:
        return False


ONLINE = None


def live(fn):
    """Live RDAP test: skipped (not failed) when rdap.org can't be reached."""
    def run():
        global ONLINE
        if ONLINE is None:
            ONLINE = _online()
        if not ONLINE:
            print(f"skip {fn.__name__}: rdap.org not reachable")
            return
        fn()
    run.__name__ = fn.__name__
    return isolated(run)


# ---------------------------------------------------------------------------
# Live tests using safe official domains (MODEL_SPEC §13 step 9)
# ---------------------------------------------------------------------------
@live
def test_safe_domains_live():
    for host in ["ntta.org", "usps.com", "google.com"]:
        res = verify(host, timeout=10.0)
        assert res["ok"] is True, res
        assert res["domain"] == host
        assert res["age_days"] is not None and res["age_days"] > 365.0 * 5  # older than 5 years
        assert res["registered_at"] is not None
        assert res["error"] is None
        assert res["registrar"] is not None
        assert res["risky_registrar"] is False


@live
def test_subdomain_extraction_live():
    res = verify("pay.bills.ntta.org", timeout=10.0)
    assert res["domain"] == "ntta.org"
    assert res["ok"] is True


@live
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
@isolated
def test_risky_registrar_mocked_response():
    with mock.patch("requests.get", return_value=rdap_ok()):
        res = verify("brand-new-fake-toll.test", timeout=1.0)
    assert res["ok"] is True
    assert res["risky_registrar"] is True
    assert res["registrar"] == "Gname.com Pte. Ltd."
    assert res["age_days"] is not None and res["age_days"] >= 0.0


@isolated
def test_timeout_mocked():
    with mock.patch("requests.get", side_effect=requests.Timeout("timed out")):
        res = verify("mocked-timeout-domain.test", timeout=1.0)
    assert res["ok"] is False
    assert res["error"] == "timeout"
    assert res["age_days"] is None


@isolated
def test_rate_limited_mocked():
    with mock.patch("requests.get", return_value=status(429, {"Retry-After": "0"})) as get:
        res = verify("mocked-rate-limit-domain.test", timeout=1.0)
    assert res["ok"] is False
    assert res["error"] == "rate_limited"
    assert get.call_count == 2                       # waited, retried once


@isolated
def test_rate_limited_then_answer():
    answers = [status(429, {"Retry-After": "0"}), rdap_ok()]
    with mock.patch("requests.get", side_effect=answers):
        res = verify("busy-registry.test", timeout=1.0)
    assert res["ok"] is True and res["error"] is None


def test_rate_limiter_spacing_and_429_pause():
    rl = stage3.RateLimiter(min_interval=0.05)
    t0 = time.monotonic()
    rl.wait(); rl.wait(); rl.wait()
    assert time.monotonic() - t0 >= 0.1                 # 3 calls, 2 gaps
    rl.penalize(0.2)
    t1 = time.monotonic()
    rl.wait()
    assert time.monotonic() - t1 >= 0.19                # everyone waits after a 429


@isolated
def test_transient_errors_are_not_cached():
    # a timeout must not hide the domain for a day: the next call asks again
    with mock.patch("requests.get", side_effect=requests.Timeout("timed out")):
        assert verify("flaky.test")["error"] == "timeout"
    with mock.patch("requests.get", return_value=status(503)):
        assert verify("flaky.test")["error"] == "other"
    with mock.patch("requests.get", return_value=rdap_ok()) as get:
        res = verify("flaky.test")
    assert get.call_count == 1 and res["ok"] is True


@isolated
def test_cache_hits_without_network():
    with mock.patch("requests.get", return_value=rdap_ok(registrar="MarkMonitor Inc.")):
        first = verify("cached-site.test")
    with mock.patch("requests.get", side_effect=RuntimeError("Network should not be called")):
        res = verify("www.cached-site.test")
    assert res["ok"] is True and res["domain"] == "cached-site.test"
    assert res["registrar"] == first["registrar"]


@isolated
def test_not_found_is_cached_but_expires():
    with mock.patch("requests.get", return_value=status(404)):
        assert verify("gone.test")["error"] == "not_found"
    with mock.patch("requests.get", side_effect=RuntimeError("cached: no network")):
        assert verify("gone.test")["error"] == "not_found"
    real = stage3.NOT_FOUND_TTL_SECONDS
    stage3.NOT_FOUND_TTL_SECONDS = 0                  # expired
    try:
        with mock.patch("requests.get", return_value=rdap_ok()) as get:
            assert verify("gone.test")["ok"] is True
        assert get.call_count == 1
    finally:
        stage3.NOT_FOUND_TTL_SECONDS = real


@isolated
def test_cached_age_is_recomputed():
    two_days_ago = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with mock.patch("requests.get", return_value=rdap_ok(registered=two_days_ago)):
        verify("aging.test")
    # pretend the answer was cached 20 hours ago with the age it had then
    with stage3._CACHE_LOCK:
        e = stage3._MEM_CACHE["aging.test"]
        e["age_days"], e["_cached_at"] = 2.0 - 20 / 24, time.time() - 20 * 3600
    res = verify("aging.test")
    assert abs(res["age_days"] - 2.0) < 0.01, res     # measured now, not when cached


@isolated
def test_shared_hosting_is_not_looked_up():
    with mock.patch("requests.get", side_effect=RuntimeError("no lookup for a tenant")):
        res = verify("evil-toll.github.io")
    assert res["ok"] is False and res["error"] == "shared_hosting"
    assert res["domain"] == "evil-toll.github.io"


@isolated
def test_bad_input_never_raises():
    with mock.patch("requests.get", side_effect=RuntimeError("must not be reached")):
        for bad in (None, "", "....", "github.io", 123, ["x.test"], "*."):
            res = verify(bad)
            assert res["ok"] is False and set(res) == set(stage3._empty())
    with mock.patch("requests.get", side_effect=ValueError("anything at all")):
        assert verify("weird-failure.test")["error"] == "other"


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

    # shared hosting / failed lookups: HIGH trusts the score, MAYBE stays safe (MODEL_SPEC §3)
    shared = stage3._empty("evil-toll.github.io", "shared_hosting")
    assert eng.finalize(high_dec, shared)["verdict"] == "scam"
    assert eng.finalize(maybe_dec, shared)["verdict"] == "safe"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok ", fn.__name__)
    print(f"{len(fns)} passed")
