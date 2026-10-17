"""
Engine -> consumer integration (MODEL_SPEC §10): Stage 3 queue, finalize, sign, write, dedupe.
Uses the real Engine with fake stages (no model, no labels DB, no network), a temporary SQLite
DB and a throwaway signing key.
Run:  python3 -m pytest tests/test_integration.py -q
"""
import asyncio
import os
import sqlite3
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from alerts import sign as S  # noqa: E402
from alerts.check import row_to_alert  # noqa: E402
from ingest import consumer as C  # noqa: E402
from ingest.alerting import DECISION_COLUMNS, AlertWriter, Stage3Queue, now_iso  # noqa: E402
from ingest.db import connect  # noqa: E402
from model.engine import Engine  # noqa: E402

TH = {"t_high": 0.90, "t_low": 0.30}
KEY = Ed25519PrivateKey.generate()
PUB = KEY.public_key()
S._PRIV, S._KEY_ID = KEY, S.key_id_of(PUB)


class FakeS0:
    known = {"usps-redeliver-known.top"}

    def check(self, host):
        return self.explain(host)[0]

    def explain(self, host):
        if host in self.known:
            return {"brand": "usps", "category": "delivery", "feed": "openphish"}, "exact", host
        return None, None, None

    def __len__(self):
        return len(self.known)


class FakeS1:
    version = "fake-s1"
    scores = {"ezpass.com-xk2.win": 0.97, "sunpass.com-xk2.win": 0.95, "ezpas-toll.cfd": 0.55,
              "austin-toll-repair.com": 0.93, "ezpass-pay.pages.dev": 0.96, "txtag-pay.win": 0.92,
              "ntta-fee.win": 0.91}

    def score_many(self, hosts):
        return [self.scores.get(h, 0.05) for h in hosts]


class FakeEngine(Engine):
    def decide_host(self, host):  # like the worker: one name on a certificate seen at a known time
        return self.decide_cert({"all_domains": [host]}, seen_at=1792245600.5)[0]


def fake_engine():
    return FakeEngine(FakeS0(), FakeS1(), None, TH)


def ctx_for(host, cert_id="ab" * 32):
    return {"cert_id": cert_id, "domains": [host, "x." + host], "seen_at": 1792245600.5,
            "issuer": "/C=US/O=Let's Encrypt/CN=R11", "log": "Test Log", "verify": "ok", "other_gated": 1}


def tmpdb():
    return connect(os.path.join(tempfile.mkdtemp(prefix="integ-"), "t.db"))


def rows(con):
    con.row_factory = sqlite3.Row
    out = [row_to_alert(r) for r in con.execute("SELECT * FROM alerts ORDER BY id")]
    con.row_factory = None
    return out


def ok(age, registrar="Gname.com Pte. Ltd.", risky=True):
    return {"ok": True, "domain": "x", "age_days": age, "registered_at": "2026-10-17T10:00:00Z",
            "registrar": registrar, "risky_registrar": risky, "error": None}


def run_queue(verify, submits, **kw):
    """Submit (decision, ctx) pairs to a Stage3Queue, wait for it to finish, return (queue, con)."""
    con = tmpdb()
    eng = fake_engine()
    writer = AlertWriter(con, S.sign)

    async def go():
        q = Stage3Queue(eng, verify, writer.on_final, **kw)
        q.start()
        for d, ctx in submits:
            q.submit(d, ctx)
            await asyncio.sleep(0.02)
        await q.drain(timeout=10)
        await q.stop()
        return q
    q = asyncio.run(go())
    return q, writer, con


# ------------------------------------------------------------------ alert written + signed after finalize
def test_high_confirmed_is_written_with_every_field_and_valid_signature():
    eng = fake_engine()
    d = eng.decide_host("ezpass.com-xk2.win")
    assert d["verdict"] == "high"
    q, writer, con = run_queue(lambda h: ok(0.12), [(d, ctx_for(d["host"]))])
    assert q.c["confirmed"] == 1
    (a,) = rows(con)
    for k in DECISION_COLUMNS:
        assert a[k] is not None, k
    assert a["domain"] == "ezpass.com-xk2.win" and a["verdict"] == "scam" and a["stage"] == 3
    assert a["verified"] == 1 and a["risky_registrar"] == 1 and a["category"] == "toll"
    assert a["score"] == d["score"] and a["s1"] == d["s1"]
    assert "Pretends to be E-ZPass" in a["reasons"]
    assert any(r.startswith("Registered 3 hours ago via Gname") and "high-risk" in r for r in a["reasons"])
    assert "Certificate also covers 1 other lookalike name" in a["reasons"]
    assert S.verify_sig(a, PUB)                                       # signed over the final row
    a["score"] = 0.01
    assert not S.verify_sig(a, PUB)                                   # --tamper
    a["score"] = d["score"]
    a["age_days"] = 400.0
    assert not S.verify_sig(a, PUB)                                   # Decision fields are signed too


def test_signature_is_made_after_finalize():
    seen = []

    def spy_sign(alert):
        seen.append(dict(alert))
        return S.sign(alert)
    con = tmpdb()
    eng = fake_engine()
    writer = AlertWriter(con, spy_sign)

    async def go():
        q = Stage3Queue(eng, lambda h: ok(0.2), writer.on_final)
        q.start()
        q.submit(eng.decide_host("sunpass.com-xk2.win"), ctx_for("sunpass.com-xk2.win"))
        await q.drain(timeout=5)
        await q.stop()
    asyncio.run(go())
    assert len(seen) == 1 and seen[0]["verdict"] == "scam" and seen[0]["stage"] == 3
    assert seen[0]["age_days"] is not None and seen[0]["decided_at"]


def test_maybe_rescued_and_old_business_removed():
    eng = fake_engine()
    maybe, old = eng.decide_host("ezpas-toll.cfd"), eng.decide_host("austin-toll-repair.com")
    assert maybe["verdict"] == "maybe" and old["verdict"] == "high"
    answers = {"ezpas-toll.cfd": ok(2.0), "austin-toll-repair.com": ok(8 * 365, "GoDaddy", False)}
    q, writer, con = run_queue(lambda h: answers[h], [(maybe, ctx_for(maybe["host"])),
                                                      (old, ctx_for(old["host"]))])
    assert q.c["rescued"] == 1 and q.c["removed"] == 1
    (a,) = rows(con)
    assert a["domain"] == "ezpas-toll.cfd" and a["stage"] == 3
    assert any("Borderline score 0.55" in r for r in a["reasons"])
    assert S.verify_sig(a, PUB)


def test_shared_hosting_failure_trusts_the_score_for_high():
    eng = fake_engine()
    d = eng.decide_host("ezpass-pay.pages.dev")
    res = {"ok": False, "domain": "ezpass-pay.pages.dev", "age_days": None, "registered_at": None,
           "registrar": None, "risky_registrar": False, "error": "shared_hosting"}
    q, writer, con = run_queue(lambda h: res, [(d, ctx_for(d["host"]))])
    assert q.c["kept_unverified"] == 1 and q.fail["shared_hosting"] == 1
    (a,) = rows(con)
    assert a["stage"] == 2 and a["verified"] == 0 and a["age_days"] is None
    assert any("shared hosting" in r for r in a["reasons"])
    assert S.verify_sig(a, PUB)


# ------------------------------------------------------------------ Stage 3 timeout path
def test_stage3_timeout_high_alerts_on_score_maybe_dropped():
    eng = fake_engine()
    high, maybe = eng.decide_host("txtag-pay.win"), eng.decide_host("ezpas-toll.cfd")

    def slow(h):
        time.sleep(0.6)
        return ok(0.1)
    q, writer, con = run_queue(slow, [(high, ctx_for(high["host"])), (maybe, ctx_for(maybe["host"]))],
                               timeout=0.1)
    assert q.fail["deadline"] == 2
    assert q.c["kept_unverified"] == 1 and q.c["dropped_unverified"] == 1
    (a,) = rows(con)
    assert a["domain"] == "txtag-pay.win" and a["stage"] == 2 and a["verified"] == 0
    assert any("no RDAP answer within 10 s" in r for r in a["reasons"])


# ------------------------------------------------------------------ queue-full path
def test_queue_full_finalizes_with_none():
    eng = fake_engine()
    a, b, c = (eng.decide_host(h) for h in ("ezpass.com-xk2.win", "sunpass.com-xk2.win", "ntta-fee.win"))
    gate = threading.Event()

    def blocked(h):
        gate.wait(5)
        return ok(0.1)
    con = tmpdb()
    writer = AlertWriter(con, S.sign)

    async def go():
        q = Stage3Queue(eng, blocked, writer.on_final, concurrency=1, maxsize=1)
        q.start()
        assert q.submit(a, ctx_for(a["host"])) == "queued"
        await asyncio.sleep(0.05)                       # the worker takes `a`; queue empty again
        assert q.submit(b, ctx_for(b["host"])) == "queued"   # queue now full (cap 1)
        assert q.submit(c, ctx_for(c["host"])) == "queue_full"
        assert [r["domain"] for r in rows(con)] == ["ntta-fee.win"]   # HIGH, no answer -> alert now
        gate.set()
        await q.drain(timeout=5)
        await q.stop()
        return q
    q = asyncio.run(go())
    assert q.c["queue_full"] == 1 and q.fail["queue_full"] == 1 and q.c["confirmed"] == 2
    got = {r["domain"]: r for r in rows(con)}
    assert set(got) == {"ezpass.com-xk2.win", "sunpass.com-xk2.win", "ntta-fee.win"}
    assert got["ntta-fee.win"]["stage"] == 2 and any("queue was full" in r for r in got["ntta-fee.win"]["reasons"])
    assert all(S.verify_sig(r, PUB) for r in got.values())


def test_no_stage3_finalizes_immediately():
    eng = fake_engine()
    high, maybe = eng.decide_host("txtag-pay.win"), eng.decide_host("ezpas-toll.cfd")
    q, writer, con = run_queue(None, [(high, ctx_for(high["host"])), (maybe, ctx_for(maybe["host"]))])
    assert q.fail["no_stage3"] == 2 and q.c["kept_unverified"] == 1 and q.c["dropped_unverified"] == 1
    assert [r["domain"] for r in rows(con)] == ["txtag-pay.win"]


# ------------------------------------------------------------------ dedupe
def test_dedupe_one_alert_per_host_per_24h_and_reload_from_db():
    eng = fake_engine()
    d = eng.decide_host("usps-redeliver-known.top")
    assert d["verdict"] == "scam" and d["stage"] == 0
    clock = [1_800_000_000.0]
    con = tmpdb()
    w = AlertWriter(con, S.sign, clock=lambda: clock[0])
    ctx = dict(ctx_for(d["host"]), s0={"feed": "openphish", "rule": "exact", "listed": d["host"]})
    d = dict(d, decided_at=now_iso(clock[0]))
    assert w.write(d, ctx) is not None
    assert w.write(d, ctx) is None and w.c["deduped"] == 1
    w2 = AlertWriter(con, S.sign, clock=lambda: clock[0] + 3600)   # restart: loads hosts from the DB
    assert w2.is_recent(d["host"]) and w2.write(d, ctx) is None
    clock[0] += 24 * 3600 + 1
    assert not w.is_recent(d["host"]) and w.write(d, ctx) is not None
    rs = rows(con)
    assert len(rs) == 2 and rs[0]["stage"] == 0 and rs[0]["reasons"][0] == "Already on a known scam list (openphish)"
    assert all(S.verify_sig(r, PUB) for r in rs)


def test_stage3_skips_pending_duplicates():
    eng = fake_engine()
    d = eng.decide_host("ezpass.com-xk2.win")
    gate = threading.Event()

    def blocked(h):
        gate.wait(5)
        return ok(0.1)
    con = tmpdb()
    writer = AlertWriter(con, S.sign)

    async def go():
        q = Stage3Queue(eng, blocked, writer.on_final)
        q.start()
        assert q.submit(d, ctx_for(d["host"])) == "queued"
        assert q.submit(d, ctx_for(d["host"], "cd" * 32)) == "pending"   # precert + cert copy
        gate.set()
        await q.drain(timeout=5)
        assert q.submit(d, ctx_for(d["host"])) == "recent"               # answered < 1 h ago
        await q.stop()
    asyncio.run(go())
    assert len(rows(con)) == 1


def test_official_site_never_saved():
    con = tmpdb()
    w = AlertWriter(con, S.sign)
    d = dict(fake_engine().decide_host("txtag-pay.win"), host="pay.usps.com", verdict="scam")
    assert w.write(d, ctx_for("pay.usps.com")) is None and w.c["official_blocked"] == 1
    assert rows(con) == []


def test_reasons_only_claim_a_brand_at_the_start_of_a_word():
    from ingest.alerting import build_reasons
    base = {"stage": 2, "s1": 0.7, "s2_boost": 0.0, "score": 0.7, "category": "toll", "verified": False}
    assert build_reasons(dict(base, host="epass-toll.win", brand="epass"), {})[0] == "Pretends to be E-PASS"
    assert build_reasons(dict(base, host="pay.ezpass.com-xk2.win", brand="ezpass"), {})[0] == "Pretends to be E-ZPass"
    assert build_reasons(dict(base, host="coffeepass.world", brand="epass"), {})[0] == \
        'Contains "epass" (E-PASS, toll) inside another word'
    assert build_reasons(dict(base, host="tollroad-fee.win", brand="toll"), {})[0] == 'Uses the toll lure word "toll"'


# ------------------------------------------------------------------ signatures, schema
def test_legacy_alert_still_verifies():
    old = {"cert_id": "ab" * 32, "domain": "x.win", "domains": ["x.win"], "score": 0.9, "reasons": [],
           "seen_at": 1.0, "issuer": "i", "log": "l", "verify": "ok", "crtsh_url": "u"}
    signed = S.sign(old)
    row = dict(signed, **{k: None for k in S.DECISION_SIGNED})   # as read back after the migration
    assert S.verify_sig(row, PUB)


def test_migration_adds_columns_and_keeps_rows():
    path = os.path.join(tempfile.mkdtemp(prefix="integ-"), "old.db")
    con = sqlite3.connect(path)
    con.executescript("CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, cert_id TEXT NOT NULL, "
                      "domain TEXT NOT NULL, domains TEXT, score REAL NOT NULL, reasons TEXT, "
                      "seen_at REAL NOT NULL, issuer TEXT, log TEXT, verify TEXT, crtsh_url TEXT, "
                      "sig TEXT, key_id TEXT);"
                      "INSERT INTO alerts(cert_id, domain, score, seen_at) VALUES ('c', 'd.win', 0.9, 1.0);")
    con.commit()
    con.close()
    con = connect(path)
    connect(path).close()                                             # idempotent
    cols = [r[1] for r in con.execute("PRAGMA table_info(alerts)")]
    assert all(k in cols for k in DECISION_COLUMNS)
    assert con.execute("SELECT domain, stage FROM alerts").fetchall() == [("d.win", None)]


# ------------------------------------------------------------------ worker side
def test_worker_returns_only_non_safe_decisions_and_counters():
    C._ENGINE = {"engine": fake_engine(), "verify": lambda rec: {"status": "unknown_issuer"},
                 "info": {"pid": os.getpid(), "stage0_refreshes": 0}, "refreshed": time.time()}
    try:
        recs = [{"id": "01" * 32, "seen_at": 1792245600.5, "issuer": "i", "log": "l",
                 "not_before": 0, "not_after": 1,
                 "domains": ["ezpass.com-xk2.win", "sunpass.com-xk2.win", "dallas-pizza.com"]},
                {"id": "02" * 32, "seen_at": 1792245601.0, "issuer": "i", "log": "l",
                 "not_before": 0, "not_after": 1, "domains": ["usps-redeliver-known.top", "ntta.org"]}]
        out = C.process_batch_engine(recs, {"refresh_s": 900})
    finally:
        C._ENGINE = None
    c = out["counts"]
    assert c["names"] == 5 and c["gate_passes"] == 2 and c["high"] == 2 and c["stage0_hits"] == 1
    assert sorted(d["host"] for d, _ in out["hits"]) == ["ezpass.com-xk2.win", "sunpass.com-xk2.win",
                                                         "usps-redeliver-known.top"]
    ctx = {d["host"]: x for d, x in out["hits"]}
    assert ctx["ezpass.com-xk2.win"]["other_gated"] == 1 and ctx["ezpass.com-xk2.win"]["verify"] == "unknown_issuer"
    assert ctx["usps-redeliver-known.top"]["s0"]["feed"] == "openphish"
    assert len(out["results"]) == 2 and len(out["names"]) == 5


def test_unique_names_estimate():
    t = [36000.0 + 600]                     # 10 min into an hour
    u = C.UniqueNames(clock=lambda: t[0])
    t[0] += 600                             # 10 min measured
    u.add(list(range(100)) + list(range(50)))
    est = u.estimate()
    assert est["unique_names_per_hour"] == round(100 * C.NAME_SAMPLE * 3600 / 600)
    assert est["unique_names_per_day"] == round(100 * C.NAME_SAMPLE * 3600 / 600 * 24)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok ", fn.__name__)
    print(f"{len(fns)} passed")
