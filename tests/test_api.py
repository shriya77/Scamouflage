"""
Tests for api/server.py: real data only (no mocks), the dashboard served at /, alert lookup by
numeric id or cert_id, /health. Uses a temporary DATA_DIR with a tiny alerts DB.
Run:  python3 -m pytest tests/test_api.py -q      (or: python3 tests/test_api.py)
"""
import asyncio
import importlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from aiohttp.test_utils import TestClient, TestServer  # noqa: E402


def load_server(data_dir):
    os.environ.pop("SCAM_DB", None)
    os.environ["DATA_DIR"] = data_dir
    import api.server as server
    return importlib.reload(server)


def make_db(data_dir):
    con = sqlite3.connect(os.path.join(data_dir, "scamouflage.db"))
    con.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY, cert_id TEXT, domain TEXT, "
                "domains TEXT, score REAL, reasons TEXT, seen_at REAL, stage INTEGER, "
                "category TEXT, sig TEXT, key_id TEXT)")
    con.execute("INSERT INTO alerts VALUES (1, 'aaa', 'usps-pay.test', '[\"usps-pay.test\"]', 0.97, "
                "'[\"Pretends to be USPS\"]', 1.0, 2, 'delivery', 'c2ln', 'ed25519:x')")
    con.execute("INSERT INTO alerts VALUES (2, 'bbb', 'known.test', '[\"known.test\"]', 1.0, "
                "'[\"Already on a known scam list\"]', 2.0, 0, 'other', 'c2ln', 'ed25519:x')")
    con.commit()
    con.close()


def run(coro_fn, data_dir):
    async def go():
        server = load_server(data_dir)
        client = TestClient(TestServer(server.make_app()))
        await client.start_server()
        try:
            return await coro_fn(client, server)
        finally:
            await client.close()
    return asyncio.run(go())


def with_dir(fn):
    def test():
        d = tempfile.mkdtemp(prefix="api-test-")
        try:
            fn(d)
        finally:
            shutil.rmtree(d, ignore_errors=True)
            os.environ.pop("DATA_DIR", None)
    test.__name__ = fn.__name__
    return test


@with_dir
def test_missing_sources_are_503_not_mock(d):
    async def check(c, server):
        for path in ("/api/stats", "/api/results", "/api/leadtime", "/api/alerts",
                     "/api/alerts/summary", "/api/campaigns", "/api/alerts/1"):
            r = await c.get(path)
            body = await r.json()
            assert r.status == 503, (path, r.status)
            assert body["source"] == "unavailable", path
        assert not hasattr(server, "MOCK") and not hasattr(server, "mock_alert")
    run(check, d)


@with_dir
def test_alerts_newest_first_and_detail_by_id_or_cert_id(d):
    make_db(d)

    async def check(c, server):
        r = await c.get("/api/alerts?limit=15")
        body = await r.json()
        assert body["source"] == "live" and [a["id"] for a in body["items"]] == [2, 1]
        assert body["items"][1]["reasons"] == ["Pretends to be USPS"]      # JSON decoded
        r = await c.get("/api/alerts?stage=0")
        assert [a["domain"] for a in (await r.json())["items"]] == ["known.test"]
        for key in ("1", "aaa"):
            r = await c.get(f"/api/alerts/{key}")
            a = await r.json()
            assert r.status == 200 and a["domain"] == "usps-pay.test" and a["sig"] == "c2ln", key
        assert (await c.get("/api/alerts/999")).status == 404
        s = await (await c.get("/api/alerts/summary")).json()
        assert (s["known_total"], s["new_total"], s["total"]) == (1, 1, 2)
    run(check, d)


@with_dir
def test_dashboard_is_served_same_origin(d):
    async def check(c, server):
        r = await c.get("/")
        assert r.status == 200 and "text/html" in r.headers["Content-Type"]
        assert "<html" in (await r.text()).lower()
        assert (await c.get("/app.js")).status == 200
        assert (await c.get("/style.css")).status == 200
        # nothing else from the repo is reachable
        for path in ("/api/server.py", "/../keys/alert_ed25519.pem", "/keys/alert_ed25519.pem",
                     "/data/scamouflage.db", "/README.md"):
            assert (await c.get(path)).status == 404, path
    run(check, d)


@with_dir
def test_health(d):
    with open(os.path.join(d, "stats.json"), "w") as f:
        json.dump({"ts": time.time(), "lag_s": 0.2, "certs_per_s": 600, "dropped_total": 0,
                   "last_seen_at": 1792279000.0,
                   "engine": {"mode": "on", "stage0": "real", "stage1": "real", "stage2": "real",
                              "stage3": "real", "stage1_version": "v", "signing": {"ok": True}}}, f)

    async def check(c, server):
        for path in ("/health", "/api/health"):
            h = await (await c.get(path)).json()
            assert h["ok"] is True and h["engine"]["stage1"] == "real" and h["engine"]["signing"] is True
            assert h["lag_s"] == 0.2 and h["stats_age_s"] < 5
            assert h["last_cert_seen_at"] == 1792279000.0
        assert server.health_payload(now=time.time() + 120)["ok"] is False   # stale stats = down
    run(check, d)


@with_dir
def test_health_flags_a_stub_stage(d):
    with open(os.path.join(d, "stats.json"), "w") as f:
        json.dump({"ts": time.time(), "lag_s": 0.1,
                   "engine": {"mode": "on", "stage0": "real", "stage1": "stub",
                              "stage2": "real", "stage3": "real"}}, f)

    async def check(c, server):
        h = await (await c.get("/health")).json()
        assert h["ok"] is False and h["last_cert_seen_at"] is not None   # from ts - lag_s
    run(check, d)



@with_dir
def test_stats_carries_lead_time(d):
    with open(os.path.join(d, "stats.json"), "w") as f:
        json.dump({"ts": time.time(), "certs_total": 5}, f)

    async def check(c, server):
        s = await (await c.get("/api/stats")).json()
        assert s["certs_total"] == 5 and s["lead_time"] is None        # job hasn't run yet
        with open(os.path.join(d, "leadtime.json"), "w") as f:
            json.dump({"n": 3, "n_alerts_new": 10, "median_days": 0.5, "share_before_any_feed": 1.0,
                       "examples": [{"host": "a.test", "lead_days": 0.5}]}, f)
        lt = (await (await c.get("/api/stats")).json())["lead_time"]
        assert lt["n_later_listed"] == 3 and lt["median_hours_early"] == 12.0
        assert lt["examples"] == [{"host": "a.test", "lead_days": 0.5}]
    run(check, d)

if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok ", fn.__name__)
    print(f"{len(fns)} passed")
