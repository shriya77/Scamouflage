"""
Tests for backend/abuse_report.py: RDAP abuse-contact parsing, the report text, and the
/api/abuse/* routes in preview and send mode (fake SMTP, no network, no real registrar).
Run:  python3 -m pytest tests/test_abuse_report.py -q      (or: python3 tests/test_abuse_report.py)
"""
import asyncio
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestClient, TestServer  # noqa: E402

from backend import abuse_report as ar  # noqa: E402

# A trimmed real-world shape: registrar entity with a nested abuse entity (ICANN profile).
RDAP_FIXTURE = {
    "ldhName": "com-xk2.win",
    "status": ["client transfer prohibited"],
    "events": [{"eventAction": "registration", "eventDate": "2026-10-15T03:10:00Z"},
               {"eventAction": "expiration", "eventDate": "2027-10-15T03:10:00Z"}],
    "entities": [{
        "objectClassName": "entity", "handle": "1479", "roles": ["registrar"],
        "publicIds": [{"type": "IANA Registrar ID", "identifier": "1479"}],
        "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "NameSilo, LLC"]]],
        "entities": [{
            "objectClassName": "entity", "roles": ["abuse"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Abuse Contact"],
                                     ["tel", {"type": "voice"}, "uri", "tel:+1.4805240066"],
                                     ["email", {}, "text", "abuse@namesilo.com"]]],
        }],
    }],
}

ALERT = {
    "cert_id": "ab" * 32, "domain": "ezpass.com-xk2.win", "domains": ["ezpass.com-xk2.win", "www.ezpass.com-xk2.win"],
    "score": 0.97, "reasons": ["Pretends to be E-ZPass", "Registered 2 days ago via NameSilo, LLC (Unit 42 high-risk registrar)"],
    "seen_at": 1760680000.0, "issuer": "Let's Encrypt R11", "log": "Google Argon 2026",
    "verify": "ok", "crtsh_url": "https://crt.sh/?q=" + "ab" * 32, "verdict": "scam", "stage": 3, "s1": 0.93,
    "s2_boost": 0.04, "brand": "ezpass", "category": "toll", "verified": 1, "age_days": 2.1,
    "registrar": "NameSilo, LLC", "risky_registrar": 1, "model_version": "stage1-v3",
    "cert_seen_at": "2026-10-17T05:46:40Z", "decided_at": "2026-10-17T05:46:41Z",
    "sig": "c2ln", "key_id": "ed25519:deadbeef",
}


def make_alerts_db(path):
    con = sqlite3.connect(path)
    cols = ["id INTEGER PRIMARY KEY"] + [f"{k} {'REAL' if isinstance(v, float) else 'TEXT'}" for k, v in ALERT.items()]
    con.execute(f"CREATE TABLE alerts ({', '.join(cols)})")

    def insert(aid, **over):
        row = dict(ALERT, **over)
        vals = [json.dumps(v) if isinstance(v, list) else v for v in row.values()]
        con.execute(f"INSERT INTO alerts VALUES ({aid}, {','.join('?' * len(vals))})", vals)
    insert(1)                                                           # eligible: 0.97, verified
    insert(2, domain="low.com-xk2.win", score=0.80)                     # below the 0.85 threshold
    insert(3, domain="unverified.com-xk2.win", score=0.95, verified=0, stage=2)  # RDAP never answered
    insert(4, domain="listed.com-xk2.win", score=1.0, verified=0, stage=0)       # on a public list
    con.commit()
    con.close()


# ------------------------------------------------------------------ parsing

def test_parse_abuse_contact_nested_under_registrar():
    c = ar.parse_abuse_contact(RDAP_FIXTURE)
    assert c["registrar"] == "NameSilo, LLC"
    assert c["registrar_iana_id"] == "1479"
    assert c["emails"] == ["abuse@namesilo.com"]
    assert c["phone"] == "+1.4805240066"
    assert c["abuse_source"] == "registrar/abuse"
    assert c["registered_at"] == "2026-10-15T03:10:00Z"


def test_parse_falls_back_to_registrar_mailbox_then_remarks():
    d = json.loads(json.dumps(RDAP_FIXTURE))
    d["entities"][0]["entities"] = []
    d["entities"][0]["vcardArray"][1].append(["email", {}, "text", "Support@Registrar.example"])
    c = ar.parse_abuse_contact(d)
    assert c["emails"] == ["support@registrar.example"] and c["abuse_source"] == "registrar"

    d["entities"][0]["vcardArray"][1].pop()
    d["remarks"] = [{"title": "abuse", "description": ["Report abuse to abuse-desk@registry.example."]}]
    c = ar.parse_abuse_contact(d)
    assert c["emails"] == ["abuse-desk@registry.example"] and c["abuse_source"] == "remarks"

    d["remarks"] = []
    assert ar.parse_abuse_contact(d)["emails"] == []


def test_lookup_uses_registered_domain_and_cache():
    tmp = tempfile.mkdtemp(prefix="abuse-")
    try:
        store = ar.TakedownStore(os.path.join(tmp, "t.db"))
        calls = []

        def fake_fetch(domain):
            calls.append(domain)
            return RDAP_FIXTURE, None

        r1 = ar.lookup_abuse_contact("pay.ezpass.com-xk2.win", store, fetch=fake_fetch)
        r2 = ar.lookup_abuse_contact("www.com-xk2.win", store, fetch=fake_fetch)
        assert calls == ["com-xk2.win"], "the registered domain is looked up once"
        assert r1["emails"] == ["abuse@namesilo.com"] and not r1["cached"]
        assert r2["emails"] == ["abuse@namesilo.com"] and r2["cached"]

        err = ar.lookup_abuse_contact("x.top", store, fetch=lambda d: (None, "timeout"))
        assert err["error"] == "timeout" and err["emails"] == []
        assert store.get_contact("x.top") is None, "timeouts are not cached"
        shared = ar.lookup_abuse_contact("evil.github.io", store, fetch=fake_fetch)
        assert shared["domain"] == "evil.github.io"
        store.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------------ report text

def test_build_report_contents():
    contact = dict(ar.parse_abuse_contact(RDAP_FIXTURE), domain="com-xk2.win",
                   rdap_url="https://rdap.org/domain/com-xk2.win")
    rep = ar.build_report(dict(ALERT, id=1), contact, {"name": "Ada", "email": "ada@example.org", "org": "Team"},
                          note="Victims reported SMS lures.", public_base="http://127.0.0.1:8000")
    assert rep["to"] == ["abuse@namesilo.com"]
    assert "E-ZPass" in rep["subject"] and "ezpass.com-xk2.win" in rep["subject"]
    body = rep["body"]
    for needle in ("com-xk2.win", "ab" * 32, "Let's Encrypt R11", "Pretends to be E-ZPass",
                   "we did not visit the site", "Victims reported SMS lures.",
                   "http://127.0.0.1:8000/api/alerts/1", "/api/alerts/pubkey", "clientHold",
                   "Ada", "ada@example.org", "IANA 1479"):
        assert needle in body, needle
    att = rep["attachment"]
    assert att["evidence"]["site_visited"] is False
    assert att["signed_alert"]["sig"] == "c2ln" and att["signed_alert"]["key_id"] == "ed25519:deadbeef"
    assert att["registrar"]["abuse_emails"] == ["abuse@namesilo.com"]
    assert rep["mailto"].startswith("mailto:abuse@namesilo.com?subject=")
    assert ar.build_report(ALERT, dict(contact, emails=[]))["mailto"] is None


# ------------------------------------------------------------------ routes

class FakeSMTP:
    sent = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self):
        pass

    def login(self, u, p):
        self.auth = (u, p)

    def send_message(self, msg, to_addrs=None):
        FakeSMTP.sent.append((msg, to_addrs))


def run_app(mode, fn, **env):
    """peer: the remote address every request appears to come from (default loopback = operator)."""
    tmp = tempfile.mkdtemp(prefix="abuse-api-")
    saved = {k: getattr(ar, k) for k in ("MODE", "SMTP_HOST", "FROM_ADDR", "TEST_TO", "MAX_PER_HOUR",
                                         "DEDUPE_HOURS", "TOKEN", "MIN_SCORE", "REQUIRE_VERIFIED")}
    try:
        ar.MODE = mode
        ar.SMTP_HOST, ar.FROM_ADDR = env.get("smtp_host", ""), env.get("from_addr", "")
        ar.TEST_TO = env.get("test_to", "")
        ar.MAX_PER_HOUR = env.get("max_per_hour", 20)
        ar.DEDUPE_HOURS = env.get("dedupe_hours", 24)
        ar.TOKEN = env.get("token", "")
        ar.MIN_SCORE, ar.REQUIRE_VERIFIED = 0.85, True
        db = os.path.join(tmp, "scamouflage.db")
        make_alerts_db(db)
        store = ar.TakedownStore(os.path.join(tmp, "takedowns.db"))
        app = web.Application()
        peer = env.get("peer", "127.0.0.1")
        ar.setup_abuse_routes(
            app, store=store, alerts_db=db, peer=lambda request: peer,
            lookup=lambda host: ar.lookup_abuse_contact(host, store, fetch=env.get("fetch", lambda d: (RDAP_FIXTURE, None))),
            sender=lambda rep: ar.send_report(rep, smtp_factory=FakeSMTP))

        async def go():
            client = TestClient(TestServer(app))
            await client.start_server()
            try:
                return await fn(client, store)
            finally:
                await client.close()
        return asyncio.run(go())
    finally:
        for k, v in saved.items():
            setattr(ar, k, v)
        shutil.rmtree(tmp, ignore_errors=True)


def test_non_local_caller_gets_403_unless_token_matches():
    async def fn(client, store):
        cfg = await (await client.get("/api/abuse/config")).json()
        assert cfg["mode"] == "preview" and cfg["operator"] is False, "config is public but says who we are"
        assert "from" not in cfg
        for req in (client.get("/api/abuse/contact?domain=ezpass.com-xk2.win"),
                    client.post("/api/abuse/report", json={"alert_id": 1}),
                    client.post("/api/abuse/report", json={"alert_id": 1, "handoff": True}),
                    client.post("/api/abuse/report", json={"alert_id": 1, "send": True, "force": True}),
                    client.get("/api/abuse/reports")):
            r = await req
            assert r.status == 403, (r.method, r.url)
            assert "operator only" in (await r.json())["error"]
        assert store.recent() == [] and FakeSMTP.sent == []
        # wrong / empty token: still 403
        r = await client.post("/api/abuse/report", json={"alert_id": 1}, headers={"X-Scamouflage-Token": "nope"})
        assert r.status == 403
        r = await client.post("/api/abuse/report", json={"alert_id": 1}, headers={"X-Scamouflage-Token": ""})
        assert r.status == 403
        # the right token lets a remote operator in
        r = await client.post("/api/abuse/report", json={"alert_id": 1}, headers={"X-Scamouflage-Token": "s3cret"})
        assert r.status == 200 and (await r.json())["status"] == "preview"
        cfg = await (await client.get("/api/abuse/config", headers={"X-Scamouflage-Token": "s3cret"})).json()
        assert cfg["operator"] is True
    FakeSMTP.sent = []
    run_app("preview", fn, peer="203.0.113.7", token="s3cret")

    async def fn_no_token(client, store):
        # no SCAM_ABUSE_TOKEN configured: nothing a remote caller sends can match
        r = await client.post("/api/abuse/report", json={"alert_id": 1}, headers={"X-Scamouflage-Token": ""})
        assert r.status == 403
    run_app("preview", fn_no_token, peer="203.0.113.7", token="")

    async def fn_v6(client, store):
        assert (await client.post("/api/abuse/report", json={"alert_id": 1})).status == 200
    run_app("preview", fn_v6, peer="::1")


def test_contact_lookup_only_for_alerted_hostnames():
    async def fn(client, store):
        calls = []
        r = await client.get("/api/abuse/contact?domain=ezpass.com-xk2.win")
        assert r.status == 200 and (await r.json())["emails"] == ["abuse@namesilo.com"]
        for host in ("google.com", "com-xk2.win", "www.ezpass.com-xk2.win", "pay.ezpass.com-xk2.win"):
            r = await client.get(f"/api/abuse/contact?domain={host}")
            assert r.status == 404, host   # only the exact alerted hostname; not its parent or siblings
            assert "no alert" in (await r.json())["error"]
        assert (await client.get("/api/abuse/contact?domain=")).status == 400
        assert (await client.get("/api/abuse/contact?domain=*.foo.bar")).status == 400
        assert store.get_contact("google.com") is None, "nothing cached for refused names"
    run_app("preview", fn)


def test_only_high_confidence_verified_alerts_are_eligible():
    async def fn(client, store):
        r = await client.post("/api/abuse/report", json={"alert_id": 2, "send": True, "force": True})
        d = await r.json()
        assert r.status == 409 and d["eligible"] is False and "below the reporting threshold 0.85" in d["error"]
        r = await client.post("/api/abuse/report", json={"alert_id": 3, "handoff": True})
        d = await r.json()
        assert r.status == 409 and "not verified by Stage 3" in d["error"]
        r = await client.post("/api/abuse/report", json={"alert_id": 4})     # stage 0: public list, allowed
        assert r.status == 200
        r = await client.post("/api/abuse/report", json={"alert_id": 1})
        assert r.status == 200
        assert FakeSMTP.sent == [] and store.recent() == []
        cfg = await (await client.get("/api/abuse/config")).json()
        assert cfg["min_score"] == 0.85 and cfg["require_verified"] is True
    FakeSMTP.sent = []
    run_app("send", fn, smtp_host="smtp.example", from_addr="a@b.example")
    assert ar.eligibility(dict(ALERT, score=0.9, verified=0, stage=2)) is not None
    saved = ar.REQUIRE_VERIFIED
    try:
        ar.REQUIRE_VERIFIED = False
        assert ar.eligibility(dict(ALERT, score=0.9, verified=0, stage=2)) is None
    finally:
        ar.REQUIRE_VERIFIED = saved


def test_host_candidates_and_eligible_alert_lookup():
    assert ar.host_candidates("pay.ezpass.com-xk2.win") == ["pay.ezpass.com-xk2.win", "ezpass.com-xk2.win", "com-xk2.win"]
    assert ar.host_candidates("*.Com-XK2.win.") == ["com-xk2.win"]
    assert ar.host_candidates("evil.github.io") == ["evil.github.io"]        # shared hosting: never the platform
    assert ar.host_candidates("win") == [] and ar.host_candidates("a..b") == [] and ar.host_candidates("x/y.z") == []
    tmp = tempfile.mkdtemp(prefix="abuse-")
    try:
        db = os.path.join(tmp, "a.db")
        make_alerts_db(db)
        a, st = ar.find_eligible_alert("www.ezpass.com-xk2.win", db)           # parent of an alerted name
        assert st == "ok" and a["domain"] == "ezpass.com-xk2.win" and a["id"] == 1
        assert ar.find_eligible_alert("low.com-xk2.win", db) == (None, "not_eligible")
        assert ar.find_eligible_alert("nothing.example", db) == (None, "not_flagged")
        assert ar.find_eligible_alert("x.listed.com-xk2.win", db)[1] == "ok"  # stage 0 parent
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_public_draft_for_the_extension():
    async def fn(client, store):
        # a stranger (non-loopback) may ask for a draft of an eligible, flagged name
        r = await client.post("/api/abuse/draft", json={"hostname": "www.ezpass.com-xk2.win"})
        d = await r.json()
        assert r.status == 200, d
        assert d["matched"] == "ezpass.com-xk2.win" and d["domain"] == "com-xk2.win" and d["alert_id"] == 1
        assert d["contact"]["emails"] == ["abuse@namesilo.com"] and d["contact"]["registrar"] == "NameSilo, LLC"
        rep = d["report"]
        assert rep["to"] == ["abuse@namesilo.com"] and rep["mailto"].startswith("mailto:abuse@namesilo.com?")
        assert "A Scamouflage user" in rep["body"] and "browser extension" in rep["body"]
        assert "attachment" not in rep and "signed_alert" not in json.dumps(d)
        # nothing sent, nothing logged, no operator routes opened up
        assert FakeSMTP.sent == [] and store.recent() == []
        assert (await client.get("/api/abuse/reports")).status == 403
        # refusals
        r = await client.post("/api/abuse/draft", json={"hostname": "google.com"})
        assert r.status == 404 and (await r.json())["code"] == "not_flagged"
        r = await client.post("/api/abuse/draft", json={"hostname": "low.com-xk2.win"})
        assert r.status == 409 and (await r.json())["code"] == "not_eligible"
        r = await client.post("/api/abuse/draft", json={"hostname": "unverified.com-xk2.win"})
        assert r.status == 409
        assert (await client.post("/api/abuse/draft", json={"hostname": ""})).status == 400
        assert (await client.post("/api/abuse/draft", json={"hostname": "http://x.y/z"})).status == 400
        assert (await client.post("/api/abuse/draft", data="nope")).status == 400
        assert store.get_contact("google.com") is None
    FakeSMTP.sent = []
    run_app("preview", fn, peer="203.0.113.9")

    async def fn_rate(client, store):
        codes = []
        for _ in range(8):
            codes.append((await client.post("/api/abuse/draft", json={"hostname": "ezpass.com-xk2.win"})).status)
        assert codes == [200] * 6 + [429, 429]
    run_app("preview", fn_rate, peer="203.0.113.10")

    async def fn_off(client, store):
        r = await client.post("/api/abuse/draft", json={"hostname": "ezpass.com-xk2.win"})
        assert r.status == 503 and (await r.json())["code"] == "off"
    run_app("off", fn_off, peer="203.0.113.11")


def test_per_ip_limiter_windows():
    t = [1000.0]
    lim = ar.PerIpLimiter(per_minute=2, per_hour=3, clock=lambda: t[0])
    assert lim.allow("a") and lim.allow("a") and not lim.allow("a")
    assert lim.allow("b"), "other addresses are independent"
    t[0] += 61
    assert lim.allow("a"), "minute window slid"
    assert not lim.allow("a"), "hour cap (3) reached"
    t[0] += 3600
    assert lim.allow("a")


def test_preview_mode_builds_but_never_sends():
    async def fn(client, store):
        r = await client.get("/api/abuse/config")
        assert (await r.json())["mode"] == "preview"
        r = await client.get("/api/abuse/contact?domain=ezpass.com-xk2.win")
        assert r.status == 200 and (await r.json())["emails"] == ["abuse@namesilo.com"]

        r = await client.post("/api/abuse/report", json={"alert_id": 1})
        d = await r.json()
        assert r.status == 200 and d["status"] == "preview" and d["can_send"] is False
        assert d["report"]["to"] == ["abuse@namesilo.com"] and d["domain"] == "com-xk2.win"
        assert store.recent() == [], "previews are not logged"

        r = await client.post("/api/abuse/report", json={"alert_id": 1, "send": True})
        assert r.status == 403 and FakeSMTP.sent == []

        r = await client.post("/api/abuse/report", json={"alert_id": 1, "handoff": True, "reporter": {"email": "nope"}})
        assert r.status == 400
        r = await client.post("/api/abuse/report", json={"alert_id": 1, "handoff": True})
        assert r.status == 200 and (await r.json())["status"] == "mailto"
        log = (await (await client.get("/api/abuse/reports")).json())["items"]
        assert len(log) == 1 and log[0]["status"] == "mailto" and log[0]["domain"] == "com-xk2.win"
        assert "body" not in log[0]

        r = await client.post("/api/abuse/report", json={"alert_id": 999})
        assert r.status == 404
        r = await client.post("/api/abuse/report", data="nope")
        assert r.status == 400
    FakeSMTP.sent = []
    run_app("preview", fn)


def test_send_mode_sends_once_then_dedupes_and_caps():
    async def fn(client, store):
        r = await client.post("/api/abuse/report", json={"alert_id": 1, "send": True,
                                                         "reporter": {"name": "Ada", "email": "ada@example.org"}})
        d = await r.json()
        assert r.status == 200, d
        assert d["status"] == "sent" and d["sent_to"] == ["abuse@namesilo.com"] and d["message_id"]
        msg, to_addrs = FakeSMTP.sent[-1]
        assert to_addrs == ["abuse@namesilo.com"] and msg["From"] == "Scamouflage <abuse@scam.example>"
        assert msg["Subject"].startswith("[Phishing] ezpass.com-xk2.win")
        parts = list(msg.iter_attachments())
        assert len(parts) == 1 and parts[0].get_filename() == "scamouflage-alert-1.json"
        attached = json.loads(parts[0].get_payload(decode=True))
        assert attached["signed_alert"]["domain"] == "ezpass.com-xk2.win"

        r = await client.post("/api/abuse/report", json={"alert_id": 1, "send": True})
        assert r.status == 409 and len(FakeSMTP.sent) == 1, "same domain within 24 h is refused"
        r = await client.post("/api/abuse/report", json={"alert_id": 1, "send": True, "force": True})
        assert r.status == 200 and len(FakeSMTP.sent) == 2
        r = await client.post("/api/abuse/report", json={"alert_id": 1, "send": True, "force": True})
        assert r.status == 429, "hourly cap"
        log = (await (await client.get("/api/abuse/reports?domain=com-xk2.win")).json())["items"]
        assert [x["status"] for x in log] == ["sent", "sent"]
    FakeSMTP.sent = []
    run_app("send", fn, smtp_host="smtp.example", from_addr="Scamouflage <abuse@scam.example>", max_per_hour=2)


def test_test_to_reroutes_everything():
    async def fn(client, store):
        r = await client.post("/api/abuse/report", json={"alert_id": 1, "send": True})
        d = await r.json()
        assert r.status == 200 and d["rerouted"] and d["sent_to"] == ["me@example.org"]
        msg, to_addrs = FakeSMTP.sent[-1]
        assert to_addrs == ["me@example.org"] and "[TEST, would go to abuse@namesilo.com]" in msg["Subject"]
    FakeSMTP.sent = []
    run_app("send", fn, smtp_host="smtp.example", from_addr="abuse@scam.example", test_to="me@example.org")


def test_send_mode_without_contact_or_smtp():
    async def fn(client, store):
        r = await client.post("/api/abuse/report", json={"alert_id": 1, "send": True})
        assert r.status == 409   # RDAP found nothing -> nothing to send
        d = await r.json()
        assert d["contact"]["error"] == "not_found" and d["report"]["to"] == []
    run_app("send", fn, smtp_host="smtp.example", from_addr="a@b.example", fetch=lambda d: (None, "not_found"))

    async def fn2(client, store):
        r = await client.post("/api/abuse/report", json={"alert_id": 1, "send": True})
        assert r.status == 503   # mode send but no SMTP configured
    run_app("send", fn2)


def test_mode_off_answers_503_and_config_says_so():
    async def fn(client, store):
        assert (await (await client.get("/api/abuse/config")).json())["mode"] == "off"
        assert (await client.post("/api/abuse/report", json={"alert_id": 1})).status == 503
        assert (await client.get("/api/abuse/contact?domain=a.b")).status == 503
    run_app("off", fn)


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            t = time.time()
            fn()
            print(f"ok  {name}  ({time.time() - t:.2f}s)")
    print("all abuse_report tests passed")
