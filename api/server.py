"""Scamouflage API (role F) - aiohttp on :8000.

Read-only: serves what other stations write.
  SQLite  data/scamouflage.db  -> alerts (consumer), seen (consumer), labels (B)
  JSON    data/stats.json (A), results.json (C), leadtime.json (B), hardware.json (D)

If a source is missing, the endpoint returns mock data with "source": "mock"
so the dashboard can label simulated data. Real data -> "source": "live".

Run:  DATA_DIR=/path/to/data python3 api/server.py
"""
import asyncio
import json
import os
import random
import re
import sqlite3
import time
from collections import defaultdict
from pathlib import Path

from aiohttp import web

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("DATA_DIR", ROOT / "data"))
# SCAM_DB points straight at the consumer's DB; its folder holds the JSON files too.
if os.environ.get("SCAM_DB"):
    DB_PATH = Path(os.environ["SCAM_DB"])
    DATA_DIR = Path(os.environ.get("DATA_DIR", DB_PATH.parent))
else:
    DB_PATH = DATA_DIR / "scamouflage.db"
HOST = os.environ.get("API_HOST", "127.0.0.1")
PORT = int(os.environ.get("API_PORT", 8000))
WS_POLL_SECONDS = 1.0


# ---------------------------------------------------------------- helpers

def read_json(name):
    """Return parsed JSON file from DATA_DIR, or None if missing/partial."""
    try:
        with open(DATA_DIR / name) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def db():
    """Read-only connection, or None if the DB doesn't exist yet."""
    if not DB_PATH.exists():
        return None
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=2)
    conn.row_factory = sqlite3.Row
    return conn


def decode_row(row):
    """Row -> dict, JSON-decoding text columns that hold lists/dicts."""
    out = {}
    for k in row.keys():
        v = row[k]
        if isinstance(v, str) and v[:1] in "[{":
            try:
                v = json.loads(v)
            except json.JSONDecodeError:
                pass
        out[k] = v
    out.setdefault("id", out.get("cert_id"))
    return out


def fetch_alerts(limit=100, after_rowid=0, since=None):
    """since: only alerts with seen_at > since (ISO string or unix seconds)."""
    conn = db()
    if conn is None:
        return None
    try:
        sql = "SELECT rowid AS _rowid, * FROM alerts WHERE rowid > ?"
        args = [after_rowid]
        if since:
            sql += " AND seen_at > ?"
            args.append(float(since) if since.replace(".", "", 1).isdigit() else since)
        sql += " ORDER BY rowid DESC LIMIT ?"
        args.append(limit)
        rows = conn.execute(sql, args).fetchall()
        return [decode_row(r) for r in rows]
    except sqlite3.OperationalError:  # table not created yet
        return None
    finally:
        conn.close()


def ok(payload, source):
    payload = dict(payload) if isinstance(payload, dict) else {"items": payload}
    payload["source"] = source
    return web.json_response(payload)


# ---------------------------------------------------------------- campaigns

_RANDOM_TOKEN = re.compile(r"(?<![a-z])[a-z0-9]*\d[a-z0-9]*(?![a-z])|[a-z0-9]{12,}")


def template(domain):
    """ezpass.com-xk29.win -> ezpass.com-*.win  (random/digit tokens -> *)."""
    d = domain.lower().lstrip("*.")
    parts = re.split(r"([.\-])", d)
    return "".join("*" if _RANDOM_TOKEN.fullmatch(p or "") else p for p in parts)


def build_campaigns(alerts, min_size=2):
    groups = defaultdict(list)
    for a in alerts:
        dom = a.get("domain") or (a.get("domains") or [""])[0]
        if dom:
            groups[template(dom)].append(a)
    out = []
    for tpl, members in groups.items():
        if len(members) < min_size:
            continue
        out.append({
            "template": tpl,
            "count": len(members),
            "max_score": max(m.get("score", 0) for m in members),
            "first_seen": min(str(m.get("seen_at", "")) for m in members),
            "last_seen": max(str(m.get("seen_at", "")) for m in members),
            "domains": [m.get("domain") for m in members][:20],
        })
    return sorted(out, key=lambda c: c["count"], reverse=True)


# ---------------------------------------------------------------- mocks

_BRANDS = ["ezpass", "ntta", "txtag", "sunpass", "usps", "dmv", "paytoll"]
_TLDS = ["win", "top", "xin", "vip", "icu"]


def mock_alert(i=None):
    i = i if i is not None else random.randint(1000, 99999)
    tok = "".join(random.choices("abcdefghjkmnpqrstuvwxyz23456789", k=4))
    dom = f"{random.choice(_BRANDS)}.com-{tok}.{random.choice(_TLDS)}"
    cid = f"mock{i:08d}"
    return {
        "id": cid, "cert_id": cid, "domain": dom, "domains": [dom],
        "score": round(random.uniform(0.80, 0.99), 3),
        "reasons": ["brand in subdomain", "cheap TLD", "com- pattern"],
        "seen_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "issuer": random.choice(["Let's Encrypt", "Google Trust Services"]),
        "log": "mock-log",
        "verify": {"status": "ok", "algo": "ecdsa-p256"},
        "crtsh_url": "https://crt.sh/",
        "sig": "MOCK", "key_id": "mock",
    }


MOCK_ALERTS = [mock_alert(i) for i in range(25)]
MOCK = {
    "stats.json": {"certs_total": 123456, "certs_per_sec": 247.3,
                   "verified": {"ok": 0.82, "fail": 0.01, "unknown_issuer": 0.17},
                   "alerts_total": 25, "uptime_s": 3600},
    "results.json": {"precision": 0.0, "recall": 0.0, "pr_auc": 0.0,
                     "false_alarms_per_10k": 0.0,
                     "baselines": {"unit42_regex": {}, "keyword_rule": {}}},
    "leadtime.json": {"median_days": 0.0, "min_days": 0.0, "max_days": 0.0,
                      "share_before_any_feed": 0.0, "n": 0},
    "hardware.json": {"machine": "unknown", "nnpa": False,
                      "cpacf_on": {}, "cpacf_off": {}, "speedup": {}},
}


# ---------------------------------------------------------------- routes

routes = web.RouteTableDef()


def json_file_route(path, filename):
    @routes.get(path)
    async def handler(request):
        data = read_json(filename)
        return ok(data, "live") if data is not None else ok(MOCK[filename], "mock")
    return handler


json_file_route("/api/stats", "stats.json")
json_file_route("/api/results", "results.json")
json_file_route("/api/leadtime", "leadtime.json")
json_file_route("/api/hardware", "hardware.json")


@routes.get("/api/alerts")
async def alerts(request):
    try:
        limit = min(int(request.query.get("limit", 100)), 1000)
    except ValueError:
        limit = 100
    since = request.query.get("since")
    rows = fetch_alerts(limit, since=since)
    if rows is None:
        items = MOCK_ALERTS
        if since:
            items = [a for a in items if a["seen_at"] > since]
        return ok({"items": items[:limit]}, "mock")
    return ok({"items": rows}, "live")


@routes.get("/api/alerts/{id}")
async def alert_detail(request):
    aid = request.match_info["id"]
    conn = db()
    if conn is None:
        hit = next((a for a in MOCK_ALERTS if a["id"] == aid), None)
        if hit:
            return ok(hit, "mock")
        raise web.HTTPNotFound(text=json.dumps({"error": "not found"}),
                               content_type="application/json")
    try:
        row = conn.execute(
            "SELECT rowid AS _rowid, * FROM alerts WHERE cert_id = ? LIMIT 1",
            (aid,),
        ).fetchone()
    except sqlite3.OperationalError:
        row = None
    finally:
        conn.close()
    if row is None:
        raise web.HTTPNotFound(text=json.dumps({"error": "not found"}),
                               content_type="application/json")
    return ok(decode_row(row), "live")


@routes.get("/api/campaigns")
async def campaigns(request):
    rows = fetch_alerts(5000)
    if rows is None:
        return ok({"items": build_campaigns(MOCK_ALERTS, min_size=1)}, "mock")
    return ok({"items": build_campaigns(rows)}, "live")


@routes.get("/api/health")
async def health(request):
    return web.json_response({
        "ok": True, "data_dir": str(DATA_DIR), "db_exists": DB_PATH.exists(),
        "files": {n: (DATA_DIR / n).exists() for n in MOCK},
    })


@routes.get("/ws/live")
async def ws_live(request):
    """Pushes {"type":"stats"} every second and {"type":"alert"} per new alert."""
    ws = web.WebSocketResponse(heartbeat=20)
    await ws.prepare(request)
    last_rowid = None
    try:
        while not ws.closed:
            stats = read_json("stats.json")
            await ws.send_json({"type": "stats", "source": "live" if stats else "mock",
                                "data": stats or MOCK["stats.json"]})

            rows = fetch_alerts(50, after_rowid=last_rowid or 0)
            if rows is None:
                if random.random() < 0.5:
                    await ws.send_json({"type": "alert", "source": "mock",
                                        "data": mock_alert()})
            else:
                if last_rowid is None:  # first poll: start from newest, don't replay
                    last_rowid = rows[0]["_rowid"] if rows else 0
                else:
                    for r in reversed(rows):
                        await ws.send_json({"type": "alert", "source": "live", "data": r})
                    if rows:
                        last_rowid = rows[0]["_rowid"]
            await asyncio.sleep(WS_POLL_SECONDS)
    except (ConnectionResetError, asyncio.CancelledError):
        pass
    return ws


# ---------------------------------------------------------------- app

@web.middleware
async def cors(request, handler):
    if request.method == "OPTIONS":
        resp = web.Response()
    else:
        resp = await handler(request)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "*"
    return resp


def make_app():
    app = web.Application(middlewares=[cors])
    app.add_routes(routes)
    try:  # Shriya's blocklist route for the Chrome extension
        import sys
        sys.path.insert(0, str(ROOT))
        from backend.blocklist_route import setup_blocklist_route
        setup_blocklist_route(app)
        print("blocklist route: on")
    except ImportError as e:
        print(f"blocklist route: off ({e})")
    return app


if __name__ == "__main__":
    print(f"Scamouflage API on {HOST}:{PORT}  db={DB_PATH}  data_dir={DATA_DIR}")
    web.run_app(make_app(), host=HOST, port=PORT)
