"""Scamouflage API (role F) - aiohttp on :8000.

Read-only: serves what other stations write.
  SQLite  data/scamouflage.db  -> alerts (consumer), seen (consumer), labels (B)
  JSON    data/stats.json (A), results.json (C), leadtime.json (B), hardware.json (D),
          cpacf_live.json (D)
  PEM     data/alert_pubkey.pem (D)

Real data only: every answer has "source": "live". If a source is missing (no stats.json yet,
no DB), the endpoint answers 503 {"error": ..., "source": "unavailable"}; nothing is made up.
The dashboard (dashboard/) is served from the same server at /, so it calls /api/... on the
same origin (no CORS, no mixed http/https).

Run:  DATA_DIR=/path/to/data python3 api/server.py      (API_HOST / API_PORT to change the bind)
"""
import asyncio
import json
import os
import re
import sqlite3
import sys
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
sys.path.insert(0, str(ROOT))  # backend/ and alerts/ live next to api/
DASHBOARD_DIR = ROOT / "dashboard"
DASHBOARD_FILES = ("index.html", "app.js", "style.css", "logo.png")
HOST = os.environ.get("API_HOST", "127.0.0.1")
PORT = int(os.environ.get("API_PORT", 8000))
WS_POLL_SECONDS = 1.0
WS_CPACF_EVERY = 2  # polls, i.e. every 2 s (cpacf_live.json refreshes every 2 s)


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


def has_stage(conn):
    """True once the consumer has added alerts.stage (0 = known, >0 = new)."""
    return any(r[1] == "stage" for r in conn.execute("PRAGMA table_info(alerts)"))


def fetch_alerts(limit=100, after_rowid=0, since=None, stage=None):
    """since: only alerts with seen_at > since (ISO string or unix seconds).
    stage: only alerts with that stage. Without a stage column every alert
    counts as new, so stage=0 matches nothing and stage>0 matches everything.
    Rows with stage NULL (added before the column) count as stage 1."""
    conn = db()
    if conn is None:
        return None
    try:
        sql = "SELECT rowid AS _rowid, * FROM alerts WHERE rowid > ?"
        args = [after_rowid]
        if since:
            sql += " AND seen_at > ?"
            args.append(float(since) if since.replace(".", "", 1).isdigit() else since)
        if stage is not None:
            if has_stage(conn):
                sql += " AND COALESCE(stage, 1) = ?"
                args.append(stage)
            elif stage == 0:
                return []
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


# ---------------------------------------------------------------- sources

JSON_FILES = ("stats.json", "results.json", "leadtime.json", "hardware.json", "cpacf_live.json")


def unavailable(what):
    """503 instead of made-up data."""
    return web.HTTPServiceUnavailable(
        text=json.dumps({"error": f"{what} not available yet", "source": "unavailable"}),
        content_type="application/json")


# ---------------------------------------------------------------- routes

routes = web.RouteTableDef()


def json_file_route(path, filename, *aliases):
    async def handler(request):
        data = read_json(filename)
        if data is None:
            raise unavailable(filename)
        return ok(data, "live")
    for p in (path, *aliases):
        routes.get(p)(handler)
    return handler


def lead_time_summary():
    """leadtime.json (model/lead_time.py, hourly) in the shape /api/stats promises. Stage-0 alerts
    never count. None if the job hasn't written the file yet."""
    lt = read_json("leadtime.json")
    if lt is None:
        return None
    med = lt.get("median_days")
    return {
        "n_later_listed": lt.get("n") or 0,               # our stage>=1 alerts a feed listed later
        "n_alerts_new": lt.get("n_alerts_new"),
        "median_hours_early": None if med is None else round(med * 24, 1),
        "share_before_any_feed": lt.get("share_before_any_feed"),
        "examples": lt.get("examples") or [],
        "generated_at": lt.get("generated_at"),
    }


@routes.get("/api/stats")
async def stats(request):
    data = read_json("stats.json")
    if data is None:
        raise unavailable("stats.json")
    data["lead_time"] = lead_time_summary()
    return ok(data, "live")


json_file_route("/api/results", "results.json")
json_file_route("/api/leadtime", "leadtime.json")
json_file_route("/api/hardware", "hardware.json")
json_file_route("/api/cpacf/live", "cpacf_live.json", "/api/cpacf")


def bad_request(msg):
    return web.HTTPBadRequest(text=json.dumps({"error": msg}),
                              content_type="application/json")


@routes.get("/api/alerts")
async def alerts(request):
    try:
        limit = min(int(request.query.get("limit", 100)), 1000)
    except ValueError:
        limit = 100
    since = request.query.get("since")
    stage = request.query.get("stage")
    if stage is not None:
        try:
            stage = int(stage)
        except ValueError:
            raise bad_request("stage must be an integer")
    rows = fetch_alerts(limit, since=since, stage=stage)
    if rows is None:
        raise unavailable("alerts database")
    return ok({"items": rows}, "live")


# Registered before /api/alerts/{id} so "summary"/"pubkey" aren't taken as ids.
@routes.get("/api/alerts/summary")
async def alerts_summary(request):
    """known_total = stage 0, new_total = stage > 0. No stage column -> all new."""
    conn = db()
    if conn is not None:
        try:
            if has_stage(conn):
                known, new, total = conn.execute(
                    "SELECT COALESCE(SUM(stage = 0), 0), COALESCE(SUM(COALESCE(stage, 1) > 0), 0),"
                    " COUNT(*) FROM alerts").fetchone()
                has_col = True
            else:
                known, new, total = 0, *conn.execute(
                    "SELECT COUNT(*), COUNT(*) FROM alerts").fetchone()
                has_col = False
            return ok({"known_total": known, "new_total": new, "total": total,
                       "stage_column": has_col}, "live")
        except sqlite3.OperationalError:  # table not created yet
            pass
        finally:
            conn.close()
    raise unavailable("alerts database")


@routes.get("/api/alerts/pubkey")
async def alerts_pubkey(request):
    """Public key for alert signatures (data/alert_pubkey.pem). No mock: a fake
    key would make every alert look forged, so a missing key is a 503."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from alerts.sign import key_id_of
        pem = (DATA_DIR / "alert_pubkey.pem").read_bytes()
        pub = load_pem_public_key(pem)
        if not isinstance(pub, Ed25519PublicKey):
            raise ValueError("not an Ed25519 key")
    except (ImportError, OSError, ValueError) as e:
        why = "alert_pubkey.pem missing" if isinstance(e, FileNotFoundError) else str(e)
        raise web.HTTPServiceUnavailable(
            text=json.dumps({"error": f"alert public key unavailable: {why}"}),
            content_type="application/json")
    return ok({"key_id": key_id_of(pub), "alg": "Ed25519",
               "public_key_pem": pem.decode()}, "live")


@routes.get("/api/alerts/{id}")
async def alert_detail(request):
    aid = request.match_info["id"]
    conn = db()
    if conn is None:
        raise unavailable("alerts database")
    try:
        # the numeric alert id (what /api/alerts lists as "id"), or a cert_id
        if aid.isdigit():
            row = conn.execute("SELECT rowid AS _rowid, * FROM alerts WHERE id = ? LIMIT 1",
                               (int(aid),)).fetchone()
        else:
            row = None
        if row is None:
            row = conn.execute(
                "SELECT rowid AS _rowid, * FROM alerts WHERE cert_id = ? ORDER BY id DESC LIMIT 1",
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
        raise unavailable("alerts database")
    return ok({"items": build_campaigns(rows)}, "live")


STALE_S = 60.0  # no stats.json update for this long = the consumer is down


def health_payload(now=None):
    """For the demo: is the pipeline alive, how far behind, which engine stages are real."""
    now = time.time() if now is None else now
    st = read_json("stats.json") or {}
    eng = st.get("engine") or {}
    age = round(now - st["ts"], 1) if st.get("ts") else None
    last_cert = st.get("last_seen_at")
    if last_cert is None and st.get("ts") and st.get("lag_s") is not None:
        last_cert = round(st["ts"] - st["lag_s"], 1)   # stats.json: lag_s = ts - last cert seen_at
    stages = {k: eng.get(k) for k in ("stage0", "stage1", "stage2", "stage3")}
    healthy = (age is not None and age < STALE_S and (st.get("lag_s") or 0) < 60
               and (eng.get("mode") != "on" or all(v == "real" for v in stages.values())))
    return {
        "ok": bool(healthy),
        "stats_age_s": age,
        "last_cert_seen_at": last_cert,
        "lag_s": st.get("lag_s"),
        "certs_per_s": st.get("certs_per_s"),
        "dropped_total": st.get("dropped_total"),
        "engine": {"mode": eng.get("mode"), **stages, "stage1_version": eng.get("stage1_version"),
                   "signing": (eng.get("signing") or {}).get("ok")},
        "data_dir": str(DATA_DIR), "db_exists": DB_PATH.exists(),
        "files": {n: (DATA_DIR / n).exists() for n in JSON_FILES},
    }


@routes.get("/api/health")
@routes.get("/health")
async def health(request):
    return web.json_response(health_payload())


@routes.get("/ws/live")
async def ws_live(request):
    """Pushes {"type":"stats"} every second, {"type":"cpacf"} every 2 s and
    {"type":"alert"} per new alert."""
    ws = web.WebSocketResponse(heartbeat=20)
    await ws.prepare(request)
    last_rowid = None
    tick = 0
    try:
        while not ws.closed:
            stats = read_json("stats.json")
            if stats is not None:  # real data only; nothing is pushed while a source is missing
                await ws.send_json({"type": "stats", "source": "live", "data": stats})
            if tick % WS_CPACF_EVERY == 0:
                cpacf = read_json("cpacf_live.json")
                if cpacf is not None:
                    await ws.send_json({"type": "cpacf", "source": "live", "data": cpacf})
            tick += 1

            rows = fetch_alerts(50, after_rowid=last_rowid or 0)
            if rows is not None:
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


def dashboard_routes(app):
    """The website, same origin as the API. Only these files are served (no directory listing,
    nothing else from the repo)."""
    async def index(request):
        return web.FileResponse(DASHBOARD_DIR / "index.html", headers={"Cache-Control": "no-cache"})

    def file_route(name):
        async def handler(request):
            return web.FileResponse(DASHBOARD_DIR / name, headers={"Cache-Control": "no-cache"})
        return handler

    if (DASHBOARD_DIR / "index.html").exists():
        app.router.add_get("/", index)
        for name in DASHBOARD_FILES:
            if (DASHBOARD_DIR / name).exists():
                app.router.add_get(f"/{name}", file_route(name))


def make_app():
    app = web.Application(middlewares=[cors])
    app.add_routes(routes)
    dashboard_routes(app)
    try:  # Shriya's blocklist route for the Chrome extension
        from backend.blocklist_route import setup_blocklist_route
        setup_blocklist_route(app)
        print("blocklist route: on")
    except ImportError as e:
        print(f"blocklist route: off ({e})")
    return app


if __name__ == "__main__":
    print(f"Scamouflage API on {HOST}:{PORT}  db={DB_PATH}  data_dir={DATA_DIR}")
    web.run_app(make_app(), host=HOST, port=PORT)
