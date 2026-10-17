"""Scamouflage consumer: CT stream -> verify -> featurize -> score -> sign -> SQLite.

Run (on the VM, from the repo root):
    python -m ingest.consumer                       # live stream
    python -m ingest.consumer --url ws://127.0.0.1:8081/   # a replay
    python -m ingest.consumer --workers 3           # use all 3 cores

Writes:
    data/scamouflage.db   (alerts, seen; labels table is created for Role B)
    data/stats.json       (refreshed every second, read by the API/dashboard)
"""
import argparse
import asyncio
import collections
import concurrent.futures as cf
import hashlib
import json
import os
import signal
import sys
import time

import websockets

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ingest.db import DEFAULT_DB, connect  # noqa: E402
from ingest.record import brand_hit, to_record  # noqa: E402


# ---------------------------------------------------------------- the stations
def _load_stations():
    from alerts.sign import sign
    from features.features import featurize
    from model.model import score
    from verify.verify import verify
    return verify, featurize, score, sign


_STATIONS = None


def process_batch(records, threshold):
    """Runs in a worker process (or inline). Pure function: no DB access."""
    global _STATIONS
    if _STATIONS is None:
        _STATIONS = _load_stations()
    verify, featurize, score, sign = _STATIONS
    out = []
    for rec in records:
        t0 = time.perf_counter()
        try:
            v = verify(rec)
        except Exception as e:  # a broken station must never kill the pipeline
            v = {"status": "fail", "algo": f"error:{type(e).__name__}"}
        t1 = time.perf_counter()
        try:
            s = score(featurize(rec))
        except Exception as e:
            s = {"score": 0.0, "reasons": [f"error:{type(e).__name__}"]}
        t2 = time.perf_counter()
        alert = None
        if float(s.get("score", 0.0)) >= threshold:
            alert = {
                "cert_id": rec["id"],
                "domain": brand_hit(rec["domains"]) or (rec["domains"][0] if rec["domains"] else ""),
                "domains": rec["domains"],
                "score": float(s["score"]),
                "reasons": list(s.get("reasons") or []),
                "seen_at": rec["seen_at"],
                "issuer": rec["issuer"],
                "log": rec["log"],
                "verify": v.get("status"),
                "crtsh_url": f"https://crt.sh/?q={rec['id']}",
            }
            try:
                alert = sign(alert)
            except Exception as e:
                alert["sig"], alert["key_id"] = "", f"error:{type(e).__name__}"
        out.append((rec["id"], v.get("status", "fail"), alert, t1 - t0, t2 - t1))
    return out


# ---------------------------------------------------------------- helpers
def sampled(domain: str, pct: int) -> bool:
    """Deterministic ~pct% sample so the same domain is always in or out."""
    return int(hashlib.blake2b(domain.encode(), digest_size=2).hexdigest(), 16) % 100 < pct


class Dedupe:
    """Remembers the last `cap` cert hashes (same cert shows up in several logs)."""

    def __init__(self, cap=500_000):
        self.cap, self.d = cap, collections.OrderedDict()

    def seen(self, k):
        if k in self.d:
            return True
        self.d[k] = None
        if len(self.d) > self.cap:
            self.d.popitem(last=False)
        return False


class Stats:
    def __init__(self):
        self.start = time.time()
        self.c = collections.Counter()
        self.logs = collections.Counter()
        self.verify = collections.Counter()
        self.win = collections.deque()  # (t, msgs, certs)
        self.verify_s = 0.0
        self.score_s = 0.0
        self.last_alert = None
        self.last_seen_at = None

    def snapshot(self, queue_depth):
        now = time.time()
        self.win.append((now, self.c["msgs"], self.c["certs"]))
        while self.win and now - self.win[0][0] > 10:
            self.win.popleft()
        t0, m0, c0 = self.win[0]
        dt = max(now - t0, 1e-9)
        n = max(self.c["processed"], 1)
        return {
            "ts": now,
            "uptime_s": round(now - self.start, 1),
            "msgs_total": self.c["msgs"],
            "certs_total": self.c["certs"],
            "dupes_total": self.c["dupes"],
            "precert_total": self.c["precert"],
            "cert_total": self.c["cert"],
            "processed_total": self.c["processed"],
            "alerts_total": self.c["alerts"],
            "msgs_per_s": round((self.c["msgs"] - m0) / dt, 1) if len(self.win) > 1 else 0.0,
            "certs_per_s": round((self.c["certs"] - c0) / dt, 1) if len(self.win) > 1 else 0.0,
            "verify": dict(self.verify),
            "avg_verify_ms": round(1000 * self.verify_s / n, 3),
            "avg_score_ms": round(1000 * self.score_s / n, 3),
            "queue_depth": queue_depth,
            "lag_s": round(now - self.last_seen_at, 2) if self.last_seen_at else None,
            "top_logs": dict(self.logs.most_common(10)),
            "last_alert": self.last_alert,
        }


def write_json_atomic(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


# ---------------------------------------------------------------- main loop
async def run(args):
    con = connect(args.db)
    stats = Stats()
    dedupe = Dedupe()
    queue: asyncio.Queue = asyncio.Queue(maxsize=args.max_queue)
    pool = cf.ProcessPoolExecutor(args.workers) if args.workers > 0 else None
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    async def reader():
        backoff = 1
        while not stop.is_set():
            try:
                async with websockets.connect(args.url, max_size=None, ping_interval=30,
                                              open_timeout=10) as ws:
                    print(f"[consumer] connected to {args.url}", flush=True)
                    backoff = 1
                    async for raw in ws:
                        stats.c["msgs"] += 1
                        try:
                            rec = to_record(json.loads(raw))
                        except (ValueError, TypeError):
                            stats.c["bad_json"] += 1
                            continue
                        if rec is None:
                            continue
                        if dedupe.seen(rec["id"]):
                            stats.c["dupes"] += 1
                            continue
                        stats.c["certs"] += 1
                        stats.c[rec["update_type"]] += 1
                        stats.logs[rec["log"]] += 1
                        if queue.full():
                            stats.c["dropped"] += 1  # never block the socket
                            continue
                        queue.put_nowait(rec)
                        if stop.is_set():
                            break
                    if args.exit_on_close:
                        stop.set()
            except (OSError, websockets.exceptions.WebSocketException) as e:
                if args.exit_on_close and stats.c["msgs"]:
                    stop.set()
                    break
                print(f"[consumer] stream error: {e!r}; retry in {backoff}s", flush=True)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30)

    def write_results(results, recs_by_id):
        alerts_rows, seen_rows = [], []
        for cid, vstatus, alert, vt, st in results:
            stats.c["processed"] += 1
            stats.verify[vstatus] += 1
            stats.verify_s += vt
            stats.score_s += st
            rec = recs_by_id[cid]
            for d in rec["domains"]:
                if brand_hit([d]) or sampled(d, args.sample_pct):
                    seen_rows.append((d, rec["seen_at"], cid))
            if alert:
                stats.c["alerts"] += 1
                alerts_rows.append((
                    alert["cert_id"], alert["domain"], json.dumps(alert["domains"]),
                    alert["score"], json.dumps(alert["reasons"]), alert["seen_at"],
                    alert["issuer"], alert["log"], alert["verify"], alert["crtsh_url"],
                    alert.get("sig", ""), alert.get("key_id", ""),
                ))
                stats.last_alert = {k: alert[k] for k in ("domain", "score", "seen_at", "crtsh_url")}
        with con:
            if alerts_rows:
                con.executemany(
                    "INSERT INTO alerts(cert_id,domain,domains,score,reasons,seen_at,issuer,log,"
                    "verify,crtsh_url,sig,key_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", alerts_rows)
            if seen_rows:
                con.executemany(
                    "INSERT OR IGNORE INTO seen(domain,first_cert_seen,cert_id) VALUES (?,?,?)",
                    seen_rows)

    async def worker():
        inflight = set()
        while not (stop.is_set() and queue.empty()):
            batch = []
            try:
                batch.append(await asyncio.wait_for(queue.get(), timeout=0.25))
            except asyncio.TimeoutError:
                pass
            while batch and len(batch) < args.batch and not queue.empty():
                batch.append(queue.get_nowait())
            if batch:
                stats.last_seen_at = batch[-1]["seen_at"] or stats.last_seen_at
                by_id = {r["id"]: r for r in batch}
                if pool:
                    fut = loop.run_in_executor(pool, process_batch, batch, args.threshold)
                    fut.add_done_callback(lambda f, b=by_id: write_results(f.result(), b))
                    inflight.add(fut)
                    fut.add_done_callback(inflight.discard)
                    # keep at most 2 batches per worker in flight
                    if len(inflight) >= 2 * args.workers:
                        await asyncio.wait(inflight, return_when=asyncio.FIRST_COMPLETED)
                else:
                    write_results(process_batch(batch, args.threshold), by_id)
                    await asyncio.sleep(0)
        if inflight:
            await asyncio.wait(inflight)

    async def stats_writer():
        os.makedirs(os.path.dirname(args.stats) or ".", exist_ok=True)
        while not stop.is_set():
            snap = stats.snapshot(queue.qsize())
            snap["dropped_total"] = stats.c["dropped"]
            write_json_atomic(args.stats, snap)
            if not args.quiet and int(snap["uptime_s"]) % 10 == 0:
                print(f"[consumer] {snap['certs_per_s']:.0f} certs/s  processed={snap['processed_total']} "
                      f"alerts={snap['alerts_total']} queue={snap['queue_depth']} "
                      f"dropped={snap['dropped_total']}", flush=True)
            await asyncio.sleep(1)

    tasks = [asyncio.create_task(reader()), asyncio.create_task(worker()),
             asyncio.create_task(stats_writer())]
    await stop.wait()
    await asyncio.gather(tasks[1], return_exceptions=True)
    for t in tasks:
        t.cancel()
    snap = stats.snapshot(queue.qsize())
    snap["dropped_total"] = stats.c["dropped"]
    write_json_atomic(args.stats, snap)
    if pool:
        pool.shutdown()
    con.close()
    print(f"[consumer] stopped. certs={stats.c['certs']} processed={stats.c['processed']} "
          f"alerts={stats.c['alerts']} dupes={stats.c['dupes']}", flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", default=os.environ.get("SCAM_STREAM", "ws://127.0.0.1:8080/full-stream"))
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--stats", default="data/stats.json")
    p.add_argument("--threshold", type=float, default=0.8, help="score >= this becomes an alert")
    p.add_argument("--workers", type=int, default=0, help="0 = inline; 3 = use all VM cores")
    p.add_argument("--batch", type=int, default=200)
    p.add_argument("--max-queue", type=int, default=50_000)
    p.add_argument("--sample-pct", type=int, default=1, help="%% of non-brand domains kept in seen")
    p.add_argument("--exit-on-close", action="store_true", help="stop when the stream ends (replays)")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
