"""Scamouflage consumer: CT stream -> verify -> detection engine -> Stage 3 -> sign -> SQLite.

Run (on the VM, from the repo root):
    python -m ingest.consumer                       # live stream
    python -m ingest.consumer --url ws://127.0.0.1:8081/   # a replay
    python -m ingest.consumer --workers 3           # use all 3 cores
    python -m ingest.consumer --no-engine           # the old featurize/score path (safety net)

Engine path (MODEL_SPEC §10), the default:
    worker processes: verify.verify(record), then engine.decide_cert(leaf_cert, seen_at) per cert
                      (Engine.from_disk once per worker; Stage 0 refresh() every 15 min)
    main process:     Stage 0 `scam` -> alert. `high`/`maybe` -> Stage 3 queue (asyncio, 2 at a
                      time, 10 s timeout) -> engine.finalize -> alert if `scam`. One alert per
                      host per 24 h. Signed after finalize, when every field is set.
    Model:      --models, else $SCAM_MODELS, else data/models
    Known list: --labels-db, else $LABELS_DB, else data/labels.db, else ~/scamouflage-data/labels.db

Writes:
    data/scamouflage.db   (alerts, seen; labels table is created for Role B)
    data/stats.json       (refreshed every second, read by the API/dashboard)

stats.json `unique_names_per_day`: every clean name is hashed (blake2b, 64 bit); names whose hash
is 0 mod 64 are a deterministic 1/64 sample (the same name is always in or out, so precert + cert
copies count once). Distinct sampled hashes per clock hour x 64 = distinct names that hour; x 24 =
per day. Until a full hour has passed, the current hour is scaled up from the time measured so far.
It is "distinct per hour x 24", so a name seen in two different hours counts twice (an upper bound
on distinct names per day). Sampling error ~ 1/sqrt(sampled names per hour), well under 1 %.
"""
import argparse
import asyncio
import collections
import concurrent.futures as cf
import hashlib
import json
import logging
import os
import random
import signal
import sys
import time

import websockets

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

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
                "crtsh_url": rec["crtsh_url"],
            }
            try:
                alert = sign(alert)
            except Exception as e:
                alert["sig"], alert["key_id"] = "", f"error:{type(e).__name__}"
        out.append((rec["id"], v.get("status", "fail"), alert, t1 - t0, t2 - t1))
    return out


# ---------------------------------------------------------------- the engine path (MODEL_SPEC §10)
NAME_SAMPLE = 64            # 1 in 64 names (by hash) feeds unique_names_per_day
RECENT_NAMES_PER_BATCH = 10
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s[%(process)d]: %(message)s"
_ENGINE = None              # per process: {"engine", "verify", "info", "refreshed"}


def rss_mb():
    try:
        with open("/proc/self/statm") as f:
            return round(int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE") / 1e6, 1)
    except (OSError, ValueError):
        return None


def engine_info(eng) -> dict:
    def real(s):
        return "real" if s is not None else "stub"
    return {"stage0": real(eng.stage0), "stage0_hosts": len(eng.stage0) if eng.stage0 is not None else 0,
            "stage1": real(eng.stage1), "stage1_version": getattr(eng.stage1, "version", None) or "stub",
            "t_high": eng.t_high, "t_low": eng.t_low,
            "stage2": real(eng.stage2), "stage2_version": getattr(eng.stage2, "version", None) or "stub"}


def _engine_state(cfg):
    global _ENGINE
    if _ENGINE is None:
        from model.engine import Engine
        from verify.verify import verify
        t0 = time.perf_counter()
        eng = Engine.from_disk(labels_db=cfg["labels_db"], model_dir=cfg["model_dir"])
        info = engine_info(eng)
        info.update(pid=os.getpid(), load_s=round(time.perf_counter() - t0, 1), stage0_refreshes=0,
                    stage0_last_added=0, rss_mb=rss_mb())
        print(f"[engine] worker pid={info['pid']}: stage0={info['stage0']} ({info['stage0_hosts']:,} hosts) "
              f"stage1={info['stage1']} version={info['stage1_version']} t_high={info['t_high']} "
              f"t_low={info['t_low']} stage2={info['stage2']} ({info['stage2_version']}) "
              f"loaded in {info['load_s']} s, rss {info['rss_mb']} MB", flush=True)
        # Each worker gets its own random phase in the refresh cycle. With the same start time all
        # workers refreshed (or fully reloaded, e.g. when tranco_top changed) in the same second:
        # a 5.5 s processing-lag spike in the replay. Spread out, at most one reloads at a time.
        _ENGINE = {"engine": eng, "verify": verify, "info": info,
                   "refreshed": time.time() - refresh_phase(cfg.get("refresh_s", 900.0))}
    return _ENGINE


def refresh_phase(refresh_s, rng=random):
    """Seconds this worker pretends its last Stage 0 refresh is in the past: uniform in
    [0, refresh_s), so the first refresh (and every one after it) lands at a different moment
    in each worker."""
    return rng.uniform(0.0, float(refresh_s))


def init_engine_worker(cfg):
    """ProcessPoolExecutor initializer: load the engine ONCE per worker process."""
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
    _engine_state(cfg)


def engine_ping(cfg, hold_s=0.0):
    """Startup check. hold_s keeps this worker busy so the other pings reach the other workers."""
    info = dict(_engine_state(cfg)["info"], rss_mb=rss_mb())
    time.sleep(hold_s)
    return info


def process_batch_engine(records, cfg):
    """Runs in a worker process (or inline). No DB access. Returns only non-safe Decisions
    (with what the main process needs to write the alert) plus counters."""
    st = _engine_state(cfg)
    eng, verify, info = st["engine"], st["verify"], st["info"]
    now = time.time()
    if eng.stage0 is not None and now - st["refreshed"] >= cfg["refresh_s"]:
        st["refreshed"] = now
        info["stage0_last_added"] = eng.stage0.refresh()   # never raises; reads only new rows
        info["stage0_hosts"] = len(eng.stage0)
        info["stage0_refreshes"] += 1
    c = collections.Counter()
    results, hits, hashes, hosts = [], [], [], []
    max_ms = 0.0
    for rec in records:
        t0 = time.perf_counter()
        try:
            v = verify(rec)
        except Exception as e:  # a broken station must never kill the pipeline
            v = {"status": "fail", "algo": f"error:{type(e).__name__}"}
        t1 = time.perf_counter()
        leaf = {"all_domains": rec["domains"], "issuer": rec["issuer"],
                "not_before": rec["not_before"], "not_after": rec["not_after"]}
        try:
            ds = eng.decide_cert(leaf, rec["seen_at"] or None)
        except Exception:
            ds = []
            c["engine_errors"] += 1
        gated = sum(1 for d in ds if d["stage"] >= 2)
        c["names"] += len(ds)
        c["gate_passes"] += gated
        for d in ds:
            host = d["host"]
            hosts.append(host)
            hv = int.from_bytes(hashlib.blake2b(host.encode(), digest_size=8).digest(), "big")
            if hv % NAME_SAMPLE == 0:
                hashes.append(hv)
            if d["verdict"] == "safe":
                if d["stage"] == -1:
                    c["allowlisted"] += 1
                continue
            c["stage0_hits" if d["verdict"] == "scam" else d["verdict"]] += 1
            ctx = {"cert_id": rec["id"], "crtsh_url": rec["crtsh_url"], "domains": rec["domains"], "seen_at": rec["seen_at"],
                   "issuer": rec["issuer"], "log": rec["log"], "verify": v.get("status", "fail"),
                   "other_gated": gated - (1 if d["stage"] >= 2 else 0)}
            if d["verdict"] == "scam" and eng.stage0 is not None:
                res, rule, listed = eng.stage0.explain(host)
                ctx["s0"] = {"feed": (res or {}).get("feed"), "rule": rule, "listed": listed}
            if d.get("s2_boost") and eng.stage2 is not None:
                try:
                    ctx["s2_reasons"] = list(eng.stage2.explain(host, leaf).get("reasons") or [])
                except Exception:
                    pass
            hits.append((d, ctx))
        t2 = time.perf_counter()
        max_ms = max(max_ms, 1000 * (t2 - t1))
        results.append((rec["id"], v.get("status", "fail"), None, t1 - t0, t2 - t1))
    info["rss_mb"] = rss_mb()
    return {"results": results, "hits": hits, "counts": dict(c), "hashes": hashes,
            "names": random.sample(hosts, min(RECENT_NAMES_PER_BATCH, len(hosts))),
            "max_engine_ms": max_ms, "info": dict(info)}


class UniqueNames:
    """Distinct names per clock hour from the 1/NAME_SAMPLE hash sample (see module docstring)."""

    def __init__(self, clock=time.time):
        self.clock = clock
        self.start = clock()
        self.hours = {}  # hour index -> set of sampled hashes

    def add(self, hashes):
        if not hashes:
            return
        h = int(self.clock() // 3600)
        self.hours.setdefault(h, set()).update(hashes)
        for old in [k for k in self.hours if k < h - 2]:
            del self.hours[old]

    def estimate(self):
        now = self.clock()
        h = int(now // 3600)
        if h - 1 in self.hours and self.start <= (h - 1) * 3600:   # a full hour was measured
            per_hour, basis = len(self.hours[h - 1]) * NAME_SAMPLE, "last full hour"
            measured_s = 3600.0
        else:
            measured_s = now - max(self.start, h * 3600)
            if measured_s < 60:
                return {"unique_names_per_day": None, "unique_names_per_hour": None,
                        "basis": "measuring (needs 60 s)", "sample": f"1/{NAME_SAMPLE}"}
            per_hour = len(self.hours.get(h, ())) * NAME_SAMPLE * 3600 / measured_s
            basis = f"current hour, scaled from {measured_s / 60:.0f} min"
        return {"unique_names_per_day": round(per_hour * 24), "unique_names_per_hour": round(per_hour),
                "basis": basis, "sample": f"1/{NAME_SAMPLE}"}


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
        self.win = collections.deque()  # (t, msgs, certs, names)
        self.verify_s = 0.0
        self.score_s = 0.0
        self.last_alert = None
        self.last_seen_at = None
        self.proc_lag_s = None      # receive -> results written, for the latest batch
        self.max_proc_lag_s = 0.0
        self.names_per_s = 0.0

    def snapshot(self, queue_depth):
        now = time.time()
        self.win.append((now, self.c["msgs"], self.c["certs"], self.c["names"]))
        while self.win and now - self.win[0][0] > 10:
            self.win.popleft()
        t0, m0, c0, n0 = self.win[0]
        dt = max(now - t0, 1e-9)
        n = max(self.c["processed"], 1)
        self.names_per_s = round((self.c["names"] - n0) / dt, 1) if len(self.win) > 1 else 0.0
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


def default_labels_db():
    """$LABELS_DB, else data/labels.db (on the VM data/ -> ~/tolltrap/data, the feeds loop's DB),
    else Stage 0's default ~/scamouflage-data/labels.db."""
    if os.environ.get("LABELS_DB"):
        return os.path.expanduser(os.environ["LABELS_DB"])
    local = os.path.join(REPO, "data", "labels.db")
    return local if os.path.exists(local) else os.path.expanduser("~/scamouflage-data/labels.db")


class EnginePath:
    """Main-process state of the engine path: Stage 3 queue, alert writer, dashboard counters."""

    def __init__(self, args, con, stats):
        from alerts.sign import sign
        from ingest.alerting import AlertWriter, Stage3Queue
        from model.engine import DEFAULT_MODEL_DIR, Engine, load_stage3, load_thresholds
        logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
        self.cfg = {"labels_db": os.path.expanduser(args.labels_db or default_labels_db()),
                    "model_dir": os.path.expanduser(args.models or DEFAULT_MODEL_DIR),
                    "refresh_s": args.stage0_refresh}
        self.stats = stats
        # finalize() uses no stage objects, so the main process doesn't load the model or the list
        self.finalizer = Engine(thresholds=load_thresholds(self.cfg["model_dir"]))
        self.verify = load_stage3()
        self.writer = AlertWriter(con, sign)
        self.s3 = Stage3Queue(self.finalizer, self.verify, self.writer.on_final,
                              concurrency=args.stage3_concurrency, timeout=args.stage3_timeout,
                              maxsize=args.stage3_queue)
        self.workers = {}  # pid -> latest engine info from that worker
        self.uniq = UniqueNames()
        self.recent_names = collections.deque(maxlen=30)
        self.max_engine_ms = 0.0
        rdap = ""
        if self.verify is not None:
            from model import stage3
            rdap = f", RDAP cache {stage3._DB_PATH}"
        print(f"[engine] labels_db={self.cfg['labels_db']} model_dir={self.cfg['model_dir']}", flush=True)
        print(f"[engine] stage3={'real' if self.verify else 'stub'} "
              f"(load_stage3() returned {'a function' if self.verify else 'None'}{rdap}); "
              f"concurrency {args.stage3_concurrency}, timeout {args.stage3_timeout} s, "
              f"queue cap {args.stage3_queue}", flush=True)
        print(f"[engine] dedupe: {self.writer.loaded_hosts} hosts alerted in the last 24 h loaded from "
              f"{args.db}", flush=True)

    def absorb(self, out):
        info = out["info"]
        self.workers[info["pid"]] = info
        self.recent_names.extend(out["names"])
        self.uniq.add(out["hashes"])
        self.max_engine_ms = max(self.max_engine_ms, out["max_engine_ms"])

    def status(self):
        w = list(self.workers.values())

        def worst(key):
            if not w:
                return "loading"
            return "real" if all(i[key] == "real" for i in w) else "stub"
        return {
            "mode": "on",
            "stage0": worst("stage0"), "stage1": worst("stage1"),
            "stage1_version": w[0]["stage1_version"] if w else None,
            "t_high": w[0]["t_high"] if w else self.finalizer.t_high,
            "t_low": w[0]["t_low"] if w else self.finalizer.t_low,
            "stage2": worst("stage2"), "stage3": "real" if self.verify else "stub",
            "stage0_hosts": max((i["stage0_hosts"] for i in w), default=0),
            "stage0_refreshes": sum(i["stage0_refreshes"] for i in w),
            "workers": {str(i["pid"]): {k: i.get(k) for k in ("rss_mb", "load_s", "stage0_hosts",
                                                                "stage0_refreshes", "stage0_last_added")}
                        for i in w},
        }

    def snapshot(self):
        st, c, wr = self.stats, self.stats.c, self.writer
        n = max(c["processed"], 1)
        est = self.uniq.estimate()
        last = wr.last
        return {
            "engine": self.status(),
            "alerts_total": wr.c["alerts"],
            "last_alert": {k: last[k] for k in ("domain", "score", "seen_at", "crtsh_url")} if last else None,
            "names_checked": c["names"],
            "names_per_s": st.names_per_s,
            "gate_passes": c["gate_passes"],
            "stage0_hits": c["stage0_hits"],
            "high": c["high"],
            "maybe": c["maybe"],
            "stage3": self.s3.snapshot(),
            "alerts_new": wr.c["alerts_new"],
            "alerts_known": wr.c["alerts_known"],
            "alerts_by_category": dict(wr.by_category),
            "alerts_deduped": wr.c["deduped"] + c["skipped_alerted"],
            "official_blocked": wr.c["official_blocked"],
            "allowlisted_names": c["allowlisted"],
            "engine_ms_per_cert": round(1000 * st.score_s / n, 3),
            "max_engine_ms_per_cert": round(self.max_engine_ms, 2),
            "proc_lag_s": None if st.proc_lag_s is None else round(st.proc_lag_s, 2),
            "max_proc_lag_s": round(st.max_proc_lag_s, 2),
            "unique_names_per_day": est["unique_names_per_day"],
            "unique_names_estimate": est,
            "recent_names": list(self.recent_names),
            "recent_alerts": list(reversed(wr.recent)),
            "stage3_examples": {k: list(v) for k, v in self.s3.examples.items()},
            "engine_errors": c["engine_errors"],
            "batch_errors": c["batch_errors"],
        }


# ---------------------------------------------------------------- main loop
async def run(args):
    con = connect(args.db)
    stats = Stats()
    dedupe = Dedupe()
    queue: asyncio.Queue = asyncio.Queue(maxsize=args.max_queue)
    eng = EnginePath(args, con, stats) if args.engine else None
    if eng:
        pool = (cf.ProcessPoolExecutor(args.workers, initializer=init_engine_worker, initargs=(eng.cfg,))
                if args.workers > 0 else None)
    else:
        pool = cf.ProcessPoolExecutor(args.workers) if args.workers > 0 else None
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    finished = asyncio.Event()
    signalled = []

    def on_signal():
        signalled.append(True)
        stop.set()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, on_signal)
        except NotImplementedError:
            pass

    if eng:  # load every engine before reading the stream, and say what's real
        if pool:
            infos = await asyncio.gather(*[loop.run_in_executor(pool, engine_ping, eng.cfg, 1.5)
                                           for _ in range(args.workers)])
        else:
            init_engine_worker(eng.cfg)
            infos = [engine_ping(eng.cfg)]
        for i in infos:
            eng.workers[i["pid"]] = i
        s = eng.status()
        print(f"[engine] ready: stage0={s['stage0']} stage1={s['stage1']} ({s['stage1_version']}) "
              f"t_high={s['t_high']} t_low={s['t_low']} stage2={s['stage2']} stage3={s['stage3']} "
              f"workers reporting {len(eng.workers)} of {max(args.workers, 1)}", flush=True)
        stubs = [k for k in ("stage0", "stage1", "stage2", "stage3") if s[k] != "real"]
        if stubs:
            print(f"[engine] WARNING: running WITHOUT {', '.join(stubs)} (stub); see the errors above",
                  flush=True)
        eng.s3.start()

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
                        if eng:
                            rec["_rx"] = time.time()
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

    def seen_rows_for(rec, cid, rows):
        for d in rec["domains"]:
            if brand_hit([d]) or sampled(d, args.sample_pct):
                rows.append((d, rec["seen_at"], cid))

    def write_results(results, recs_by_id):
        alerts_rows, seen_rows = [], []
        for cid, vstatus, alert, vt, st in results:
            stats.c["processed"] += 1
            stats.verify[vstatus] += 1
            stats.verify_s += vt
            stats.score_s += st
            rec = recs_by_id[cid]
            seen_rows_for(rec, cid, seen_rows)
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

    def write_results_engine(out, recs_by_id, rx0):
        seen_rows = []
        for cid, vstatus, _, vt, et in out["results"]:
            stats.c["processed"] += 1
            stats.verify[vstatus] += 1
            stats.verify_s += vt
            stats.score_s += et
            seen_rows_for(recs_by_id[cid], cid, seen_rows)
        stats.c.update(out["counts"])
        eng.absorb(out)
        for d, ctx in out["hits"]:
            if d["verdict"] == "scam":                    # Stage 0: final already
                eng.writer.write(d, ctx)
            elif d["verdict"] in ("high", "maybe"):
                if eng.writer.is_recent(d["host"]):
                    stats.c["skipped_alerted"] += 1
                else:
                    eng.s3.submit(d, ctx)
        if seen_rows:
            with con:
                con.executemany(
                    "INSERT OR IGNORE INTO seen(domain,first_cert_seen,cert_id) VALUES (?,?,?)",
                    seen_rows)
        stats.proc_lag_s = time.time() - rx0
        stats.max_proc_lag_s = max(stats.max_proc_lag_s, stats.proc_lag_s)

    def engine_done(fut, by_id, rx0):
        try:
            write_results_engine(fut.result(), by_id, rx0)
        except Exception as e:  # never lose the loop over one batch; say so loudly
            stats.c["batch_errors"] += 1
            print(f"[consumer] ERROR in engine batch: {e!r}", flush=True)
            import traceback
            traceback.print_exc()

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
                    if eng:
                        fut = loop.run_in_executor(pool, process_batch_engine, batch, eng.cfg)
                        fut.add_done_callback(lambda f, b=by_id, rx=batch[0]["_rx"]: engine_done(f, b, rx))
                    else:
                        fut = loop.run_in_executor(pool, process_batch, batch, args.threshold)
                        fut.add_done_callback(lambda f, b=by_id: write_results(f.result(), b))
                    inflight.add(fut)
                    fut.add_done_callback(inflight.discard)
                    # keep at most 2 batches per worker in flight
                    if len(inflight) >= 2 * args.workers:
                        await asyncio.wait(inflight, return_when=asyncio.FIRST_COMPLETED)
                else:
                    if eng:
                        f = loop.create_future()
                        try:
                            f.set_result(process_batch_engine(batch, eng.cfg))
                        except Exception as e:
                            f.set_exception(e)
                        engine_done(f, by_id, batch[0]["_rx"])
                    else:
                        write_results(process_batch(batch, args.threshold), by_id)
                    await asyncio.sleep(0)
        if inflight:
            await asyncio.wait(inflight)

    def snapshot():
        snap = stats.snapshot(queue.qsize())
        snap["dropped_total"] = stats.c["dropped"]
        if eng:
            snap.update(eng.snapshot())
        else:
            snap["engine"] = {"mode": "off"}
        return snap

    async def stats_writer():
        os.makedirs(os.path.dirname(args.stats) or ".", exist_ok=True)
        while not finished.is_set():
            snap = snapshot()
            write_json_atomic(args.stats, snap)
            if not args.quiet and int(snap["uptime_s"]) % 10 == 0:
                line = (f"[consumer] {snap['certs_per_s']:.0f} certs/s  processed={snap['processed_total']} "
                        f"alerts={snap['alerts_total']} queue={snap['queue_depth']} "
                        f"dropped={snap['dropped_total']}")
                if eng:
                    s3 = snap["stage3"]
                    line += (f"  names={snap['names_checked']} gate={snap['gate_passes']} "
                             f"s0={snap['stage0_hits']} high={snap['high']} maybe={snap['maybe']} "
                             f"new={snap['alerts_new']} known={snap['alerts_known']} "
                             f"s3q={s3['queue_depth']} s3={s3['lookups']} "
                             f"engine={snap['engine_ms_per_cert']}ms lag={snap['proc_lag_s']}s")
                print(line, flush=True)
            await asyncio.sleep(1)

    tasks = [asyncio.create_task(reader()), asyncio.create_task(worker()),
             asyncio.create_task(stats_writer())]
    await stop.wait()
    await asyncio.gather(tasks[1], return_exceptions=True)
    if eng:
        left = eng.s3.depth() + len(eng.s3.pending)
        if args.exit_on_close and not signalled:
            print(f"[consumer] stream ended; waiting for Stage 3 to finish {left} names", flush=True)
            await eng.s3.drain()
        elif left:
            print(f"[consumer] stopping; giving Stage 3 15 s for {left} names", flush=True)
            await eng.s3.drain(timeout=15)
        await eng.s3.stop()
        eng.s3.flush_with_none()
    finished.set()
    for t in tasks:
        t.cancel()
    snap = snapshot()
    write_json_atomic(args.stats, snap)
    if pool:
        pool.shutdown()
    con.close()
    print(f"[consumer] stopped. certs={stats.c['certs']} processed={stats.c['processed']} "
          f"alerts={snap['alerts_total']} dupes={stats.c['dupes']}", flush=True)
    if eng:
        print(f"[engine] totals: names={snap['names_checked']} gate={snap['gate_passes']} "
              f"stage0_hits={snap['stage0_hits']} high={snap['high']} maybe={snap['maybe']} "
              f"alerts new={snap['alerts_new']} known={snap['alerts_known']} "
              f"by_category={snap['alerts_by_category']} stage3={json.dumps(snap['stage3'])}", flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", default=os.environ.get("SCAM_STREAM", "ws://127.0.0.1:8080/full-stream"))
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--stats", default="data/stats.json")
    p.add_argument("--engine", action=argparse.BooleanOptionalAction, default=True,
                   help="detection engine (default). --no-engine = the old featurize/score path")
    p.add_argument("--labels-db", default=None, help="known-scam list for Stage 0 (default: $LABELS_DB, "
                   "else data/labels.db, else ~/scamouflage-data/labels.db)")
    p.add_argument("--models", default=None, help="Stage 1 model dir (default: $SCAM_MODELS, else data/models)")
    p.add_argument("--stage3-concurrency", type=int, default=2)
    p.add_argument("--stage3-timeout", type=float, default=10.0, help="seconds per Stage 3 answer")
    p.add_argument("--stage3-queue", type=int, default=2000, help="Stage 3 queue cap")
    p.add_argument("--stage0-refresh", type=float, default=900.0, help="seconds between Stage 0 refreshes")
    p.add_argument("--threshold", type=float, default=0.8, help="--no-engine only: score >= this alerts")
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


