"""Main-process side of the engine path (MODEL_SPEC §10): Stage 3 queue, final alert writing.

    writer = AlertWriter(con, sign)                    # 24 h per-host dedupe, signs LAST
    s3 = Stage3Queue(engine, verify, writer.on_final)  # verify = load_stage3() (may be None)
    s3.start()
    ... for each non-safe Decision from a worker:
        writer.write(d, ctx)          if d["verdict"] == "scam"   (Stage 0)
        s3.submit(d, ctx)             if engine.needs_verify(d)   (HIGH / MAYBE)

`ctx` is what the worker knew about the certificate (cert_id, domains, seen_at, issuer, log,
verify, other_gated, s2_reasons, s0). Reasons on an alert are built only from measured fields.
"""
import asyncio
import collections
import concurrent.futures as cf
import datetime as dt
import json
import logging
import time

from model import features as F

log = logging.getLogger("scamouflage.alerting")

DEDUPE_S = 24 * 3600
LEGACY_COLUMNS = ("cert_id", "domain", "domains", "score", "reasons", "seen_at",
                  "issuer", "log", "verify", "crtsh_url")
DECISION_COLUMNS = ("verdict", "stage", "s1", "s2_boost", "brand", "category", "verified",
                    "age_days", "registrar", "risky_registrar", "model_version",
                    "cert_seen_at", "decided_at")
ALERT_COLUMNS = LEGACY_COLUMNS + DECISION_COLUMNS + ("sig", "key_id")

# Display names for brand words that are a real organisation. Other gate words (toll, parcel,
# citation, ...) are lure words, not a brand, and are described as such.
BRAND_NAMES = {
    "ezpass": "E-ZPass", "e-zpass": "E-ZPass", "ezdrive": "EZDriveMA", "ntta": "NTTA",
    "tolltag": "NTTA TollTag", "txtag": "TxTag", "hctra": "HCTRA", "eztag": "EZ TAG",
    "sunpass": "SunPass", "fastrak": "FasTrak", "thetollroads": "The Toll Roads",
    "ipass": "Illinois Tollway I-PASS", "peachpass": "Peach Pass", "pikepass": "PikePass",
    "goodtogo": "Good To Go", "quickpass": "Quick Pass", "epass": "E-PASS", "usps": "USPS",
    "fedex": "FedEx", "dhl": "DHL", "irs": "the IRS", "dmv": "the DMV", "txdmv": "the Texas DMV",
    "txdot": "TxDOT",
}

S3_ERRORS = {
    "shared_hosting": "shared hosting, no registry record of its own",
    "timeout": "RDAP lookup timed out",
    "deadline": "no RDAP answer within 10 s",
    "rate_limited": "RDAP registry rate-limited us",
    "not_found": "no RDAP record",
    "other": "RDAP lookup failed",
    "queue_full": "verifier queue was full",
    "no_stage3": "verifier not installed",
    "shutdown": "consumer was shutting down",
}


def now_iso(t=None):
    t = time.time() if t is None else t
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fmt_age(days):
    if days is None:
        return None
    h = days * 24
    if h < 1:
        return "under 1 hour"
    if days < 2:
        n = round(h)
        return f"{n} hour{'s' if n != 1 else ''}"
    if days < 60:
        return f"{round(days)} days"
    if days < 730:
        return f"{round(days / 30.4)} months"
    return f"{days / 365.25:.0f} years"


def is_official(host):
    """The host, its registered domain or any parent is on labels/official.txt."""
    if F.is_official(host):
        return True
    parts = host.split(".")
    return any(".".join(parts[i:]) in F.OFFICIAL for i in range(1, len(parts) - 1))


def build_reasons(d, ctx):
    """Short evidence sentences, only from fields that were actually measured."""
    out = []
    host, brand = d["host"], d.get("brand")
    if d.get("stage") == 0:
        s0 = ctx.get("s0") or {}
        feed = f" ({s0['feed']})" if s0.get("feed") else ""
        if s0.get("rule") == "registered-domain" and s0.get("listed"):
            out.append(f"Its registered domain {s0['listed']} is already on a known scam list{feed}")
        else:
            out.append(f"Already on a known scam list{feed}")
        if brand:
            out.append(f"Listed as a {d.get('category') or 'other'} scam ({BRAND_NAMES.get(brand, brand)})")
        return out
    if brand:
        name = BRAND_NAMES.get(brand)
        if brand not in host:
            out.append(f'Name looks like a misspelling of "{brand}" ({d.get("category")})')
        elif name:
            out.append(f"Pretends to be {name}")
        else:
            out.append(f'Uses the {d.get("category")} lure word "{brand}"')
    elif d.get("category") == "other":
        out.append('Fake ".com-" / "gov-" pattern in the name')
    if d.get("s1") is not None:
        out.append(f"Name model score {d['s1']:.2f}")
    if d.get("s2_boost"):
        out.extend(ctx.get("s2_reasons") or [])
        out.append(f"Certificate check raised the score to {d['score']:.2f}")
    n = ctx.get("other_gated") or 0
    if n:
        out.append(f"Certificate also covers {n} other lookalike name{'s' if n != 1 else ''}")
    if d.get("verified"):
        age = fmt_age(d.get("age_days"))
        reg = d.get("registrar")
        line = f"Registered {age} ago" + (f" via {reg}" if reg else "")
        if d.get("risky_registrar"):
            line += " (Unit 42 high-risk registrar)"
        out.append(line)
        if d.get("s1") is not None and d["score"] < ctx.get("t_high", 1.0):
            out.append(f"Borderline score {d['score']:.2f} kept because the domain is new")
    else:
        why = S3_ERRORS.get(ctx.get("s3_error"), ctx.get("s3_error"))
        if why:
            out.append(f"Domain age not checked ({why}); alerted on the score")
    return out


def _f(x):
    return None if x is None else float(x)


def _i(x):
    return None if x is None else int(x)


def alert_row(d, ctx):
    """The alert exactly as it is stored and read back (so the signature checks after a DB round
    trip): REAL columns as float, INTEGER columns (booleans too) as int."""
    return {
        "cert_id": ctx["cert_id"],
        "domain": d["host"],
        "domains": list(ctx.get("domains") or []),
        "score": float(d["score"]),
        "reasons": build_reasons(d, ctx),
        "seen_at": float(ctx.get("seen_at") or 0.0),
        "issuer": ctx.get("issuer"),
        "log": ctx.get("log"),
        "verify": ctx.get("verify"),
        "crtsh_url": f"https://crt.sh/?q={ctx['cert_id']}",
        "verdict": d["verdict"],
        "stage": _i(d.get("stage")),
        "s1": _f(d.get("s1")),
        "s2_boost": _f(d.get("s2_boost")),
        "brand": d.get("brand"),
        "category": d.get("category") or "other",
        "verified": _i(bool(d.get("verified"))),
        "age_days": _f(d.get("age_days")),
        "registrar": d.get("registrar"),
        "risky_registrar": _i(d.get("risky_registrar")),
        "model_version": d.get("model_version"),
        "cert_seen_at": d.get("cert_seen_at") or (now_iso(ctx["seen_at"]) if ctx.get("seen_at") else None),
        "decided_at": d.get("decided_at"),
    }


class AlertWriter:
    """Final step: official-site guard, one alert per host per 24 h, sign LAST, insert."""

    def __init__(self, con, sign, dedupe_s=DEDUPE_S, recent_n=15, clock=time.time):
        self.con, self.sign, self.dedupe_s, self.clock = con, sign, dedupe_s, clock
        self.recent_hosts = {}  # host -> unix time of its last alert
        self.recent = collections.deque(maxlen=recent_n)
        self.c = collections.Counter()
        self.by_category = collections.Counter()
        self.last = None
        self._load()

    def _load(self):
        now = self.clock()
        cutoff = now - self.dedupe_s
        try:
            rows = self.con.execute(
                "SELECT domain, decided_at, seen_at FROM alerts WHERE decided_at >= ? OR seen_at >= ?",
                (now_iso(cutoff), cutoff)).fetchall()
        except Exception:
            log.exception("could not load recent alert hosts; dedupe starts empty")
            rows = []
        for host, decided, seen in rows:
            t = seen or 0.0
            if decided:
                try:
                    t = dt.datetime.strptime(decided, "%Y-%m-%dT%H:%M:%SZ").replace(
                        tzinfo=dt.timezone.utc).timestamp()
                except ValueError:
                    pass
            if t >= cutoff:
                self.recent_hosts[host] = max(t, self.recent_hosts.get(host, 0.0))
        try:
            for host, cat, score, stage, decided in reversed(self.con.execute(
                    "SELECT domain, category, score, stage, decided_at FROM alerts "
                    "WHERE stage IS NOT NULL ORDER BY id DESC LIMIT ?", (self.recent.maxlen,)).fetchall()):
                self.recent.append({"host": host, "category": cat, "score": score, "stage": stage,
                                    "decided_at": decided})
        except Exception:
            log.exception("could not load the latest alerts")
        self.loaded_hosts = len(self.recent_hosts)

    def is_recent(self, host):
        t = self.recent_hosts.get(host)
        if t is None:
            return False
        if self.clock() - t >= self.dedupe_s:
            del self.recent_hosts[host]
            return False
        return True

    def _prune(self):
        cutoff = self.clock() - self.dedupe_s
        for h in [h for h, t in self.recent_hosts.items() if t < cutoff]:
            del self.recent_hosts[h]

    def write(self, d, ctx):
        """Save a final `scam` Decision. Returns the stored alert, or None if skipped."""
        if d.get("verdict") != "scam":
            return None
        host = d["host"]
        if is_official(host):
            self.c["official_blocked"] += 1
            return None
        if self.is_recent(host):
            self.c["deduped"] += 1
            return None
        alert = alert_row(d, ctx)
        try:
            alert = self.sign(alert)
        except Exception as e:  # a broken key must not stop the pipeline
            alert["sig"], alert["key_id"] = "", f"error:{type(e).__name__}"
        vals = [json.dumps(alert[k]) if k in ("domains", "reasons") else alert.get(k)
                for k in ALERT_COLUMNS]
        with self.con:
            cur = self.con.execute(
                f"INSERT INTO alerts({','.join(ALERT_COLUMNS)}) VALUES ({','.join('?' * len(ALERT_COLUMNS))})",
                vals)
        alert["id"] = cur.lastrowid
        self.last = alert
        self.recent_hosts[host] = self.clock()
        if len(self.recent_hosts) > 200_000:
            self._prune()
        self.c["alerts"] += 1
        self.c["alerts_known" if alert["stage"] == 0 else "alerts_new"] += 1
        self.by_category[alert["category"]] += 1
        self.recent.append({k: alert[k] for k in ("score", "stage", "category", "decided_at")}
                           | {"host": host})
        return alert

    def on_final(self, d, ctx):
        return self.write(d, ctx)


class Stage3Queue:
    """HIGH / MAYBE names wait here for the verifier (RDAP, blocking, ~1 s), `concurrency` at a time.
    Every name is finalized exactly once: with the RDAP answer, or with None if there's no Stage 3,
    the queue is full, or there is no answer within `timeout` seconds (§3 fallback rules apply)."""

    OUTCOMES = ("confirmed", "kept_unverified", "removed", "rescued", "cleared", "dropped_unverified")

    def __init__(self, engine, verify, on_final, concurrency=2, timeout=10.0, maxsize=2000,
                 recheck_s=3600.0, t_high=None):
        self.engine, self.verify, self.on_final = engine, verify, on_final
        self.concurrency, self.timeout, self.maxsize, self.recheck_s = concurrency, timeout, maxsize, recheck_s
        self.t_high = t_high if t_high is not None else getattr(engine, "t_high", 1.0)
        self.q = None
        self.tasks = []
        self.executor = cf.ThreadPoolExecutor(max_workers=concurrency + 2, thread_name_prefix="stage3")
        self.pending = set()
        self.answered = {}  # host -> time of a finalize that had an RDAP answer
        self.c = collections.Counter()
        self.fail = collections.Counter()
        self.examples = collections.defaultdict(lambda: collections.deque(maxlen=5))
        self.calls = collections.deque()  # monotonic times of verify() calls (last 60 s)
        self.max_wait_s = 0.0
        self.max_depth = 0
        self.max_calls_10s = 0

    def start(self):
        self.q = asyncio.Queue(maxsize=self.maxsize)
        if self.verify is not None:
            self.tasks = [asyncio.create_task(self._worker()) for _ in range(self.concurrency)]

    def depth(self):
        return self.q.qsize() if self.q else 0

    def submit(self, d, ctx):
        host = d["host"]
        if host in self.pending:
            self.c["skipped_pending"] += 1
            return "pending"
        t = self.answered.get(host)
        if t is not None and time.monotonic() - t < self.recheck_s:
            self.c["skipped_recent"] += 1
            return "recent"
        self.c[f"queued_{d['verdict']}"] += 1
        if self.verify is None:
            self._finish(d, ctx, None, "no_stage3")
            return "finalized"
        if self.q.full():
            self.c["queue_full"] += 1
            self._finish(d, ctx, None, "queue_full")
            return "queue_full"
        self.pending.add(host)
        self.q.put_nowait((d, ctx, time.monotonic()))
        self.max_depth = max(self.max_depth, self.q.qsize())
        return "queued"

    async def _worker(self):
        loop = asyncio.get_running_loop()
        while True:
            d, ctx, t_enq = await self.q.get()
            done = False
            try:
                self.max_wait_s = max(self.max_wait_s, time.monotonic() - t_enq)
                now = time.monotonic()
                self.calls.append(now)
                while self.calls and now - self.calls[0] > 60:
                    self.calls.popleft()
                self.max_calls_10s = max(self.max_calls_10s, sum(1 for x in self.calls if now - x <= 10))
                self.c["lookups"] += 1
                res, why = None, None
                try:
                    res = await asyncio.wait_for(loop.run_in_executor(self.executor, self.verify, d["host"]),
                                                 self.timeout)
                except asyncio.TimeoutError:
                    why = "deadline"
                except Exception as e:
                    why = f"error:{type(e).__name__}"
                if why is None and not (isinstance(res, dict) and res.get("ok")):
                    why = (res.get("error") if isinstance(res, dict) else None) or "other"
                done = True
                self._finish(d, ctx, res if why is None else None, why)
            except asyncio.CancelledError:
                if not done:
                    self._finish(d, ctx, None, "shutdown")
                raise
            except Exception:
                log.exception("Stage 3 worker failed on %s", d.get("host"))
            finally:
                self.pending.discard(d["host"])
                self.q.task_done()

    def _finish(self, d, ctx, res, why):
        final = self.engine.finalize(d, res)
        before, after, answered = d["verdict"], final["verdict"], res is not None
        if before == "high":
            outcome = ("confirmed" if answered else "kept_unverified") if after == "scam" else "removed"
        else:
            outcome = "rescued" if after == "scam" else ("cleared" if answered else "dropped_unverified")
        self.c[outcome] += 1
        if why:
            self.fail[why] += 1
        if answered:
            self.answered[d["host"]] = time.monotonic()
            if len(self.answered) > 50_000:
                cut = time.monotonic() - self.recheck_s
                self.answered = {h: t for h, t in self.answered.items() if t >= cut}
        self.examples[outcome].append({
            "host": d["host"], "score": d["score"], "age_days": final.get("age_days"),
            "registrar": final.get("registrar"), "error": why})
        log.info("stage3 %s: %s (%s, score %.3f) age_days=%s registrar=%s error=%s", outcome, d["host"],
                 before, d["score"], final.get("age_days"), final.get("registrar"), why)
        ctx = dict(ctx, s3_error=why, t_high=self.t_high)
        try:
            self.on_final(final, ctx)
        except Exception:
            log.exception("writing the alert for %s failed", d.get("host"))
        return final

    async def drain(self, timeout=None):
        """Wait until every queued name is finalized (replays: --exit-on-close)."""
        if self.q is None or not self.tasks:
            return True
        try:
            await asyncio.wait_for(self.q.join(), timeout)
            return True
        except asyncio.TimeoutError:
            return False

    def flush_with_none(self):
        """On shutdown: finalize whatever is still queued without an answer (§3 fallback)."""
        while self.q is not None and not self.q.empty():
            d, ctx, _ = self.q.get_nowait()
            self._finish(d, ctx, None, "shutdown")
            self.pending.discard(d["host"])
            self.q.task_done()

    async def stop(self):
        for t in self.tasks:
            t.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        self.executor.shutdown(wait=False, cancel_futures=True)

    def snapshot(self):
        now = time.monotonic()
        recent = sum(1 for x in self.calls if now - x <= 10)
        return {
            "confirmed": self.c["confirmed"],
            "kept_unverified": self.c["kept_unverified"],
            "removed": self.c["removed"],
            "rescued": self.c["rescued"],
            "cleared": self.c["cleared"],
            "dropped_unverified": self.c["dropped_unverified"],
            "failed": sum(self.fail.values()),
            "failed_by_reason": dict(self.fail),
            "queue_depth": self.depth(),
            "max_queue_depth": self.max_depth,
            "queue_full": self.c["queue_full"],
            "lookups": self.c["lookups"],
            "lookups_per_s": round(recent / 10, 2),
            "max_lookups_per_s_10s": round(self.max_calls_10s / 10, 2),
            "max_wait_s": round(self.max_wait_s, 1),
            "queued_high": self.c["queued_high"],
            "queued_maybe": self.c["queued_maybe"],
            "skipped_pending": self.c["skipped_pending"],
            "skipped_recent": self.c["skipped_recent"],
            "available": self.verify is not None,
        }
