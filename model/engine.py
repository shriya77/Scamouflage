"""
Scamouflage — model/engine.py  (owner: Vaishnavi; called from ingest/consumer.py by Shriya)

The decider. Runs the stages in the exact order of MODEL_SPEC §3 and returns one Decision per name.

    from model.engine import Engine, load_stage3
    engine = Engine.from_disk(labels_db="~/tolltrap/data/labels.db")
    verify = load_stage3()                      # None if Stage 3 isn't installed

    for d in engine.decide_cert(leaf_cert, seen_at=msg["data"]["seen"]):
        if d["verdict"] == "scam":              # Stage 0 hit -> final already
            save(d)
        elif engine.needs_verify(d):            # "high" or "maybe" -> Stage 3 queue
            queue.put(d)
    # Stage 3 worker:
    d = engine.finalize(d, verify(d["host"]) if verify else None)
    if d["verdict"] == "scam":
        save(d)                                 # sign AFTER this, when every field is final

Stage order per name:
  allowlist -> Stage 0 known list -> brand gate -> Stage 1 name score -> Stage 2 boost
  -> sort (high / maybe / safe) -> [Stage 3 worker] -> finalize (scam / safe)

The brand gate runs BEFORE Stage 1: names that fail the gate are SAFE whatever Stage 1 says, so
skipping Stage 1 for them gives the same result and saves ~99.9% of the model work.

Every stage after the gate is optional: if it is missing, raises or returns junk, the engine
carries on (MODEL_SPEC §2 rule 7). Stage 2 can only raise a score (rule 8).
"""
import datetime as dt
import json
import logging
import os

from . import features as F

log = logging.getLogger("scamouflage.engine")

ROOT = F.ROOT
DEFAULT_MODEL_DIR = os.path.join(ROOT, "models")
DEFAULT_THRESHOLDS = {"t_high": 0.90, "t_low": 0.50}   # placeholders until train_stage1.py writes thresholds.json

MAX_BOOST = 0.6          # Stage 2 cap
OLD_DOMAIN_DAYS = 365    # HIGH + older than this -> false alarm removed ...
VERY_HIGH_SCORE = 0.99   # ... unless the score is at least this
NEW_DOMAIN_DAYS = 7      # MAYBE + younger than this -> scam
NEW_RISKY_DAYS = 30      # MAYBE + younger than this + risky registrar -> scam

# `stage` field = the last stage that decided this name
STAGE_ALLOWLIST, STAGE_KNOWN, STAGE_GATE, STAGE_SCORED, STAGE_VERIFIED = -1, 0, 1, 2, 3

DECISION_FIELDS = ["host", "domain", "verdict", "stage", "score", "s1", "s2_boost", "brand", "category",
                   "verified", "age_days", "registrar", "risky_registrar", "model_version",
                   "cert_seen_at", "decided_at"]


def _now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _iso(ts):
    """certstream gives `seen` as epoch seconds (float). Accept that, an ISO string, or None."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return dt.datetime.fromtimestamp(ts, dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return str(ts)


def _clamp(x, lo, hi):
    try:
        x = float(x)
    except (TypeError, ValueError):
        return lo
    if x != x:  # NaN
        return lo
    return max(lo, min(hi, x))


def load_thresholds(model_dir=DEFAULT_MODEL_DIR):
    th = dict(DEFAULT_THRESHOLDS)
    path = os.path.join(model_dir, "thresholds.json")
    if os.path.exists(path):
        with open(path) as f:
            th.update(json.load(f))
    else:
        log.warning("no %s yet; using placeholder thresholds %s", path, DEFAULT_THRESHOLDS)
    return th


def load_stage3():
    """Shadow's verify(host) function, or None if model/stage3.py isn't there or fails to import."""
    try:
        from .stage3 import verify
        return verify
    except Exception as e:  # missing file, missing dependency, syntax error...
        log.warning("Stage 3 not available (%s: %s); HIGH -> scam, MAYBE -> safe", type(e).__name__, e)
        return None


class Engine:
    def __init__(self, stage0=None, stage1=None, stage2=None, thresholds=None, model_version=None):
        self.stage0 = stage0
        self.stage1 = stage1
        self.stage2 = stage2
        th = dict(DEFAULT_THRESHOLDS)
        th.update(thresholds or {})
        self.t_high = float(th["t_high"])
        self.t_low = float(th["t_low"])
        assert 0.0 < self.t_low <= self.t_high <= 1.0, f"bad thresholds {th}"
        self.model_version = model_version or th.get("model_version") or getattr(stage1, "version", "none")
        self._warned = set()

    @classmethod
    def from_disk(cls, labels_db=None, model_dir=DEFAULT_MODEL_DIR):
        """Load the real stages. Any stage that fails to load is left out (engine still works)."""
        labels_db = os.path.expanduser(labels_db or os.environ.get("SCAM_DB", ""))

        def load(what, make):
            try:
                return make()
            except Exception as e:
                log.error("%s failed to load (%s: %s); running without it", what, type(e).__name__, e)
                return None

        from . import stage0, stage1, stage2
        s0 = load("Stage 0", lambda: stage0.KnownList(labels_db))
        s1 = load("Stage 1", lambda: stage1.Stage1(model_dir))
        s2 = load("Stage 2", lambda: stage2.Stage2(model_dir))
        return cls(s0, s1, s2, load_thresholds(model_dir))

    # ------------------------------------------------------------------ helpers
    def _warn_once(self, key, msg, *args):
        if key not in self._warned:
            self._warned.add(key)
            log.exception(msg, *args)

    def _known(self, host):
        if self.stage0 is None:
            return None
        try:
            return self.stage0.check(host)
        except Exception:
            self._warn_once("s0", "Stage 0 check failed; skipping Stage 0")
            return None

    def _scores(self, hosts):
        if not hosts:
            return []
        if self.stage1 is None:
            return [0.0] * len(hosts)
        try:
            out = list(self.stage1.score_many(hosts))
            if len(out) != len(hosts):
                raise ValueError(f"score_many returned {len(out)} scores for {len(hosts)} names")
            return [_clamp(s, 0.0, 1.0) for s in out]
        except Exception:
            self._warn_once("s1", "Stage 1 failed; scoring 0.0 (safe)")
            return [0.0] * len(hosts)

    def _boost(self, host, leaf_cert):
        if self.stage2 is None:
            return 0.0
        try:
            return _clamp(self.stage2.boost(host, leaf_cert), 0.0, MAX_BOOST)   # never lowers a score
        except Exception:
            self._warn_once("s2", "Stage 2 failed; boost 0.0")
            return 0.0

    def _base(self, host, cert_seen_at):
        d = dict.fromkeys(DECISION_FIELDS)
        d.update(host=host, domain=F.registered_domain(host), verdict="safe", stage=STAGE_GATE,
                 score=0.0, s1=None, s2_boost=None, verified=False, risky_registrar=None,
                 model_version=self.model_version, cert_seen_at=cert_seen_at, decided_at=_now())
        return d

    # ------------------------------------------------------------------ public API
    def decide_cert(self, leaf_cert, seen_at=None):
        """One Decision per unique clean name on the certificate. Inline stages only (0, gate, 1, 2).
        verdict: "safe" | "scam" (Stage 0 hit) | "high" | "maybe"  — high/maybe go to Stage 3."""
        leaf_cert = leaf_cert or {}
        seen = _iso(seen_at)
        hosts = []
        for raw in leaf_cert.get("all_domains") or []:
            h = F.clean_host(raw)
            if h and h not in hosts:
                hosts.append(h)

        decisions, gated = [], []
        for h in hosts:
            d = self._base(h, seen)
            decisions.append(d)
            if F.is_official(h):
                d["stage"] = STAGE_ALLOWLIST
                continue
            known = self._known(h)
            if known:
                d.update(verdict="scam", stage=STAGE_KNOWN, score=1.0,
                         brand=known.get("brand"), category=known.get("category") or "other")
                continue
            passes, brand, category = F.brand_gate(h)
            if not passes:
                continue                                   # SAFE at the gate
            d.update(brand=brand, category=category)
            gated.append(d)

        for d, s1 in zip(gated, self._scores([d["host"] for d in gated])):
            b = self._boost(d["host"], leaf_cert)
            final = 1.0 - (1.0 - s1) * (1.0 - b)
            verdict = "high" if final >= self.t_high else "maybe" if final >= self.t_low else "safe"
            d.update(s1=round(s1, 4), s2_boost=round(b, 4), score=round(final, 4),
                     verdict=verdict, stage=STAGE_SCORED)
        return decisions

    def decide_host(self, host):
        """Convenience for tests / a 'check a site' box: one name, no certificate."""
        out = self.decide_cert({"all_domains": [host]})
        return out[0] if out else None

    @staticmethod
    def needs_verify(decision):
        return decision.get("verdict") in ("high", "maybe")

    def finalize(self, decision, verify_result=None):
        """Apply Stage 3 (MODEL_SPEC §3). verify_result = stage3.verify(...) output, or None if Stage 3
        is missing / timed out. Returns a NEW dict with verdict "scam" or "safe"."""
        d = dict(decision)
        if d.get("verdict") not in ("high", "maybe"):
            return d
        v = verify_result if isinstance(verify_result, dict) and verify_result.get("ok") else None
        age = None
        if v:
            age = v.get("age_days")
            age = None if age is None else _clamp(age, 0.0, 1e6)
            d.update(verified=True, age_days=age, registrar=v.get("registrar"),
                     risky_registrar=bool(v.get("risky_registrar")), stage=STAGE_VERIFIED)
        risky = bool(d.get("risky_registrar"))

        if d["verdict"] == "high":
            old = age is not None and age > OLD_DOMAIN_DAYS and d["score"] < VERY_HIGH_SCORE
            d["verdict"] = "safe" if old else "scam"        # no answer -> trust the score
        else:  # maybe
            young = age is not None and (age <= NEW_DOMAIN_DAYS or (age <= NEW_RISKY_DAYS and risky))
            d["verdict"] = "scam" if young else "safe"      # no answer -> precision first
        d["decided_at"] = _now()
        return d
