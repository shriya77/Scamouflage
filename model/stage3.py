"""
Scamouflage — model/stage3.py  (owner: Shadow)

Stage 3: Domain Verifier via RDAP (MODEL_SPEC §2, §8, §13).
Queries rdap.org for domain registration date and registrar metadata.
Never makes HTTP requests to target scam sites, only rdap.org.

Interface:
    verify(host: str, timeout: float = 5.0) -> dict

Returns:
    {
        "ok": bool,
        "domain": str,               # eTLD+1 registered domain (e.g. "ezpass.com-xk2.win")
        "age_days": float | None,    # domain age in days (float)
        "registered_at": str | None, # ISO UTC timestamp (e.g. "2026-10-17T14:02:00Z")
        "registrar": str | None,     # registrar name
        "risky_registrar": bool,     # True if registrar matches labels/risky_registrars.txt
        "error": str | None          # None | "timeout" | "not_found" | "rate_limited" | "other"
    }

Registered domain: tldextract's BUNDLED Public Suffix List with private domains on (same as
Stage 0/2, no download). A name on shared hosting (x.github.io, x.pages.dev, x.weebly.com is
NOT private) has no registry record of its own: verify() returns error "shared_hosting" without
any request, so the engine falls back to "lookup failed" (HIGH -> scam, MAYBE -> safe).

Caching & Rate Limiting:
    - Cache in SQLite (data/rdap_cache.db, or $SCAM_RDAP_CACHE) + memory LRU. Only real answers
      are cached: found for 24 h, not_found for 6 h. Timeouts, 429s and other errors are NEVER
      cached, so a blip does not hide a domain for a day. age_days is recomputed from
      registered_at on every cache hit, so it never goes stale.
    - Rate limit: 1 request/second to rdap.org by default (spec max is 2/s; $SCAM_RDAP_INTERVAL),
      per process (Stage 3 runs in one worker)
    - On HTTP 429: wait (Retry-After, capped at 5 s, else 2 s) and retry once; if refused again,
      that TLD's registry is left alone for 60 s, doubling up to 15 min (see _tld_refused)
"""
import argparse
import collections
import datetime as dt
import logging
import os
import re
import sqlite3
import sys
import threading
import time
from urllib.parse import quote

import requests

log = logging.getLogger("scamouflage.stage3")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Registered domain from the BUNDLED PSL with private domains on (Stage 0's extractor: never
# downloads). features.registered_domain uses a tldextract that may fetch the live PSL.
try:
    from .stage0 import _EXTRACT as _PSL
except ImportError:  # pragma: no cover - run outside the package
    import tldextract
    _PSL = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                                 include_psl_private_domains=True)


def _extract_domain(host: str) -> tuple[str, bool]:
    """(registered domain, on shared hosting?). "" if the name is itself a public suffix.
    pay.ezpass.com-xk2.win -> ("com-xk2.win", False); evil.github.io -> ("evil.github.io", True)."""
    e = _PSL(host)
    if not e.suffix:  # ending not on the PSL: last two labels
        parts = host.split(".")
        return (".".join(parts[-2:]) if len(parts) >= 2 else ""), False
    if not e.domain:
        return "", False
    return f"{e.domain}.{e.suffix}", bool(getattr(e, "is_private", False))


# ---------------------------------------------------------------------------
# Risky registrars configuration (MODEL_SPEC §8, §13)
# ---------------------------------------------------------------------------
RISKY_REGISTRARS_FILE = os.path.join(ROOT, "labels", "risky_registrars.txt")
DEFAULT_RISKY = ["dominet", "namesilo", "gname"]


def load_risky_registrars(path: str = RISKY_REGISTRARS_FILE) -> list[str]:
    """Load lowercase risky registrar substrings from file, or fall back to defaults."""
    if not os.path.exists(path):
        return list(DEFAULT_RISKY)
    items = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip().lower()
                if line:
                    items.append(line)
        return items or list(DEFAULT_RISKY)
    except Exception as e:
        log.warning("could not read %s (%s); using defaults", path, e)
        return list(DEFAULT_RISKY)


_RISKY_LIST = load_risky_registrars()


def is_risky_registrar(name: str | None) -> bool:
    """Case-insensitive substring match against known high-risk registrars."""
    if not name:
        return False
    lower = str(name).lower()
    return any(r in lower for r in _RISKY_LIST)


# ---------------------------------------------------------------------------
# Rate limiting (max 2 requests/second)
# ---------------------------------------------------------------------------
class RateLimiter:
    """Enforces at least min_interval seconds between consecutive requests to rdap.org."""
    def __init__(self, min_interval: float = 1.0):
        self.min_interval = min_interval
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            delay = self._next - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self._next = time.monotonic() + self.min_interval



# 1 request/second: the spec allows at most 2/s, but at 2/s rdap.org answered 429 to a quarter
# of 150 lookups (VM, 2026-10-17).
_RATE_LIMITER = RateLimiter(min_interval=float(os.environ.get("SCAM_RDAP_INTERVAL", "1.0")))

# Per-TLD cool-down. rdap.org redirects to each registry's own RDAP server, and some refuse hard:
# the .top registry (rdap.zdnsgtld.com) answered 429 to single requests 3 s apart (VM,
# 2026-10-17). After a 429 that survives the retry, that TLD is skipped (error "rate_limited",
# no request) for 60 s, doubling up to 15 min; one success resets it. Other TLDs are unaffected.
TLD_COOLDOWN_START, TLD_COOLDOWN_MAX = 60.0, 900.0
_TLD_BLOCKED: dict[str, float] = {}   # tld -> monotonic time it may be asked again
_TLD_STRIKES: dict[str, int] = {}
_TLD_LOCK = threading.Lock()


def _tld_blocked(tld: str) -> bool:
    with _TLD_LOCK:
        return time.monotonic() < _TLD_BLOCKED.get(tld, 0.0)


def _tld_refused(tld: str) -> None:
    with _TLD_LOCK:
        n = _TLD_STRIKES.get(tld, 0)
        _TLD_STRIKES[tld] = n + 1
        _TLD_BLOCKED[tld] = time.monotonic() + min(TLD_COOLDOWN_MAX, TLD_COOLDOWN_START * 2 ** n)


def _tld_answered(tld: str) -> None:
    with _TLD_LOCK:
        _TLD_STRIKES.pop(tld, None)
        _TLD_BLOCKED.pop(tld, None)


# ---------------------------------------------------------------------------
# Cache: In-memory LRU + SQLite (24 hours TTL)
# ---------------------------------------------------------------------------
CACHE_TTL_SECONDS = 86400            # found: 24 hours
NOT_FOUND_TTL_SECONDS = 6 * 3600     # not_found: 6 hours (a just-registered domain can lag in RDAP)
CACHED_ERRORS = {None, "not_found"}  # everything else (timeout, rate_limited, other) is retried
DEFAULT_CACHE_DB = os.environ.get("SCAM_RDAP_CACHE") or os.path.join(ROOT, "data", "rdap_cache.db")
_MEM_CACHE: "collections.OrderedDict[str, dict]" = collections.OrderedDict()
_MEM_CACHE_MAX = 2000
_CACHE_LOCK = threading.Lock()


def _init_cache_db(db_path: str = DEFAULT_CACHE_DB) -> sqlite3.Connection | None:
    try:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rdap_cache (
                domain TEXT PRIMARY KEY,
                ok INTEGER NOT NULL,
                age_days REAL,
                registered_at TEXT,
                registrar TEXT,
                risky_registrar INTEGER NOT NULL,
                error TEXT,
                cached_at REAL NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rdap_cached_at ON rdap_cache(cached_at);")
        return conn
    except Exception as e:
        log.warning("failed to initialize rdap_cache db at %s: %s", db_path, e)
        return None


_DB_CONN = None
_DB_PATH = DEFAULT_CACHE_DB


def set_cache_path(path: str) -> None:
    """Use another cache file (tests use a temporary one) and forget everything cached so far."""
    global _DB_CONN, _DB_PATH
    with _CACHE_LOCK:
        if _DB_CONN is not None:
            try:
                _DB_CONN.close()
            except Exception:
                pass
        _DB_CONN, _DB_PATH = None, path
        _MEM_CACHE.clear()


def _get_db():
    global _DB_CONN
    if _DB_CONN is None:
        _DB_CONN = _init_cache_db(_DB_PATH)
    return _DB_CONN


def _ttl(entry: dict) -> float:
    return CACHE_TTL_SECONDS if entry.get("ok") else NOT_FOUND_TTL_SECONDS


def _fresh_age(entry: dict) -> dict:
    """Recompute age_days from registered_at, so a cached answer never goes stale."""
    out = dict(entry)
    out.pop("_cached_at", None)
    reg = _parse_iso_datetime(out.get("registered_at"))
    if out.get("ok") and reg is not None:
        out["age_days"] = round(max(0.0, (dt.datetime.now(dt.timezone.utc) - reg).total_seconds()
                                    / 86400.0), 4)
    return out


def _cache_get(domain: str) -> dict | None:
    now = time.time()
    with _CACHE_LOCK:
        if domain in _MEM_CACHE:
            entry = _MEM_CACHE[domain]
            if now - entry.get("_cached_at", 0) < _ttl(entry):
                _MEM_CACHE.move_to_end(domain)
                return _fresh_age(entry)
            else:
                del _MEM_CACHE[domain]

    conn = _get_db()
    if conn is None:
        return None
    try:
        with _CACHE_LOCK:
            row = conn.execute(
                "SELECT ok, age_days, registered_at, registrar, risky_registrar, error, cached_at "
                "FROM rdap_cache WHERE domain = ?", (domain,)
            ).fetchone()
        if row:
            ok, age_days, registered_at, registrar, risky_reg, error, cached_at = row
            if error in CACHED_ERRORS and now - cached_at < _ttl({"ok": bool(ok)}):
                entry = {
                    "ok": bool(ok),
                    "domain": domain,
                    "age_days": age_days,
                    "registered_at": registered_at,
                    "registrar": registrar,
                    "risky_registrar": bool(risky_reg),
                    "error": error,
                }
                with _CACHE_LOCK:
                    _MEM_CACHE[domain] = dict(entry, _cached_at=cached_at)
                    if len(_MEM_CACHE) > _MEM_CACHE_MAX:
                        _MEM_CACHE.popitem(last=False)
                return _fresh_age(entry)
    except Exception as e:
        log.warning("cache read error for %s: %s", domain, e)
    return None


def _cache_put(res: dict) -> None:
    if res.get("error") not in CACHED_ERRORS:  # never cache a timeout / 429 / server error
        return
    now = time.time()
    domain = res["domain"]
    with _CACHE_LOCK:
        _MEM_CACHE[domain] = dict(res, _cached_at=now)
        if len(_MEM_CACHE) > _MEM_CACHE_MAX:
            _MEM_CACHE.popitem(last=False)

    conn = _get_db()
    if conn is None:
        return
    try:
        with _CACHE_LOCK:
            conn.execute("""
                INSERT OR REPLACE INTO rdap_cache
                (domain, ok, age_days, registered_at, registrar, risky_registrar, error, cached_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                domain,
                1 if res["ok"] else 0,
                res.get("age_days"),
                res.get("registered_at"),
                res.get("registrar"),
                1 if res.get("risky_registrar") else 0,
                res.get("error"),
                now
            ))
            conn.commit()
    except Exception as e:
        log.warning("cache write error for %s: %s", domain, e)


# ---------------------------------------------------------------------------
# RDAP Response Parsers
# ---------------------------------------------------------------------------
def _parse_iso_datetime(date_str: str) -> dt.datetime | None:
    """Parse various ISO-8601 formats into UTC timezone-aware datetime."""
    if not date_str or not isinstance(date_str, str):
        return None
    cleaned = date_str.strip()
    # Normalize Z to +00:00
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(cleaned)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc)
    except Exception:
        pass
    # Fallback with regex for common date-time strings
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})[T\s](\d{2}):(\d{2}):(\d{2})", cleaned)
    if m:
        try:
            return dt.datetime(
                int(m.group(1)), int(m.group(2)), int(m.group(3)),
                int(m.group(4)), int(m.group(5)), int(m.group(6)),
                tzinfo=dt.timezone.utc
            )
        except Exception:
            pass
    return None


def _extract_registration_date(data: dict) -> tuple[float | None, str | None]:
    """Find registration event in RDAP JSON and calculate age in days."""
    now_utc = dt.datetime.now(dt.timezone.utc)
    events = data.get("events") or []
    # Check registration / creation actions
    target_actions = {"registration", "created", "registered"}
    chosen_date_str = None
    for ev in events:
        action = str(ev.get("eventAction", "")).lower()
        if action in target_actions:
            chosen_date_str = ev.get("eventDate")
            break

    if not chosen_date_str:
        return None, None

    dt_obj = _parse_iso_datetime(chosen_date_str)
    if dt_obj is None:
        return None, None

    age_days = max(0.0, (now_utc - dt_obj).total_seconds() / 86400.0)
    iso_utc = dt_obj.strftime("%Y-%m-%dT%H:%M:%SZ")
    return round(age_days, 4), iso_utc


def _extract_registrar(entities: list | None) -> str | None:
    """Find entity with role 'registrar' and extract its formatted name."""
    if not entities or not isinstance(entities, list):
        return None

    for ent in entities:
        if not isinstance(ent, dict):
            continue
        roles = [str(r).lower() for r in ent.get("roles") or []]
        if "registrar" in roles:
            # Check vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "..."]]]
            vcard = ent.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                        fn = str(item[3]).strip()
                        if fn:
                            return fn
            # Alternative entity fields (a bare numeric handle is an IANA id, not a name)
            name = ent.get("name") or ent.get("handle")
            if name and not str(name).strip().isdigit():
                return str(name).strip()

        # Search nested entities recursively
        nested = _extract_registrar(ent.get("entities"))
        if nested:
            return nested

    return None


def _retry_after(resp) -> float:
    """Seconds to wait before the one retry after a 429: Retry-After (capped at 5 s), else 2 s.
    Longer refusals are handled by the per-TLD cool-down, not by blocking this caller."""
    try:
        return min(5.0, max(0.0, float(resp.headers.get("Retry-After"))))
    except Exception:
        return 2.0


# ---------------------------------------------------------------------------
# Main Public Interface
# ---------------------------------------------------------------------------
def _empty(domain: str = "", error: str | None = None) -> dict:
    return {"ok": False, "domain": domain, "age_days": None, "registered_at": None,
            "registrar": None, "risky_registrar": False, "error": error}


def verify(host: str, timeout: float = 5.0) -> dict:
    """
    Look up domain registration age and registrar via RDAP (rdap.org).
    Never raises an exception. Follows MODEL_SPEC §8 and §13.
    """
    try:
        return _verify(host, timeout)
    except Exception as e:  # never let Stage 3 stop the stream
        log.warning("verify(%r) failed: %s", host, e)
        return _empty(error="other")


def _verify(host: str, timeout: float) -> dict:
    clean_h = str(host or "").strip().lower().rstrip(".") if isinstance(host, str) else ""
    while clean_h.startswith("*."):
        clean_h = clean_h[2:]
    reg_domain, shared = _extract_domain(clean_h) if clean_h else ("", False)
    if shared:
        # e.g. evil.github.io: the registry only knows github.io (years old), which says nothing
        # about this tenant. Don't spend the 2/s budget; the engine treats it as lookup failed.
        return _empty(reg_domain, "shared_hosting")

    result = {
        "ok": False,
        "domain": reg_domain,
        "age_days": None,
        "registered_at": None,
        "registrar": None,
        "risky_registrar": False,
        "error": None,
    }

    if not reg_domain or "." not in reg_domain:
        result["error"] = "not_found"
        return result

    # Check 24-hour cache
    cached = _cache_get(reg_domain)
    if cached is not None:
        return cached

    tld = reg_domain.rsplit(".", 1)[-1]
    if _tld_blocked(tld):  # this registry refused us just now: don't hammer it
        result["error"] = "rate_limited"
        return result

    # Query rdap.org
    url = f"https://rdap.org/domain/{quote(reg_domain)}"
    headers = {"User-Agent": "Scamouflage/1.0 (+https://github.com/shriya77/Scamouflage)"}

    for attempt in range(2):
        _RATE_LIMITER.wait()
        try:
            resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            if resp.status_code in (200, 404):
                _tld_answered(tld)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    result["error"] = "other"
                    break

                age_days, reg_at = _extract_registration_date(data)
                registrar = _extract_registrar(data.get("entities"))
                risky = is_risky_registrar(registrar)

                if age_days is not None:
                    result.update(
                        ok=True,
                        age_days=age_days,
                        registered_at=reg_at,
                        registrar=registrar,
                        risky_registrar=risky,
                        error=None,
                    )
                else:
                    # RDAP answered but registration date was absent
                    result.update(
                        ok=False,
                        registrar=registrar,
                        risky_registrar=risky,
                        error="not_found",
                    )
                break

            elif resp.status_code == 404:
                result["error"] = "not_found"
                break
            elif resp.status_code == 429:
                if attempt == 0:
                    time.sleep(_retry_after(resp))
                    continue
                _tld_refused(tld)
                result["error"] = "rate_limited"
                break
            else:
                result["error"] = "other"
                break

        except requests.Timeout:
            result["error"] = "timeout"
            break
        except requests.RequestException:
            result["error"] = "other"
            break
        except Exception as e:
            log.warning("unexpected error verifying %s: %s", reg_domain, e)
            result["error"] = "other"
            break

    # Cache response (both successes and recognized failures)
    _cache_put(result)
    return result


# ---------------------------------------------------------------------------
# Standalone CLI (MODEL_SPEC §13 step 8)
# ---------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description="Scamouflage Stage 3 RDAP Domain Verifier")
    p.add_argument("hosts", nargs="+", help="Domains/hostnames to verify")
    p.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout in seconds")
    args = p.parse_args()

    for host in args.hosts:
        res = verify(host, timeout=args.timeout)
        status = "OK" if res["ok"] else f"ERR:{res['error']}"
        age_str = f"{res['age_days']:.1f}d" if res['age_days'] is not None else "-"
        reg_str = f'"{res["registrar"]}"' if res["registrar"] else "-"
        risky_str = "RISKY" if res["risky_registrar"] else "normal"
        print(f"{host:<30} -> domain={res['domain']:<25} status={status:<15} "
              f"age={age_str:<10} date={str(res['registered_at']):<22} "
              f"reg={reg_str:<35} {risky_str}")


if __name__ == "__main__":
    main()
