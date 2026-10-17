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

Caching & Rate Limiting:
    - 24-hour cache in SQLite (data/rdap_cache.db) + memory LRU
    - Global rate limit: max 2 requests/second to rdap.org
    - Exponential backoff & single retry on HTTP 429
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

# Try importing registered_domain from features, fallback to basic logic
try:
    from .features import registered_domain as _extract_domain
except ImportError:
    try:
        from features import registered_domain as _extract_domain
    except ImportError:
        def _extract_domain(h: str) -> str:
            parts = str(h or "").strip().lower().rstrip(".").split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else (parts[0] if parts else "")


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
    """Enforces at least min_interval seconds between consecutive requests."""
    def __init__(self, min_interval: float = 0.5):
        self.min_interval = min_interval
        self._last_call = 0.0
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self._last_call = time.monotonic()


_RATE_LIMITER = RateLimiter(min_interval=0.5)


# ---------------------------------------------------------------------------
# Cache: In-memory LRU + SQLite (24 hours TTL)
# ---------------------------------------------------------------------------
CACHE_TTL_SECONDS = 86400  # 24 hours
DEFAULT_CACHE_DB = os.path.join(ROOT, "data", "rdap_cache.db")
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


def _get_db():
    global _DB_CONN
    if _DB_CONN is None:
        _DB_CONN = _init_cache_db()
    return _DB_CONN


def _cache_get(domain: str) -> dict | None:
    now = time.time()
    with _CACHE_LOCK:
        if domain in _MEM_CACHE:
            entry = _MEM_CACHE[domain]
            if now - entry.get("_cached_at", 0) < CACHE_TTL_SECONDS:
                _MEM_CACHE.move_to_end(domain)
                res = dict(entry)
                res.pop("_cached_at", None)
                return res
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
            if now - cached_at < CACHE_TTL_SECONDS:
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
                return entry
    except Exception as e:
        log.warning("cache read error for %s: %s", domain, e)
    return None


def _cache_put(res: dict) -> None:
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
            # Alternative entity fields
            name = ent.get("name") or ent.get("handle")
            if name:
                return str(name).strip()

        # Search nested entities recursively
        nested = _extract_registrar(ent.get("entities"))
        if nested:
            return nested

    return None


# ---------------------------------------------------------------------------
# Main Public Interface
# ---------------------------------------------------------------------------
def verify(host: str, timeout: float = 5.0) -> dict:
    """
    Look up domain registration age and registrar via RDAP (rdap.org).
    Never raises an exception. Follows MODEL_SPEC §8 and §13.
    """
    clean_h = str(host or "").strip().lower().rstrip(".")
    reg_domain = _extract_domain(clean_h) if clean_h else ""

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

    # Query rdap.org
    url = f"https://rdap.org/domain/{quote(reg_domain)}"
    headers = {"User-Agent": "Scamouflage/1.0 (+https://github.com/shriya77/Scamouflage)"}

    for attempt in range(2):
        _RATE_LIMITER.wait()
        try:
            resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
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
                    time.sleep(1.0)
                    continue
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
