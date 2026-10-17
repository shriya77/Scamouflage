"""GET /api/blocklist: the signed list of flagged domains for the Scamouflage
browser extension.

The extension downloads this list and checks every site *inside the browser*.
This endpoint never receives the sites a user visits; it only hands out the
same list to everyone.

Response (the "envelope"):
    {
      "payload":   "<JSON string with version, generated_at, threshold, entries, allowlist>",
      "signature": "<base64 Ed25519 signature over the UTF-8 bytes of payload>",
      "key_id":    "scamouflage-vm-1"
    }

We sign the payload *string* (not a re-serialized object), so the extension can
verify the exact bytes it received before it even parses them.

GET /api/pubkey returns the matching PUBLIC key (and key_id) as JSON, so anyone
can check the list without reading extension/config.js.

Mount both in an existing aiohttp app:
    from backend.blocklist_route import setup_blocklist_route
    setup_blocklist_route(app)

Or run it on its own for testing (localhost only):
    python -m backend.blocklist_route --port 8000

The private key is keys/blocklist_ed25519.pem (made on the VM by
`python -m backend.make_keys`); set TOLLTRAP_SIGNING_KEY to use another file.
"""
from __future__ import annotations  # lets us write "str | None" on Python 3.9

# ---------------------------------------------------------------------------
# ASSUMED DATABASE LAYOUT. Edit these names if your `alerts` table differs.
# They match the schema in ingest/db.py.
# ---------------------------------------------------------------------------
ALERTS_TABLE = "alerts"
COL_DOMAIN = "domain"    # TEXT  the hostname that triggered the alert
COL_SCORE = "score"      # REAL  model score, 0..1
COL_REASONS = "reasons"  # TEXT  JSON list of reason strings, e.g. ["brand-impersonation"]
COL_SEEN_AT = "seen_at"  # REAL  unix seconds when we first saw the certificate in CT

import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import os
import re
import sqlite3
import stat
import time
from datetime import datetime, timezone

import tldextract
from aiohttp import web
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    import idna  # IDNA2008/UTS46, the same rules Chrome uses (installed with aiohttp)
except ImportError:  # pragma: no cover
    idna = None

log = logging.getLogger("tolltrap.blocklist")

# ---------------------------------------------------------------------------
# Settings (all optional environment variables)
# ---------------------------------------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

# Same lookup as api/server.py: SCAM_DB, else DATA_DIR/scamouflage.db, else the
# repo's data/ folder. Resolved from the repo, not the current directory, so
# the API and this route always read the same database.
DATA_DIR = os.environ.get("DATA_DIR") or (
    os.path.dirname(os.environ["SCAM_DB"]) if os.environ.get("SCAM_DB") else os.path.join(REPO, "data"))
DB_PATH = os.environ.get("SCAM_DB") or os.path.join(DATA_DIR, "scamouflage.db")
# Training stats written by model/train_stage1.py; shown in the extension popup.
THRESHOLDS_FILES = [os.path.join(DATA_DIR, "models", "thresholds.json"),
                    os.path.join(REPO, "reports", "thresholds.json")]
THRESHOLD = float(os.environ.get("TOLLTRAP_BLOCKLIST_THRESHOLD", "0.85"))
KEY_ID = os.environ.get("TOLLTRAP_KEY_ID", "scamouflage-vm-1")
SIGNING_KEY_PATH = os.environ.get("TOLLTRAP_SIGNING_KEY") or os.path.join(
    REPO, "keys", "blocklist_ed25519.pem")
# "live" for the real CT stream, "replay" when serving a recorded replay DB.
LIST_SOURCE = os.environ.get("TOLLTRAP_LIST_SOURCE") or (
    "replay" if "replay" in os.path.basename(DB_PATH) else "live")
# Rebuilding + signing the list on every request is wasteful; reuse it briefly.
CACHE_SECONDS = float(os.environ.get("TOLLTRAP_BLOCKLIST_CACHE_S", "60"))

OFFICIAL_FILES = [os.path.join(HERE, "official_domains.txt"),
                  os.path.join(REPO, "labels", "official.txt")]
NO_WILDCARD_FILE = os.path.join(HERE, "no_wildcard_domains.txt")

# Two extractors over the Public Suffix List snapshot bundled with tldextract
# (suffix_list_urls=() means "never download", so this works on an offline VM).
#   _ICANN   knows only real TLDs:          evil.github.io -> registrable "github.io"
#   _PRIVATE also knows hosting platforms:  evil.github.io -> registrable "evil.github.io"
# If they disagree about the suffix, the hostname lives on a shared platform.
_ICANN = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                               include_psl_private_domains=False)
_PRIVATE = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                                 include_psl_private_domains=True)

_HOSTNAME_RE = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)+$")


# ---------------------------------------------------------------------------
# Step 1: normalize and hash hostnames (must match matcher.js exactly)
# ---------------------------------------------------------------------------
def normalize_hostname(name: str) -> str | None:
    """Lowercase ASCII hostname: punycode for international names, no trailing
    dot, no port, no "*." wildcard prefix. "www." is NOT stripped.
    Returns None for things that aren't a usable dotted hostname."""
    if not isinstance(name, str):
        return None
    h = name.strip().lower()
    if h.startswith("*."):
        h = h[2:]
    # Drop a port like "example.com:8080" (CT domains never have one, but be safe).
    if h.count(":") == 1:
        h = h.split(":", 1)[0]
    h = h.rstrip(".")
    if not h:
        return None
    if not h.isascii():
        try:
            if idna is not None:
                h = idna.encode(h, uts46=True, transitional=False).decode("ascii")
            else:
                h = h.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):  # idna.IDNAError is a UnicodeError
            return None
        h = h.lower()
    if not _HOSTNAME_RE.match(h):
        return None
    return h


def sha256_hex(hostname: str) -> str:
    """SHA-256 of the normalized hostname's UTF-8 bytes, lowercase hex."""
    return hashlib.sha256(hostname.encode("utf-8")).hexdigest()


def candidates(hostname: str) -> list[str]:
    """The hostname plus each parent down to two labels (same as matcher.js).
    a.b.com-xk2.win -> [a.b.com-xk2.win, b.com-xk2.win, com-xk2.win]"""
    labels = hostname.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Step 2: turn one flagged hostname into blocklist entries
# ---------------------------------------------------------------------------
def make_entry(hostname: str, match_subdomains: bool, score: float,
               reasons: list[str], observed_at: str | None, source: str) -> dict:
    return {
        "h": sha256_hex(hostname),
        "match_subdomains": bool(match_subdomains),
        "score": round(float(score), 4),
        "reasons": list(reasons),
        "observed_at": observed_at,
        "source": source,
    }


def targets_for(hostname: str, no_wildcard: set[str]) -> list[tuple[str, bool]]:
    """Which names to emit for one flagged hostname, as (name, match_subdomains).

    ezpass.com-xk2.win -> [("ezpass.com-xk2.win", False), ("com-xk2.win", True)]
    """
    if _is_ip(hostname):
        return [(hostname, False)]

    icann = _ICANN(hostname)
    if not icann.suffix:
        # Unknown TLD (e.g. ".internal"): we can't compute a registrable domain.
        return [(hostname, False)]
    if not icann.domain:
        # The hostname IS a public suffix ("win", "co.uk"): never emit it.
        return []

    private = _PRIVATE(hostname)
    if private.suffix != icann.suffix:
        # Shared hosting platform from the PSL private section (github.io,
        # pages.dev, blogspot.com, ...).
        if not private.domain:
            return []  # the platform itself, e.g. "github.io": never flag it
        tenant = f"{private.domain}.{private.suffix}"  # e.g. evil.github.io
        # Never match_subdomains here: only this exact tenant site is flagged.
        return [(hostname, False), (tenant, False)]

    registrable = f"{icann.domain}.{icann.suffix}"
    wildcard = registrable not in no_wildcard
    return [(hostname, False), (registrable, wildcard)]


def _merge(entries: dict, new: dict) -> None:
    """De-duplicate by hash: keep the highest score (with its reasons), keep the
    earliest observed_at, and keep match_subdomains if either entry had it."""
    old = entries.get(new["h"])
    if old is None:
        entries[new["h"]] = new
        return
    best = dict(new if new["score"] > old["score"] else old)
    best["match_subdomains"] = old["match_subdomains"] or new["match_subdomains"]
    times = [t for t in (old["observed_at"], new["observed_at"]) if t]
    best["observed_at"] = min(times) if times else None
    entries[new["h"]] = best


def _parse_reasons(raw) -> list[str]:
    """The DB stores reasons as a JSON list; tolerate a plain string too."""
    if raw is None or raw == "":
        return []
    try:
        val = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        val = [raw]
    if isinstance(val, str):
        val = [val]
    if not isinstance(val, list):
        return []
    return [str(r)[:200] for r in val if r is not None][:10]


def iso_utc(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_domain_file(path: str) -> set[str]:
    out = set()
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            name = normalize_hostname(line.split("#", 1)[0])
            if name:
                out.add(name)
    return out


def official_domains() -> set[str]:
    out = set()
    for path in OFFICIAL_FILES:
        out |= read_domain_file(path)
    return out


def model_info() -> dict | None:
    """Model version and training-set size from thresholds.json, or None if
    the model hasn't been trained yet. Only these four fields are published."""
    for path in THRESHOLDS_FILES:
        try:
            with open(path, encoding="utf-8") as f:
                th = json.load(f)
        except (OSError, ValueError):
            continue
        return {
            "version": th.get("model_version"),
            "trained_at": th.get("trained_at"),
            "n_train": th.get("n_train"),
            "n_val": th.get("n_val"),
        }
    return None


def build_payload(rows, allow_domains: set[str], no_wildcard: set[str],
                  threshold: float = THRESHOLD, source: str = LIST_SOURCE,
                  now: float | None = None, model: dict | None = None) -> dict:
    """Pure function: alert rows -> payload dict (ready to be signed).

    rows: iterable of (domain, score, reasons_json, seen_at).
    """
    allow_hashes = {sha256_hex(d) for d in allow_domains}
    entries: dict[str, dict] = {}
    flagged_hostnames: set[str] = set()
    for domain, score, reasons_raw, seen_at in rows:
        if score is None or float(score) < threshold:
            continue
        hostname = normalize_hostname(domain)
        if not hostname:
            continue
        # Never flag an official site or anything under one.
        if any(sha256_hex(c) in allow_hashes for c in candidates(hostname)):
            continue
        reasons = _parse_reasons(reasons_raw)
        observed = iso_utc(seen_at)
        targets = targets_for(hostname, no_wildcard)
        if targets:
            flagged_hostnames.add(hostname)
        for name, wildcard in targets:
            _merge(entries, make_entry(name, wildcard, score, reasons, observed, source))

    return {
        "version": 1,
        "generated_at": iso_utc(time.time() if now is None else now),
        "threshold": threshold,
        # Sorted by hash so the order reveals nothing about when domains were added.
        "entries": [entries[h] for h in sorted(entries)],
        "allowlist": sorted(allow_hashes),
        # Shown in the popup: "Compared against N flagged sites", "trained on N".
        "flagged_hostnames": len(flagged_hostnames),
        "model": model,
    }


# ---------------------------------------------------------------------------
# Step 3: sign the payload string
# ---------------------------------------------------------------------------
class SigningKeyError(RuntimeError):
    pass


def load_private_key(path: str | None) -> Ed25519PrivateKey:
    """Load the Ed25519 private key (PEM, PKCS#8). Never logs the key itself."""
    if not path:
        raise SigningKeyError("TOLLTRAP_SIGNING_KEY is not set")
    if not os.path.exists(path):
        raise SigningKeyError(f"no signing key file at {path} (run: python -m backend.make_keys)")
    mode = os.stat(path).st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        log.warning("signing key %s is readable by other users; run: chmod 600 %s", path, path)
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningKeyError(f"{path} is not an Ed25519 private key")
    return key


def payload_to_string(payload: dict) -> str:
    """Compact, ASCII-only JSON. ensure_ascii means the UTF-8 bytes are
    identical in every language, so there's nothing to get wrong."""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def sign_payload(payload: dict, private_key: Ed25519PrivateKey, key_id: str) -> dict:
    payload_str = payload_to_string(payload)
    signature = private_key.sign(payload_str.encode("utf-8"))  # sign the exact bytes
    return {
        "payload": payload_str,
        "signature": base64.b64encode(signature).decode("ascii"),
        "key_id": key_id,
    }


# ---------------------------------------------------------------------------
# Step 4: the aiohttp handler
# ---------------------------------------------------------------------------
_private_key: Ed25519PrivateKey | None = None
_cache = {"body": None, "expires": 0.0}
_cache_lock: asyncio.Lock | None = None


def _get_key() -> Ed25519PrivateKey:
    """Load the key once and keep it in memory. A failure isn't cached, so
    fixing the env var / file and retrying works without a restart."""
    global _private_key
    if _private_key is None:
        _private_key = load_private_key(SIGNING_KEY_PATH)
    return _private_key


def _read_alert_rows(db_path: str) -> list[tuple]:
    try:
        from ingest.db import connect  # shared helper: creates tables, turns on WAL
    except ImportError:  # running outside the repo
        connect = None
    if connect is not None:
        con = connect(db_path)
    else:
        con = sqlite3.connect(db_path, timeout=30)
    try:
        return con.execute(
            f"SELECT {COL_DOMAIN}, {COL_SCORE}, {COL_REASONS}, {COL_SEEN_AT} "
            f"FROM {ALERTS_TABLE} WHERE {COL_SCORE} >= ?",
            (THRESHOLD,),
        ).fetchall()
    finally:
        con.close()


def build_signed_body() -> bytes:
    """Blocking work (DB read + signing). Runs in a thread, not the event loop."""
    key = _get_key()
    rows = _read_alert_rows(DB_PATH)
    payload = build_payload(rows, official_domains(), read_domain_file(NO_WILDCARD_FILE),
                            model=model_info())
    envelope = sign_payload(payload, key, KEY_ID)
    log.info("blocklist rebuilt: %d entries from %d alert rows (source=%s)",
             len(payload["entries"]), len(rows), LIST_SOURCE)
    return json.dumps(envelope).encode("utf-8")


async def handle_blocklist(request: web.Request) -> web.Response:
    global _cache_lock
    if _cache_lock is None:
        _cache_lock = asyncio.Lock()

    async with _cache_lock:
        if _cache["body"] is None or time.monotonic() >= _cache["expires"]:
            loop = asyncio.get_running_loop()
            try:
                body = await loop.run_in_executor(None, build_signed_body)
            except SigningKeyError as e:
                log.error("cannot sign blocklist: %s", e)
                return web.json_response(
                    {"error": "blocklist signing key is not configured on the server"},
                    status=503)
            except sqlite3.Error as e:
                log.error("cannot read alerts table: %s", e)
                return web.json_response({"error": "alerts database unavailable"}, status=503)
            _cache["body"] = body
            _cache["expires"] = time.monotonic() + CACHE_SECONDS
        body = _cache["body"]

    return web.Response(body=body, content_type="application/json",
                        headers={"Cache-Control": "no-store"})


async def handle_pubkey(request: web.Request) -> web.Response:
    """The blocklist's public key, derived from the private key we sign with,
    so it can never disagree with the signatures we send."""
    try:
        pub = _get_key().public_key()
    except SigningKeyError as e:
        log.error("cannot load blocklist key: %s", e)
        return web.json_response(
            {"error": "blocklist signing key is not configured on the server"}, status=503)
    pem = pub.public_bytes(serialization.Encoding.PEM,
                           serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return web.json_response({
        "key_id": KEY_ID,
        "alg": "Ed25519",
        "public_key_pem": pem,
        "public_key_b64": base64.b64encode(raw).decode("ascii"),  # format in extension/config.js
        "signs": "/api/blocklist",
    })


def setup_blocklist_route(app: web.Application) -> None:
    app.router.add_get("/api/blocklist", handle_blocklist)
    app.router.add_get("/api/pubkey", handle_pubkey)


def main() -> None:
    p = argparse.ArgumentParser(description="Serve GET /api/blocklist on its own (for testing).")
    p.add_argument("--host", default="127.0.0.1", help="keep this on localhost; use an SSH tunnel")
    p.add_argument("--port", type=int, default=8000)
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    app = web.Application()
    setup_blocklist_route(app)
    web.run_app(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
