"""Role D: sign every alert with Ed25519 so nobody can fake or edit one.

sign(alert) -> same dict plus "sig" (base64) and "key_id" (str)

What gets signed: the canonical JSON of SIGNED_FIELDS (sorted keys, no spaces).
Anyone with the public key (data/alert_pubkey.pem) can check an alert with
`python -m alerts.check <alert id>`; changing any signed field breaks it.

Hardware: Ed25519 signing runs on CPACF's KDSA instruction through the
system OpenSSL 3.0 (measured by bench/cpacf_ab.py).

The private key lives in keys/alert_ed25519.pem (git-ignored, chmod 600).
Create it once with:  python -m alerts.keygen
"""
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY_PATH = os.environ.get("SCAM_SIGNING_KEY", os.path.join(REPO, "keys", "alert_ed25519.pem"))
PUB_PATH = os.path.join(REPO, "data", "alert_pubkey.pem")

LEGACY_FIELDS = ("cert_id", "domain", "domains", "score", "reasons", "seen_at",
                 "issuer", "log", "verify", "crtsh_url")
# The engine's Decision fields (ingest/db.py DECISION_COLUMNS), signed too.
DECISION_SIGNED = ("verdict", "stage", "s1", "s2_boost", "brand", "category", "verified",
                   "age_days", "registrar", "risky_registrar", "model_version",
                   "cert_seen_at", "decided_at")
SIGNED_FIELDS = LEGACY_FIELDS + DECISION_SIGNED


def canonical(alert: dict) -> bytes:
    """Alerts written before the engine (or with --no-engine) have every Decision field NULL and
    were signed over LEGACY_FIELDS only. A signature over all SIGNED_FIELDS never verifies against
    the legacy bytes (and vice versa), so blanking the Decision fields can't forge anything."""
    fields = SIGNED_FIELDS if any(alert.get(k) is not None for k in DECISION_SIGNED) else LEGACY_FIELDS
    return json.dumps({k: alert.get(k) for k in fields},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def key_id_of(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


def _load():
    if not os.path.exists(KEY_PATH):
        raise FileNotFoundError(f"no signing key at {KEY_PATH}; run: python -m alerts.keygen")
    with open(KEY_PATH, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    return priv, key_id_of(priv.public_key())


_PRIV = None
_KEY_ID = None


def sign(alert: dict) -> dict:
    global _PRIV, _KEY_ID
    if _PRIV is None:
        _PRIV, _KEY_ID = _load()
    out = dict(alert)
    out["sig"] = base64.b64encode(_PRIV.sign(canonical(alert))).decode()
    out["key_id"] = _KEY_ID
    return out


def verify_sig(alert: dict, pub: Ed25519PublicKey) -> bool:
    from cryptography.exceptions import InvalidSignature
    try:
        pub.verify(base64.b64decode(alert.get("sig") or ""), canonical(alert))
        return True
    except (InvalidSignature, ValueError):
        return False
