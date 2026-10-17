"""Role D: cryptographic check of every certificate.

verify(record) -> {"status": "ok" | "fail" | "unknown_issuer", "algo": str, "reason": str}

What it proves: the leaf certificate's signature really was made by the CA it
names as issuer. We never trust the feed; every cert is checked.

How it uses the hardware: `cryptography` on the VM is built against the
system OpenSSL 3.0, which runs ECDSA/EdDSA on CPACF's KDSA instruction and
SHA-2 on KIMD/KLMD. bench/cpacf_ab.py measures this with CPACF on vs. off.

Issuer lookup:
  1. record["chain_b64"][0] if the log sent a chain (RFC 6962 logs do)
  2. otherwise an in-memory cache of every issuer we've seen, keyed by
     subject name. Static CT logs (Let's Encrypt) send no chain, but the
     same intermediates arrive with chains from Google/Cloudflare logs
     within seconds, so the cache warms up almost immediately.
"""
import base64
import binascii
import collections
import warnings

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.utils import CryptographyDeprecationWarning

# Some real CAs issue certs with non-positive serials; cryptography warns once per
# process ("Parsed a serial number which wasn't positive"), which spams consumer.log.
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

_MAX_ISSUERS = 5000           # distinct intermediate CAs we remember
_PER_NAME = 4                 # cross-signs / key rollovers share a subject name

# subject-name DER -> [issuer Certificate, ...]
_issuers: "collections.OrderedDict[bytes, list]" = collections.OrderedDict()
# chain base64 string -> parsed Certificate (chains repeat constantly)
_parsed_chain: "collections.OrderedDict[str, x509.Certificate]" = collections.OrderedDict()


def _algo(pub) -> str:
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return {"secp256r1": "ecdsa-p256", "secp384r1": "ecdsa-p384",
                "secp521r1": "ecdsa-p521"}.get(pub.curve.name, f"ecdsa-{pub.curve.name}")
    if isinstance(pub, rsa.RSAPublicKey):
        return f"rsa-{pub.key_size}"
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "ed25519"
    if isinstance(pub, ed448.Ed448PublicKey):
        return "ed448"
    return type(pub).__name__


def _remember(issuer: x509.Certificate):
    key = issuer.subject.public_bytes()
    lst = _issuers.get(key)
    if lst is None:
        _issuers[key] = [issuer]
        if len(_issuers) > _MAX_ISSUERS:
            _issuers.popitem(last=False)
        return
    _issuers.move_to_end(key)
    if issuer not in lst:
        lst.insert(0, issuer)
        del lst[_PER_NAME:]


def _parse_chain_cert(b64: str):
    c = _parsed_chain.get(b64)
    if c is None:
        c = x509.load_der_x509_certificate(base64.b64decode(b64))
        _parsed_chain[b64] = c
        if len(_parsed_chain) > _MAX_ISSUERS:
            _parsed_chain.popitem(last=False)
        _remember(c)
    return c


def candidates(leaf: x509.Certificate, chain_b64):
    """Issuer certs worth trying, best first."""
    out = []
    for b64 in chain_b64[:1]:
        try:
            out.append(_parse_chain_cert(b64))
        except (ValueError, binascii.Error):
            pass
    for c in _issuers.get(leaf.issuer.public_bytes(), []):
        if c not in out:
            out.append(c)
    return out


def check(leaf: x509.Certificate, issuer: x509.Certificate) -> bool:
    """True if issuer signed leaf. Raises nothing."""
    try:
        leaf.verify_directly_issued_by(issuer)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def verify(record: dict) -> dict:
    der_b64 = record.get("der_b64") or ""
    if not der_b64:
        return {"status": "unknown_issuer", "algo": "", "reason": "no_der"}
    try:
        leaf = x509.load_der_x509_certificate(base64.b64decode(der_b64))
    except (ValueError, binascii.Error):
        return {"status": "fail", "algo": "", "reason": "unparseable"}

    # learn from the whole chain, even if we only need the first one now
    for b64 in (record.get("chain_b64") or [])[1:]:
        try:
            _parse_chain_cert(b64)
        except (ValueError, binascii.Error):
            pass

    cands = candidates(leaf, record.get("chain_b64") or [])
    if not cands:
        return {"status": "unknown_issuer", "algo": "", "reason": "issuer_not_cached"}
    for issuer in cands:
        if check(leaf, issuer):
            return {"status": "ok", "algo": _algo(issuer.public_key()), "reason": ""}
    return {"status": "fail", "algo": _algo(cands[0].public_key()), "reason": "bad_signature"}


def cache_size() -> int:
    return len(_issuers)
