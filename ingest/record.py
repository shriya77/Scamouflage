"""Turn one certstream-server-go message into a CERTIFICATE RECORD (see CONTRACTS.md)."""
import hashlib
import re

BRAND_RE = re.compile(
    r"(^|[.-])(ntta|zipcash|txtag|tolltag|hctra|eztag|e-?zpass|sunpass|fastrak|i-?pass|"
    r"ezdrive|quickpass|pikepass|peachpass|paytoll|toll|usps)",
    re.I,
)


EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def norm_hash(h: str) -> str:
    return (h or "").replace(":", "").lower()


def cert_key(leaf: dict, issuer: str) -> tuple[str, str]:
    """(id, crtsh_url) for a leaf_cert.

    certstream-server-go sends precerts from some logs (mostly the static ones) without their DER,
    so their sha256 is the hash of empty bytes and would make them all one certificate. Those are
    keyed on issuer + serial instead, which is the same in every log the precert is in."""
    sha = norm_hash(leaf.get("sha256"))
    serial = norm_hash(leaf.get("serial_number"))
    if sha != EMPTY_SHA256:
        return sha, f"https://crt.sh/?q={sha}"
    if serial:
        return "sn:" + hashlib.sha256(f"{issuer}\n{serial}".encode()).hexdigest(), f"https://crt.sh/?serial={serial}"
    names = sorted(d.lower().lstrip("*.") for d in (leaf.get("all_domains") or []) if d)
    if not names:
        return "", ""
    key = "\n".join([issuer, str(leaf.get("not_before"))] + names)
    return "sn:" + hashlib.sha256(key.encode()).hexdigest(), f"https://crt.sh/?q={names[0]}"


def _issuer_str(issuer: dict) -> str:
    if not isinstance(issuer, dict):
        return str(issuer or "")
    return issuer.get("aggregated") or "/".join(
        f"{k}={v}" for k, v in issuer.items() if v and k != "aggregated"
    )


def to_record(msg: dict):
    """Return a record dict, or None if the message isn't a certificate."""
    if msg.get("message_type") != "certificate_update":
        return None
    data = msg.get("data") or {}
    leaf = data.get("leaf_cert") or {}
    if not norm_hash(leaf.get("sha256")):
        return None
    issuer = _issuer_str(leaf.get("issuer"))
    cid, crtsh_url = cert_key(leaf, issuer)
    if not cid:
        return None
    src = data.get("source") or {}
    domains = [d.lower().lstrip("*.") for d in (leaf.get("all_domains") or []) if d]
    # de-dupe while keeping order
    domains = list(dict.fromkeys(domains))
    return {
        "id": cid,
        "seen_at": float(data.get("seen") or 0.0),
        "domains": domains,
        "issuer": issuer,
        "not_before": leaf.get("not_before"),
        "not_after": leaf.get("not_after"),
        "log": src.get("name") or src.get("url") or "",
        "der_b64": leaf.get("as_der") or "",
        # --- additions beyond the original roles PDF ---
        "update_type": "precert" if "Precert" in (data.get("update_type") or "") else "cert",
        "chain_b64": [c.get("as_der") for c in (data.get("chain") or []) if c.get("as_der")],
        "cert_index": data.get("cert_index"),
        "crtsh_url": crtsh_url,
    }


def brand_hit(domains) -> str | None:
    """First domain that contains a toll/USPS brand word, else None."""
    for d in domains:
        if BRAND_RE.search(d):
            return d
    return None
