"""Turn one certstream-server-go message into a CERTIFICATE RECORD (see CONTRACTS.md)."""
import re

BRAND_RE = re.compile(
    r"(^|[.-])(ntta|zipcash|txtag|tolltag|hctra|eztag|e-?zpass|sunpass|fastrak|i-?pass|"
    r"ezdrive|quickpass|pikepass|peachpass|paytoll|toll|usps)",
    re.I,
)


def norm_hash(h: str) -> str:
    return (h or "").replace(":", "").lower()


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
    cid = norm_hash(leaf.get("sha256"))
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
        "issuer": _issuer_str(leaf.get("issuer")),
        "not_before": leaf.get("not_before"),
        "not_after": leaf.get("not_after"),
        "log": src.get("name") or src.get("url") or "",
        "der_b64": leaf.get("as_der") or "",
        # --- additions beyond the original roles PDF ---
        "update_type": "precert" if "Precert" in (data.get("update_type") or "") else "cert",
        "chain_b64": [c.get("as_der") for c in (data.get("chain") or []) if c.get("as_der")],
        "cert_index": data.get("cert_index"),
    }


def brand_hit(domains) -> str | None:
    """First domain that contains a toll/USPS brand word, else None."""
    for d in domains:
        if BRAND_RE.search(d):
            return d
    return None
