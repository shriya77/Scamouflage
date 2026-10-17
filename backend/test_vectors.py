"""Print hash and signature test vectors so we can confirm Python and JavaScript agree.

    python -m backend.test_vectors

Compare the output with extension/tests/matcher.test.html (the same values are
hard-coded there). If a hash differs, the extension will silently miss domains,
so fix it before anything else.
"""
import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from backend.blocklist_route import normalize_hostname, payload_to_string, sha256_hex, sign_payload
from backend.make_keys import public_key_b64

# Raw input -> what the backend hashes. JavaScript gets the same result from
# new URL(...).hostname plus stripping the trailing dot.
NORMALIZATION_CASES = [
    "ezpass.com-xk2.win",
    "EZPASS.Com-XK2.WIN.",        # uppercase + trailing dot
    "ezpass.com-xk2.win:8443",    # port
    "*.com-xk2.win",              # wildcard from a certificate
    "www.usps.com",               # "www." is kept
    "bücher.example",             # international name -> punycode
    "ezpass.com-demo.localhost",
]

HASH_CASES = [
    "ezpass.com-xk2.win",
    "com-xk2.win",
    "a.b.com-xk2.win",
    "b.com-xk2.win",
    "usps.com",
    "www.usps.com",
    "xn--bcher-kva.example",
    "ezpass.com-demo.localhost",
    "com-demo.localhost",
    "win",
]

# A deliberately PUBLIC test key (seed = sha256 of a fixed string). Never use it
# for anything real; it only proves that a Python signature verifies in tweetnacl.
TEST_SEED = hashlib.sha256(b"scamouflage-public-test-vector-key").digest()


def main() -> None:
    print("Normalization (input -> hostname that gets hashed)")
    for raw in NORMALIZATION_CASES:
        print(f"  {raw!r:32} -> {normalize_hostname(raw)!r}")

    print("\nSHA-256 of UTF-8 hostname, lowercase hex")
    for host in HASH_CASES:
        print(f"  {host:28} {sha256_hex(host)}")

    key = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    payload = {
        "version": 1,
        "generated_at": "2026-10-17T20:00:00Z",
        "threshold": 0.85,
        "entries": [{
            "h": sha256_hex("ezpass.com-xk2.win"), "match_subdomains": False,
            "score": 0.97, "reasons": ["brand-impersonation", "cheap-tld:win"],
            "observed_at": "2026-10-17T15:30:00Z", "source": "live",
        }],
        "allowlist": [sha256_hex("usps.com")],
    }
    env = sign_payload(payload, key, "test-vector-1")
    assert env["payload"] == payload_to_string(payload)
    print("\nSignature vector (public test key, NOT a real key)")
    print(f"  public key : {public_key_b64(key)}")
    print(f"  key_id     : {env['key_id']}")
    print(f"  payload    : {env['payload']}")
    print(f"  signature  : {env['signature']}")
    print(f"  sig bytes  : {len(base64.b64decode(env['signature']))}")


if __name__ == "__main__":
    main()
