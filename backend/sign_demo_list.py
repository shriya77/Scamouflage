"""Build and sign extension/demo_blocklist.json for the presentation demo.

    python -m backend.sign_demo_list

The demo list flags ONLY harmless local test hostnames under ".localhost",
which Chrome always resolves to your own computer (127.0.0.1). Serve
demo/index.html with `python -m http.server` and open
http://ezpass.com-demo.localhost:5500/ to see the warning. No real scam site is
ever contacted.

It's signed with a SEPARATE demo key (keys/demo_ed25519.pem, created on first
run). The extension trusts that key only for the bundled demo list, so the demo
key can never be used to push a fake live list.
"""
import argparse
import json
import os
import time

from backend.blocklist_route import (iso_utc, make_entry, official_domains,
                                     sha256_hex, sign_payload)
from backend.make_keys import load_or_create, public_key_b64

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_KEY = os.path.join(REPO, "keys", "demo_ed25519.pem")
DEFAULT_OUT = os.path.join(REPO, "extension", "demo_blocklist.json")
CONFIG_JS = os.path.join(REPO, "extension", "config.js")

DEMO_REASONS = ["brand-impersonation", "suspicious-domain-template", "lure-words"]


def build_demo_payload(now: float) -> dict:
    observed = iso_utc(now - 3 * 3600)  # pretend the cert was seen 3 hours ago
    entries = [
        # The exact demo hostname.
        make_entry("ezpass.com-demo.localhost", False, 0.97, DEMO_REASONS, observed, "demo"),
        # Its "registrable domain" with match_subdomains, so parent matching can
        # be shown too: pay.ezpass.com-demo.localhost and
        # usps.com-demo.localhost are flagged through this entry.
        make_entry("com-demo.localhost", True, 0.97, DEMO_REASONS, observed, "demo"),
        # A parent entry WITHOUT match_subdomains: parent-only.localhost itself
        # is flagged, but sub.parent-only.localhost is NOT.
        make_entry("parent-only.localhost", False, 0.91, ["lure-words"], observed, "demo"),
    ]
    return {
        "version": 1,
        "generated_at": iso_utc(now),
        "threshold": 0.85,
        "entries": sorted(entries, key=lambda e: e["h"]),
        "allowlist": sorted({sha256_hex(d) for d in official_domains()}),
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--key", default=DEFAULT_KEY)
    p.add_argument("--key-id", default="tolltrap-demo-1")
    p.add_argument("--out", default=DEFAULT_OUT)
    args = p.parse_args()

    key, created = load_or_create(args.key)
    envelope = sign_payload(build_demo_payload(time.time()), key, args.key_id)
    with open(args.out, "w", encoding="utf-8") as f:
        # Pretty-printing the envelope is fine: the signature covers the
        # payload string's bytes, which json.dump writes back unchanged.
        json.dump(envelope, f, indent=2)
        f.write("\n")

    pub = public_key_b64(key)
    print(("Created" if created else "Used existing") + f" demo key: {args.key}")
    print(f"Wrote {args.out}")
    print(f"Demo public key: {pub}")
    with open(CONFIG_JS, encoding="utf-8") as f:
        if pub in f.read():
            print("extension/config.js already trusts this demo key. Reload the extension.")
        else:
            print("ACTION NEEDED: put this in extension/config.js under DEMO_KEYS:")
            print(f"    '{args.key_id}': '{pub}',")


if __name__ == "__main__":
    main()
