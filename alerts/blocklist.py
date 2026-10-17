"""Role D: Ed25519-signed blocklist of flagged domains -> data/blocklist.json.

    python -m alerts.blocklist                       # rebuild every 60 s (tmux "blocklist")
    python -m alerts.blocklist --once                # build once and exit
    python -m alerts.blocklist --verify [path]       # check a list with the PUBLIC key: VALID/INVALID

Every --interval seconds it reads alerts with score >= --threshold seen in the
last --days days (read-only SELECT on data/scamouflage.db) and writes:

  {"generated_at": float, "key_id": str, "count": int, "threshold": float, "days": int,
   "domains": [sorted unique lowercase domains], "sig": base64 Ed25519}

"sig" signs the canonical JSON (sorted keys, no spaces, ASCII) of every other
field, with the same key as the alerts (alerts/sign.py). data/blocklist.txt has
the same domains, one per line, for humans (it isn't signed).
"""
import argparse
import json
import os
import sys
import time

from alerts.sign import PUB_PATH, key_id_of, sign_bytes, signing_key_id, verify_bytes
from ingest.db import DEFAULT_DB, connect

DEFAULT_OUT = "data/blocklist.json"


def canonical(bl: dict) -> bytes:
    return json.dumps({k: v for k, v in bl.items() if k != "sig"},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def read_domains(db_path: str, threshold: float, days: float, now: float) -> list:
    con = connect(db_path)
    try:
        rows = con.execute("SELECT DISTINCT lower(trim(domain)) FROM alerts "
                           "WHERE score >= ? AND seen_at >= ? AND domain != ''",
                           (threshold, now - days * 86400)).fetchall()
    finally:
        con.close()
    return sorted({r[0] for r in rows if r[0]})


def build(db_path: str, threshold: float, days: int) -> dict:
    now = time.time()
    domains = read_domains(db_path, threshold, days, now)
    bl = {"generated_at": now, "key_id": signing_key_id(), "count": len(domains),
          "threshold": threshold, "days": days, "domains": domains}
    bl["sig"], _ = sign_bytes(canonical(bl))
    return bl


def _write_atomic(path: str, text: str):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def write(bl: dict, out: str):
    _write_atomic(out, json.dumps(bl, indent=1) + "\n")
    txt = (out[:-5] if out.endswith(".json") else out) + ".txt"
    _write_atomic(txt, "".join(d + "\n" for d in bl["domains"]))


def verify_file(path: str) -> tuple:
    """-> (ok, message). Uses only the public key, like an outsider would."""
    from cryptography.hazmat.primitives import serialization
    with open(PUB_PATH, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    try:
        with open(path) as f:
            bl = json.load(f)
    except (OSError, ValueError) as e:
        return False, f"cannot read {path}: {e}"
    if not isinstance(bl, dict):
        return False, "not a JSON object"
    if bl.get("key_id") != key_id_of(pub):
        return False, f"key_id {bl.get('key_id')!r} != public key {key_id_of(pub)}"
    if not verify_bytes(canonical(bl), bl.get("sig"), pub):
        return False, "bad signature"
    return True, f"count={bl.get('count')} key={bl.get('key_id')} generated_at={bl.get('generated_at')}"


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--out", default=DEFAULT_OUT)
    p.add_argument("--threshold", type=float, default=0.8)
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--interval", type=float, default=60.0)
    p.add_argument("--once", action="store_true", help="build once and exit")
    p.add_argument("--verify", nargs="?", const=DEFAULT_OUT, metavar="PATH",
                   help="check a blocklist's signature (default data/blocklist.json)")
    args = p.parse_args()

    if args.verify:
        ok, msg = verify_file(args.verify)
        print(f"{'VALID' if ok else 'INVALID'}  {args.verify}  {msg}")
        sys.exit(0 if ok else 1)

    while True:
        try:
            bl = build(args.db, args.threshold, args.days)
            write(bl, args.out)
            print(f"[blocklist] {bl['count']} domains (score >= {args.threshold}, "
                  f"last {args.days} d) -> {args.out}", flush=True)
        except Exception as e:  # DB busy, etc.: keep the last good file, try again next round
            if args.once:
                raise
            print(f"[blocklist] {type(e).__name__}: {e}", flush=True)
        if args.once:
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
