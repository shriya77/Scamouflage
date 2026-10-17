"""Check alert signatures using only the PUBLIC key (what an outsider would do).

    python -m alerts.check              # check the 20 newest alerts
    python -m alerts.check 42           # check alert id 42
    python -m alerts.check 42 --tamper  # demo: change the score in memory, show it FAILS
"""
import argparse
import json
import sys

from cryptography.hazmat.primitives import serialization

from alerts.sign import PUB_PATH, key_id_of, verify_sig
from ingest.db import DEFAULT_DB, connect


def row_to_alert(row) -> dict:
    a = dict(row)
    a["domains"] = json.loads(a.get("domains") or "[]")
    a["reasons"] = json.loads(a.get("reasons") or "[]")
    return a


def main():
    p = argparse.ArgumentParser()
    p.add_argument("id", nargs="?", type=int)
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--tamper", action="store_true")
    args = p.parse_args()

    with open(PUB_PATH, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    kid = key_id_of(pub)
    con = connect(args.db)
    con.row_factory = __import__("sqlite3").Row
    if args.id is not None:
        rows = con.execute("SELECT * FROM alerts WHERE id=?", (args.id,)).fetchall()
    else:
        rows = con.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 20").fetchall()
    if not rows:
        print("no alerts found")
        sys.exit(1)
    bad = 0
    for r in rows:
        a = row_to_alert(r)
        if args.tamper:
            print(f"  tampering: score {a['score']} -> 0.01")
            a["score"] = 0.01
        ok = a.get("key_id") == kid and verify_sig(a, pub)
        bad += not ok
        print(f"{'VALID  ' if ok else 'INVALID'}  #{a['id']}  {a['domain']}  score={a['score']}  key={a.get('key_id')}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
