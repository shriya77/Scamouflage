"""Record the live CT stream to a gzipped JSONL file (size- and time-limited).

    python -m ingest.recorder --minutes 20                   # full messages (with DER)
    python -m ingest.recorder --minutes 60 --strip-der       # ~5x smaller, no verify possible

Output: data/recordings/ct-YYYYmmdd-HHMMSS.jsonl.gz  (one raw message per line)
Disk check: the VM has ~50 GB; 20 min with DER is roughly 1-2 GB uncompressed.
"""
import argparse
import asyncio
import gzip
import json
import os
import time

import websockets


def strip(msg: dict) -> dict:
    d = msg.get("data") or {}
    (d.get("leaf_cert") or {}).pop("as_der", None)
    for c in d.get("chain") or []:
        c.pop("as_der", None)
    return msg


async def record(args):
    os.makedirs(args.out_dir, exist_ok=True)
    path = os.path.join(args.out_dir, time.strftime("ct-%Y%m%d-%H%M%S.jsonl.gz"))
    limit_bytes = args.max_mb * 1024 * 1024
    deadline = time.time() + args.minutes * 60
    n = written = 0
    print(f"[recorder] -> {path}  (stop after {args.minutes} min or {args.max_mb} MB)", flush=True)
    with gzip.open(path, "wt", compresslevel=5) as f:
        async with websockets.connect(args.url, max_size=None, ping_interval=30) as ws:
            async for raw in ws:
                if args.strip_der:
                    msg = json.loads(raw)
                    if msg.get("message_type") != "certificate_update":
                        continue
                    raw = json.dumps(strip(msg), separators=(",", ":"))
                f.write(raw if raw.endswith("\n") else raw + "\n")
                n += 1
                written += len(raw) + 1
                if n % 20_000 == 0:
                    print(f"[recorder] {n} msgs, {written / 1e6:.0f} MB raw", flush=True)
                if time.time() > deadline or written > limit_bytes:
                    break
    print(f"[recorder] done: {n} msgs, {os.path.getsize(path) / 1e6:.1f} MB on disk -> {path}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", default="ws://127.0.0.1:8080/full-stream")
    p.add_argument("--out-dir", default="data/recordings")
    p.add_argument("--minutes", type=float, default=20)
    p.add_argument("--max-mb", type=int, default=3000, help="stop at this many MB of raw JSON")
    p.add_argument("--strip-der", action="store_true")
    asyncio.run(record(p.parse_args()))


if __name__ == "__main__":
    main()
