"""Replay a recording as a local websocket, so everyone can work without the live stream.

    python -m replay.replay data/recordings/ct-....jsonl.gz                # real-time pace
    python -m replay.replay data/recordings/ct-....jsonl.gz --speed 10     # 10x faster
    python -m replay.replay FILE --speed 0                                 # as fast as possible
    python -m replay.replay FILE --loop                                    # repeat forever (demo backup)

Then point the consumer at it:
    python -m ingest.consumer --url ws://127.0.0.1:8081/
Every client that connects gets its own copy of the replay from the start.
"""
import argparse
import asyncio
import gzip
import json
import time

import websockets


def lines(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt") as f:
        for line in f:
            line = line.strip()
            if line:
                yield line


def seen_ts(raw: str):
    try:
        return float(json.loads(raw)["data"]["seen"])
    except (KeyError, TypeError, ValueError):
        return None


async def stream_to(ws, args):
    while True:
        first_ts = start = None
        sent = 0
        for raw in lines(args.file):
            if args.speed > 0:
                ts = seen_ts(raw)
                if ts is not None:
                    if first_ts is None:
                        first_ts, start = ts, time.monotonic()
                    wait = (ts - first_ts) / args.speed - (time.monotonic() - start)
                    if wait > 0:
                        await asyncio.sleep(wait)
            await ws.send(raw)
            sent += 1
            if sent % 1000 == 0:
                await asyncio.sleep(0)  # let other clients breathe at --speed 0
        print(f"[replay] finished pass: {sent} msgs", flush=True)
        if not args.loop:
            break


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("file")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8081)
    p.add_argument("--speed", type=float, default=1.0, help="1 = real time, 0 = max speed")
    p.add_argument("--loop", action="store_true")
    args = p.parse_args()

    async def handler(ws):
        print(f"[replay] client connected: {ws.remote_address}", flush=True)
        try:
            await stream_to(ws, args)
        except websockets.exceptions.ConnectionClosed:
            print("[replay] client left", flush=True)

    async def serve():
        async with websockets.serve(handler, args.host, args.port, max_size=None):
            print(f"[replay] serving {args.file} on ws://{args.host}:{args.port}/ at speed {args.speed}",
                  flush=True)
            await asyncio.Future()

    asyncio.run(serve())


if __name__ == "__main__":
    main()
