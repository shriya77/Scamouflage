"""Live CPACF hardware counters -> data/cpacf_live.json (for the dashboard).

    python -m bench.counters                  # every 2 s, forever (tmux "cpacf")
    python -m bench.counters --once           # one sample (two reads, 2 s apart), print, exit

Reads the PAI counters of `cpacfstats` (needs the cpacfstatsd daemon and
`cpacfstats -e`). Each counter counts how many times a CPACF instruction ran
with that function code, e.g. "KDSA ECDSA Verify P256". Counters from the
pai_user and pai_kernel sections are summed. Rates are deltas between two
samples divided by the real time between them.

Output (written atomically):
  {"ts", "interval_s", "available", "totals": {name: int > 0},
   "rates_per_s": {name: float}, "groups": {ecdsa_verify_per_s, eddsa_sign_per_s,
   eddsa_verify_per_s, sha_per_s, aes_per_s, trng_per_s}, "error"}
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

_SECTION = re.compile(r"^ (pai_user|pai_kernel)\s*:\s*(\S+)")
_COUNTER = re.compile(r"^  (\S.*?)\s*:\s*(\d+)\s*$")

GROUPS = {
    "ecdsa_verify_per_s": lambda n: n.startswith("KDSA ECDSA Verify "),
    "eddsa_sign_per_s": lambda n: n.startswith("KDSA EdDSA Sign "),
    "eddsa_verify_per_s": lambda n: n.startswith("KDSA EdDSA Verify "),
    "sha_per_s": lambda n: n.startswith(("KIMD SHA", "KLMD SHA")),
    "aes_per_s": lambda n: n.split(" ", 1)[0].startswith("KM") and " AES" in n,
    "trng_per_s": lambda n: n == "PRNO TRNG",
}


def parse(text: str) -> dict:
    """cpacfstats output -> {counter name: user + kernel count}."""
    totals, section = {}, None
    for line in text.splitlines():
        m = _SECTION.match(line)
        if m:
            section = m.group(1) if m.group(2) == "enabled" else None
            continue
        if not line.startswith("  "):
            section = None
            continue
        m = _COUNTER.match(line)
        if section and m:
            totals[m.group(1)] = totals.get(m.group(1), 0) + int(m.group(2))
    return totals


def read_counters():
    """-> (totals dict or None, error str or None)"""
    err = None
    for cmd in (["sudo", "-n", "cpacfstats"], ["cpacfstats"]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired) as e:
            err = f"{' '.join(cmd)}: {e}"
            continue
        if r.returncode != 0:
            err = f"{' '.join(cmd)}: exit {r.returncode}: {(r.stderr or r.stdout).strip()[:300]}"
            continue
        totals = parse(r.stdout)
        if totals:
            return totals, None
        err = f"{' '.join(cmd)}: no enabled pai_user/pai_kernel counters (run: sudo cpacfstats -e)"
    return None, err


def build(prev, cur, dt, error=None) -> dict:
    """prev/cur are totals dicts (prev may be None on the first sample)."""
    if cur is None:
        return {"ts": time.time(), "interval_s": round(dt, 3), "available": False,
                "totals": {}, "rates_per_s": {}, "groups": {g: 0.0 for g in GROUPS},
                "error": error or "cpacfstats unavailable"}
    rates = {}
    if prev is not None and dt > 0:
        for k, v in cur.items():
            rates[k] = max(0, v - prev.get(k, 0)) / dt  # counters reset if cpacfstatsd restarts
    totals = {k: v for k, v in sorted(cur.items()) if v > 0}
    return {
        "ts": time.time(),
        "interval_s": round(dt, 3),
        "available": True,
        "totals": totals,
        "rates_per_s": {k: round(rates.get(k, 0.0), 1) for k in totals},
        "groups": {g: round(sum(r for k, r in rates.items() if match(k)), 1)
                   for g, match in GROUPS.items()},
        "error": None,
    }


def write_json_atomic(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--interval", type=float, default=2.0)
    p.add_argument("--out", default="data/cpacf_live.json")
    p.add_argument("--once", action="store_true", help="print one sample and exit (doesn't write --out)")
    args = p.parse_args()

    prev, t_prev = read_counters()[0], time.monotonic()
    if args.once:
        time.sleep(args.interval)
        cur, err = read_counters()
        now = time.monotonic()
        print(json.dumps(build(prev, cur, now - t_prev, err), indent=2))
        sys.exit(0 if cur is not None else 1)

    print(f"[counters] writing {args.out} every {args.interval:g} s", flush=True)
    last_err = None
    while True:
        time.sleep(args.interval)
        try:
            cur, err = read_counters()
            now = time.monotonic()
            write_json_atomic(args.out, build(prev, cur, now - t_prev, err))
            if err != last_err:
                print(f"[counters] {'error: ' + err if err else 'counters available'}", flush=True)
                last_err = err
            if cur is not None:
                prev, t_prev = cur, now
        except Exception as e:  # never die: the dashboard just shows the last good file
            print(f"[counters] {type(e).__name__}: {e}", flush=True)


if __name__ == "__main__":
    main()
