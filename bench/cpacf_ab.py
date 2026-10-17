"""CPACF on vs. off, measured on OUR real workload. Writes data/hardware.json.

    python -m bench.cpacf_ab ~/tolltrap/data/recordings/ct-20261017-152933.jsonl.gz

How "off" works: OpenSSL reads the OPENSSL_s390xcap environment variable at
start-up. We run the exact same Python code twice in fresh processes: once
normally (CPACF on) and once with OPENSSL_s390xcap set so OpenSSL believes the
CPU has no crypto instructions (pure software). Same data, same code, same
machine; the only difference is the hardware.

Workloads (all real):
  verify   - check leaf signatures of real CT certs against their issuers
  sign     - Ed25519-sign real-shaped alerts (what alerts/sign.py does)
  sha256   - hash real certificate DER (cert fingerprints)
"""
import argparse
import base64
import collections
import gzip
import hashlib
import json
import os
import platform
import subprocess
import sys
import time

OFF_MASK_DEFAULT = "z900"   # pretend to be a year-2000 CPU: no KIMD/KDSA/etc.


# ------------------------------------------------------------ worker side
def load_pairs(path, n):
    from cryptography import x509
    from verify import verify as V
    from ingest.record import to_record
    pairs, ders, seen = [], [], set()
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt") as f:
        for line in f:
            try:
                rec = to_record(json.loads(line))
            except ValueError:
                continue
            if not rec or not rec["der_b64"] or rec["id"] in seen:
                continue
            seen.add(rec["id"])
            try:
                der = base64.b64decode(rec["der_b64"])
                leaf = x509.load_der_x509_certificate(der)
            except ValueError:
                continue
            ders.append(der)
            for b64 in rec["chain_b64"][1:]:
                try:
                    V._parse_chain_cert(b64)
                except ValueError:
                    pass
            for iss in V.candidates(leaf, rec["chain_b64"]):
                if V.check(leaf, iss):
                    pairs.append((leaf, iss, V._algo(iss.public_key())))
                    break
            if len(pairs) >= n:
                break
    return pairs, ders


def timed(fn, seconds):
    """Run fn() (which does k ops and returns k) until `seconds` pass; return ops/s."""
    ops, t0 = 0, time.perf_counter()
    while True:
        ops += fn()
        dt = time.perf_counter() - t0
        if dt >= seconds:
            return ops / dt


def worker(args):
    from verify import verify as V
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    out = {"mask": os.environ.get("OPENSSL_s390xcap", "")}
    pairs, ders = load_pairs(args.file, args.n)
    out["pairs"] = len(pairs)

    # verify, overall and per algorithm
    def run_verify(lst):
        def f():
            for leaf, iss, _ in lst:
                V.check(leaf, iss)
            return len(lst)
        return f
    if pairs:
        out["verify_ops_s"] = timed(run_verify(pairs), args.seconds)
        groups = collections.defaultdict(list)
        for p in pairs:
            groups[p[2]].append(p)
        out["verify_by_algo"] = {a: {"n": len(g), "ops_s": timed(run_verify(g), args.seconds / 2)}
                                 for a, g in groups.items() if len(g) >= 20}

    # Ed25519 sign + verify of a real-shaped alert
    key = Ed25519PrivateKey.generate()
    msg = json.dumps({"cert_id": "a" * 64, "domain": "ezpass.com-pay.win", "domains": ["ezpass.com-pay.win"],
                      "score": 0.97, "reasons": ["brand+tld"], "seen_at": time.time(),
                      "issuer": "/C=US/O=Let's Encrypt/CN=E7", "log": "Google 'Argon2026h2'",
                      "verify": "ok", "crtsh_url": "https://crt.sh/?q=" + "a" * 64},
                     sort_keys=True, separators=(",", ":")).encode()
    sig = key.sign(msg)
    pub = key.public_key()

    def s():
        for _ in range(200):
            key.sign(msg)
        return 200

    def v():
        for _ in range(200):
            pub.verify(sig, msg)
        return 200
    out["ed25519_sign_ops_s"] = timed(s, args.seconds)
    out["ed25519_verify_ops_s"] = timed(v, args.seconds)

    # SHA-256 over real cert DER
    blob = b"".join(ders[:2000]) or os.urandom(1 << 20)

    def h():
        for d in ders[:2000] or [blob]:
            hashlib.sha256(d).digest()
        return len(ders[:2000]) or 1
    out["sha256_ops_s"] = timed(h, args.seconds)
    big = blob * max(1, (16 << 20) // max(len(blob), 1))
    t = time.perf_counter()
    hashlib.sha256(big).digest()
    out["sha256_MB_s"] = len(big) / 1e6 / (time.perf_counter() - t)
    print(json.dumps(out))


# ------------------------------------------------------------ parent side
def run_mode(args, mask):
    env = dict(os.environ)
    env.pop("OPENSSL_s390xcap", None)
    if mask:
        env["OPENSSL_s390xcap"] = mask
    cmd = [sys.executable, "-m", "bench.cpacf_ab", args.file, "--worker",
           "--n", str(args.n), "--seconds", str(args.seconds)]
    r = subprocess.run(cmd, env=env, capture_output=True, text=True,
                       cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if r.returncode:
        sys.exit(f"worker failed ({mask or 'on'}):\n{r.stderr[-2000:]}")
    return json.loads(r.stdout.strip().splitlines()[-1])


def cpacf_counters():
    for cmd in (["cpacfstats"], ["sudo", "-n", "cpacfstats"]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout
        except (OSError, subprocess.TimeoutExpired):
            pass
    return None


def ratio(a, b):
    return round(a / b, 2) if a and b else None


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("file", help="a recording WITH certificate DER (not --strip-der)")
    p.add_argument("--n", type=int, default=3000, help="real cert/issuer pairs to use")
    p.add_argument("--seconds", type=float, default=3.0, help="time per measurement")
    p.add_argument("--off-mask", default=OFF_MASK_DEFAULT)
    p.add_argument("--out", default="data/hardware.json")
    p.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = p.parse_args()
    if args.worker:
        return worker(args)

    print("[bench] CPACF ON ...", flush=True)
    before = cpacf_counters()
    on = run_mode(args, None)
    after = cpacf_counters()
    print("[bench] CPACF OFF (OPENSSL_s390xcap=%s) ..." % args.off_mask, flush=True)
    off = run_mode(args, args.off_mask)

    rows = {
        "verify (real CT certs)": ("verify_ops_s", "sig checks/s"),
        "Ed25519 sign (alerts)": ("ed25519_sign_ops_s", "signs/s"),
        "Ed25519 verify": ("ed25519_verify_ops_s", "verifies/s"),
        "SHA-256 (cert DER)": ("sha256_ops_s", "hashes/s"),
        "SHA-256 (bulk)": ("sha256_MB_s", "MB/s"),
    }
    results = {}
    print(f"\n{'workload':26s} {'CPACF on':>14s} {'CPACF off':>14s} {'speedup':>8s}")
    for name, (k, unit) in rows.items():
        a, b = on.get(k), off.get(k)
        results[name] = {"on": a, "off": b, "unit": unit, "speedup": ratio(a, b)}
        if a and b:
            print(f"{name:26s} {a:14,.0f} {b:14,.0f} {a / b:7.1f}x")
    by_algo = {}
    for algo, d in (on.get("verify_by_algo") or {}).items():
        o = (off.get("verify_by_algo") or {}).get(algo, {})
        by_algo[algo] = {"n": d["n"], "on": d["ops_s"], "off": o.get("ops_s"),
                         "speedup": ratio(d["ops_s"], o.get("ops_s"))}
        if o.get("ops_s"):
            print(f"  verify {algo:17s} {d['ops_s']:14,.0f} {o['ops_s']:14,.0f} "
                  f"{d['ops_s'] / o['ops_s']:7.1f}x   ({d['n']} certs)")

    sha = results["SHA-256 (bulk)"]["speedup"] or 0
    if sha and sha < 1.5:
        print("\n[bench] WARNING: almost no difference, so the OFF mask probably didn't apply. "
              "Try --off-mask 'kimd:0:0;klmd:0:0;kdsa:0:0'")

    try:
        machine = next((l.split("machine =")[1].split()[0] for l in open("/proc/cpuinfo")
                        if "machine =" in l), None)
    except OSError:
        machine = None
    import ssl
    report = {
        "generated_at": time.time(),
        "machine_type": machine,
        "arch": platform.machine(),
        "openssl": ssl.OPENSSL_VERSION,
        "off_mask": args.off_mask,
        "pairs_used": on.get("pairs"),
        "results": results,
        "verify_by_algo": by_algo,
        "cpacfstats_before": before,
        "cpacfstats_after": after,
        "note": "Same code and data run twice in fresh processes; only OPENSSL_s390xcap differs. "
                "RSA is not CPACF-accelerated, so RSA-issued certs show ~1x by design.",
    }
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    tmp = args.out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(report, f, indent=2)
    os.replace(tmp, args.out)
    print(f"\n[bench] wrote {args.out}")
    if before is None:
        print("[bench] (cpacfstats counters unavailable; run `sudo cpacfstatsd` and "
              "`sudo cpacfstats -e` first to include them)")


if __name__ == "__main__":
    main()
