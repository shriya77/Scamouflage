# Crypto on IBM Z: what we verify, what we sign, and proof the chip does it

All numbers below were measured on our LinuxONE VM (IBM z17, machine type 9175, s390x, 3 vCPU, Ubuntu 24.04, OpenSSL 3.0.13 via Python `cryptography`) on 2026-10-17.

## 1. We verify every certificate (we don't trust the feed)

For every certificate in the Certificate Transparency stream, `verify/verify.py` checks the leaf's signature against the CA that it names as issuer. The issuer comes from the chain the log sends, or from a cache of CAs we have already seen (Let's Encrypt's static logs send no chain). A forged or corrupted cert gets `fail`, so it can't slip a fake domain into our pipeline.

- **Recorded real CT data**, 20,000 unique certs: **19,990 ok (99.95 %), 0 fail**, 10 `unknown_issuer` (9 while the issuer cache warms up, 1 entry without DER). Precerts: 6,629 / 6,630 ok. **146 µs per cert**, 162 CAs cached. Issuer algorithms: RSA-2048 7,427 · ECDSA P-384 6,497 · ECDSA P-256 4,798 · RSA-4096 1,181 · RSA-3072 87.
- **Live stream**, about 1 hour: **2,040,206 certs, 99.993 % ok, 0 fail**, 149 `unknown_issuer`. Average 0.207 ms per cert inside the pipeline, 0 dropped, lag 0.01 s, at 590–1,000 certs/s.
- **Headroom:** at 146 µs/cert, one core verifies about 6,800 certs/s. That is **about 7.7×** the ~885 certs/s live average, and the consumer runs 3 workers.

## 2. We sign every alert and the blocklist (anyone can check, nobody can edit)

- **Alerts:** `alerts/sign.py` signs every alert with **Ed25519** (`keys/alert_ed25519.pem`, key id `ed25519:54ac72e60e2c97a6`). It signs the canonical JSON of `cert_id, domain, domains, score, reasons, seen_at, issuer, log, verify, crtsh_url`. Anyone can check an alert with the public key `data/alert_pubkey.pem`. Changing any field (for example the score) makes it INVALID.
- **Blocklist for the browser extension:** `GET /api/blocklist` (`backend/blocklist_route.py`) publishes SHA-256 hashes of flagged hostnames (score ≥ 0.85), never plain domains. It is signed with a separate Ed25519 key (`tolltrap-dev-1`) over the exact bytes of the payload string. The extension verifies the signature *before* it parses the list, and only trusts public keys built into `extension/config.js`.
- **Measured on the VM:** a replay of the recording with every cert forced to alert produced 161,241 signed alerts. `alerts.check` printed VALID for the 20 newest and for #1000. With `--tamper` (score changed in memory), #1000 printed INVALID. The bundled signed demo blocklist checks VALID, and changing one score in its payload makes it INVALID.

## 3. Proof that CPACF does the work

**How "off" works.** OpenSSL reads `OPENSSL_s390xcap` at start-up. `bench/cpacf_ab.py` runs the same code on the same 3,000 real cert/issuer pairs twice, each time in a fresh process: once normally and once with `OPENSSL_s390xcap=z900`. The z900 setting makes OpenSSL believe it is on a CPU from the year 2000 with no CPACF, so it falls back to pure software. Nothing else changes.

| Workload (real data) | CPACF on | CPACF off | Speed-up |
|---|---:|---:|---:|
| Verify real CT certs (all issuers) | 8,122 /s | 1,871 /s | **4.3×** |
| … ECDSA P-256 issuers | 9,341 /s | 1,860 /s | **5.0×** |
| … ECDSA P-384 issuers | 6,479 /s | 902 /s | **7.2×** |
| … RSA-2048 / RSA-4096 issuers | 11,336 / 4,592 /s | 10,874 / 4,508 /s | 1.0× |
| Ed25519 sign (alerts) | 28,082 /s | 13,949 /s | **2.0×** |
| Ed25519 verify | 19,893 /s | 4,677 /s | **4.3×** |
| SHA-256 per cert DER | 1,437,062 /s | 219,422 /s | **6.5×** |
| SHA-256 bulk | 4,543 MB/s | 275 MB/s | **16.5×** |

**Why RSA is 1.0×:** CPACF accelerates ECDSA and EdDSA (KDSA instruction) and SHA-2 (KIMD/KLMD), but not RSA's big-number modular exponentiation. RSA-issued certs are therefore the same speed with CPACF on or off. We report this honestly instead of hiding it.

**Hardware counters (cpacfstats, PAI).** The z17 counts every CPACF instruction it runs. During the CPACF-on benchmark the counters went up by KDSA ECDSA Verify P256 **20,178**, P384 **19,972**, KDSA EdDSA Sign Ed25519 **84,401**, EdDSA Verify **59,800** and KIMD SHA256 **9,629,208**. In the replay test, the Ed25519 sign counter rose by **161,243**: the 161,241 alerts we signed, plus 2 test signatures. Every alert signature ran on the chip.

**Live counters.** `bench/counters.py` (tmux `cpacf`) writes `data/cpacf_live.json` every 2 s with per-second rates. With the live consumer at 350–450 certs/s, we measured `ecdsa_verify_per_s` = 100–380. The counters are machine-wide, so the AES numbers include SSH traffic.

**Protected keys.** `hardware.json` → `protected_keys` lists the kernel's CPACF protected-key files: `protkey_aes_128/192/256` are 80 bytes each, and `protkey_aes_128_xts/256_xts` are 160 bytes each. Reading all five ran 7 PCKMO instructions (the firmware wrapping each key). Only the lengths are stored, never the key bytes.

## 4. Reproduce every number (on the VM, from `~/scamouflage`)

```bash
.venv/bin/python -m verify.check data/recordings/ct-20261017-152933.jsonl.gz --n 20000   # section 1
.venv/bin/python -m bench.cpacf_ab data/recordings/ct-20261017-152933.jsonl.gz           # section 3 -> data/hardware.json
.venv/bin/python -m bench.cpacf_ab --protkeys-only                                       # protected_keys only
.venv/bin/python -m bench.counters --once                                                # live CPACF rates (2 s sample)
.venv/bin/python -m alerts.check                    # newest alerts: VALID
.venv/bin/python -m alerts.check 42 --tamper        # edited alert: INVALID
```

Alerts need a DB with rows. To get one without the model, replay with every cert alerting:
`python -m replay.replay data/recordings/ct-20261017-152933.jsonl.gz --speed 0 --port 8093`, then `python -m ingest.consumer --url ws://127.0.0.1:8093/ --threshold 0 --workers 3 --db data/test.db --stats data/test_stats.json --exit-on-close`. Then run `alerts.check --db data/test.db`.

Blocklist signature, using only public keys (works on `extension/demo_blocklist.json` or a saved `/api/blocklist` response):

```bash
.venv/bin/python - extension/demo_blocklist.json <<'EOF'
import base64, json, re, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
env = json.load(open(sys.argv[1]))
keys = dict(re.findall(r"'([\w-]+)': '([A-Za-z0-9+/=]{44})'", open("extension/config.js").read()))
Ed25519PublicKey.from_public_bytes(base64.b64decode(keys[env["key_id"]])).verify(
    base64.b64decode(env["signature"]), env["payload"].encode())   # raises InvalidSignature if edited
print("VALID", env["key_id"])
EOF
```
