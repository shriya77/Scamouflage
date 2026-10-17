# Scamouflage contracts

**Read this before writing code.** Each role owns its folder and swaps the fake function for a real one with **the same name, inputs and outputs**. If you need to change a contract, tell Platform (Role A) first. Don't change it on your own.

```
CT logs -> certstream-server-go (:8080) -> ingest/consumer.py
             -> verify.verify(record)          [D]
             -> features.featurize(record)     [B/C]
             -> model.score(features)          [C]
             -> alerts.sign(alert)             [D]  (only when score >= threshold)
             -> SQLite data/scamouflage.db + data/stats.json
             -> api (:8000) -> dashboard       [F]
```

## 1. CERTIFICATE RECORD (made by `ingest/record.py`)

```python
{
  "id":          "5feceb66...",   # sha256 of the leaf cert, lowercase hex, no colons
  "seen_at":     1792248185.59,   # unix seconds the log entry was seen
  "domains":     ["ezpass.com-xyz.win", ...],  # lowercased, "*." stripped, de-duped
  "issuer":      "/C=US/O=Let's Encrypt/CN=R11",
  "not_before":  1792200000,      # unix seconds
  "not_after":   1799976000,
  "log":         "Let's Encrypt 'Sycamore2026h2'",
  "der_b64":     "MIIF...",       # leaf cert DER, base64 (precert = TBS-ish, see note)
  # --- added by Platform ---
  "update_type": "precert" | "cert",
  "chain_b64":   ["MIIF...", ...], # issuer chain DER, base64. CAN BE [] (see note)
  "cert_index":  123456789
}
```

**Notes**
- The **same certificate shows up twice**: once as a precert and once as the final cert. They have **different sha256**. The consumer de-dupes exact hashes only, so expect about 2× per domain. Use `seen` (first time per domain) for lead-time.
- **Static CT logs (Let's Encrypt Sycamore/Willow) send no chain.** `chain_b64` is `[]` for them. `verify` must handle that: look the issuer up in a cache keyed by issuer name, or return `unknown_issuer`.
- Real rate on our VM: **~885 unique certs/sec** (~2,250 websocket msgs/sec). Your function gets **about 1 ms per cert** on one core. With `--workers 3`, it gets about 3 ms.

## 2. Station functions

| Owner | Import | Signature | Returns |
|---|---|---|---|
| D | `from verify.verify import verify` | `verify(record)` | `{"status": "ok"\|"fail"\|"unknown_issuer", "algo": "ecdsa-p256"\|...}` |
| B/C | `from features.features import featurize` | `featurize(record)` | `dict[str, float]` (flat, numbers only) |
| C | `from model.model import score` | `score(features)` | `{"score": float 0..1, "reasons": [str, ...]}`. Keep reasons short and human-readable, e.g. `"brand 'ezpass' + .win TLD"` |
| D | `from alerts.sign import sign` | `sign(alert)` | same dict plus `"sig"` (base64) and `"key_id"` |

Rules:
- **Pure functions.** No DB writes, no network, no printing per cert. They run inside worker processes.
- Load models and keys **once at import time**, not per call.
- If your function throws, the consumer catches it and records the cert as `fail` (or score 0). It's still a bug, so check `data/consumer.log`.
- The alert dict passed to `sign` has these keys: `cert_id, domain, domains, score, reasons, seen_at, issuer, log, verify, crtsh_url`. Sign the canonical JSON of those keys (`json.dumps(..., sort_keys=True, separators=(",",":"))`) so anyone can verify later.

## 3. SQLite: `data/scamouflage.db` (schema in `ingest/db.py`)

Always open it with `from ingest.db import connect; con = connect()`. That creates the tables and turns on WAL so readers don't block the writer.

```sql
alerts(id INTEGER PK, cert_id, domain, domains JSON, score, reasons JSON, seen_at,
       issuer, log, verify, crtsh_url, sig, key_id)          -- written by consumer (A)
labels(domain, feed, first_seen, brand, PK(domain, feed))    -- written by B
seen(domain PK, first_cert_seen, cert_id)                    -- written by consumer (A)
```

- `seen` holds **every toll/USPS-brand domain**, plus a deterministic **1% sample** of all other domains. (Storing every domain would fill the disk.)
- Lead time for a labelled domain = `labels.first_seen - seen.first_cert_seen`.
- **Only the consumer writes `alerts` and `seen`.** The API reads them only.

## 4. JSON files in `data/`

| File | Owner | Refresh | Contents |
|---|---|---|---|
| `stats.json` | A | every 1 s | `ts, uptime_s, msgs_total, certs_total, dupes_total, precert_total, cert_total, processed_total, alerts_total, msgs_per_s, certs_per_s, verify{}, avg_verify_ms, avg_score_ms, queue_depth, dropped_total, lag_s, top_logs{}, last_alert{}` |
| `results.json` | C | once per training run | model vs baselines: precision/recall at 1 FP per 10k, PR curve points, time-split info |
| `leadtime.json` | B | on demand | per-domain lead times + median/p90 vs each feed |
| `hardware.json` | D | on demand | CPACF A/B numbers (on vs `OPENSSL_s390xcap` off), PAI counter deltas |

Write JSON **atomically** (write `x.tmp` then `os.replace`) so the API never reads half a file.

## 5. API (Role F, port 8000, localhost only. Reach it through an SSH tunnel.)

`GET /api/stats` · `GET /api/alerts?limit=&since=` · `GET /api/alerts/{id}` · `GET /api/campaigns` · `GET /api/results` · `GET /api/hardware` · `WS /ws/live` (push new alerts plus stats every second)

## 6. Safety rules (everyone)

- **Never open a scam domain in a browser.** Show domains as plain text and link only to `crt.sh`.
- Never commit keys (`*.pem`, `keys/` are git-ignored). Never paste a private key into chat.
- Don't touch the `stream` tmux session, and never run `tmux kill-server`. Use your own session names.
- Don't open ports 8000/8080 to the internet. Use `ssh -L 8000:localhost:8000 ...`.
