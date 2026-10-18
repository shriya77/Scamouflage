# Scamouflage

**Catch toll, delivery and government scam sites the moment their HTTPS certificate is issued, before the first text goes out.**

Scamouflage watches every new TLS certificate in the public Certificate Transparency logs. That's about 885 unique certificates per second, live, on an IBM LinuxONE (z17) VM. It verifies each certificate's signature and scores its domains with an ML model trained on real phishing feeds. When a domain looks like a toll, delivery or government smishing site (e.g. `ezpass.com-xyz.win`), it raises an alert signed with CPACF hardware crypto.

IBM Z Datathon 2026 · Theme 2: AI Secured

▶ **Demo video:** _link coming soon_ <!-- TODO: add the demo video URL -->

## Theme 2: AI Secured

Scamouflage uses AI to protect people from scam sites, and keeps that AI itself secure from end to end:

- **Trusted input.** Every certificate's signature is checked against its issuer before the model sees it, so a forged or corrupted log entry can't feed the AI fake domains (99.993% verified, 0 failures, over 2 million live certificates).
- **Tamper-evident output.** Every alert and the browser blocklist are signed with Ed25519 on IBM's CPACF crypto hardware. Changing a single score or byte makes the signature invalid.
- **Private by design.** Users get protection without sharing their browsing (see [Privacy design](#privacy-design)).
- **Precision first, with reasons.** A false alarm on a real business is worse than a missed scam, so the model is tuned for very few false alarms, and every alert says why in plain words built from measured facts (e.g. "Registered 3 hours ago via a high-risk registrar").

## How it fits together

```
CT logs ─► certstream-server-go :8080 ─► ingest/consumer.py ─► verify ─► featurize ─► score ─► sign
                                                 │
                                                 ├─► data/scamouflage.db  (alerts, seen, labels)
                                                 │        └─► api :8000 /api/blocklist ─► browser extension
                                                 └─► data/stats.json ─► api :8000 ─► dashboard
```

Interfaces are in **[CONTRACTS.md](CONTRACTS.md)**. Read it before touching code.

## Results

Held-out test set, split by scam campaign so the model is tested on campaigns it never saw in training: **414 toll, delivery and government scam domains vs. 79,164 normal sites** (model `stage1-20261017T2046`).

| | Scams caught (recall) | Right when it warns (precision) | False alarms per 10k normal sites |
|---|---:|---:|---:|
| **Scamouflage** | **88.4%** | **98.9%** | **0.51** |
| Keyword rule (baseline) | 100% | 91.0% | 5.18 |

- The keyword rule catches every scam but raises **about 10× more false alarms**. Ours trades a little recall for far fewer wrong warnings on real businesses.
- PR-AUC is 0.99. Counting borderline names that are sent on to the Stage 3 registration check, 99.5% of scams are flagged or reviewed.
- These numbers are before Stage 3, which removes old, real businesses from alerts. Live numbers are served by `GET /api/results`.

## Why LinuxONE

Checking ~885 new certificates per second and signing every alert is crypto-heavy. On LinuxONE the CPACF crypto hardware does that work. We measured it on our VM (IBM z17, machine type 9175, 3 vCPU) by running the same code on the same real data twice, with CPACF on and with OpenSSL forced to software only:

| Workload (real CT data) | CPACF on | Software only | Speed-up |
|---|---:|---:|---:|
| Verify certificate signatures (all issuers) | 8,122 /s | 1,871 /s | **4.3×** |
| … ECDSA P-384 issuers | 6,479 /s | 902 /s | **7.2×** |
| Ed25519 alert signing | 28,082 /s | 13,949 /s | **2.0×** |
| SHA-256 bulk hashing | 4,543 MB/s | 275 MB/s | **16.5×** |
| RSA issuers (not accelerated by CPACF) | 11,336 /s | 10,874 /s | 1.0× |

- **Live:** about 1 hour of the real stream, **2,040,206 certificates, 0.207 ms each, 0 dropped, 0.01 s behind live**, on 3 vCPUs.
- **Proof the chip did it:** the z17's own CPACF counters rose by 161,243 Ed25519 signatures during a test that signed 161,241 alerts (plus 2 test signatures).
- RSA shows 1.0× because CPACF doesn't accelerate RSA; we report that rather than hide it.

Full method and every number: [docs/crypto.md](docs/crypto.md).

| Folder | Owner | What |
|---|---|---|
| `infra/` `ingest/` `replay/` | A Platform | stream, consumer, recorder, replay, scripts |
| `labels/` `features/` | B | phishing feeds → `labels` table, lead time |
| `model/` `features/` | C | features, model, baselines, `results.json` |
| `verify/` `alerts/` `bench/` | D | signature verify, Ed25519 signing, CPACF A/B |
| `campaigns/` | E | clustering alerts into campaigns |
| `api/` `dashboard/` | F | API on :8000, web UI |
| `extension/` | F | Scamouflage browser extension (Chrome, MV3) |

## Run it (on the VM)

```bash
# one time
cd ~ && git clone git@github.com:shriya77/Scamouflage.git scamouflage
cd ~/scamouflage
sudo apt install -y python3-venv      # only if the next line says venv is missing
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
ln -s ~/tolltrap/data data            # share the data folder with the stream

# every time
bash infra/start_stream.sh               # CT stream on :8080 (skips if already running)
bash infra/start_consumer.sh --workers 3  # consumer in tmux "consumer"
bash infra/status.sh                 # health check
```

Watch it: `tmux attach -t consumer` (detach with `Ctrl-b` then `d`).

### Work without the live stream (recording and replay)

```bash
.venv/bin/python -m ingest.recorder --minutes 20                 # saves data/recordings/ct-*.jsonl.gz
.venv/bin/python -m replay.replay data/recordings/ct-XXXX.jsonl.gz --speed 10   # serves ws://127.0.0.1:8081/
.venv/bin/python -m ingest.consumer --url ws://127.0.0.1:8081/ --db data/replay.db --stats data/replay_stats.json --exit-on-close
```

The replay with `--loop` is also **the demo backup** if the Wi-Fi or the live stream dies.

### Testing your station

Swap your real function into your file (e.g. `model/model.py`) and run the consumer against a replay. Use `--threshold 0` to force every cert to become an alert so you can see rows in the DB.

## Data sources (all real, all public)

- **Certificate Transparency**: 82 CT logs via [certstream-server-go](https://github.com/d-Rickyy-b/certstream-server-go) (incl. Let's Encrypt Static CT logs).
- **Labels**: [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) (392k domains, ~1.7k toll/USPS), [phishunt.io](https://phishunt.io/feed.txt), [OpenPhish](https://openphish.com/) community feed, [Unit 42 Smishing Triad IOCs](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel) as seed patterns.

## API (Role F)

`api/server.py` (aiohttp, `127.0.0.1:8000`) reads the consumer's DB read-only and the JSON files in `data/`. It serves real data only: each response has `"source": "live"`, and a missing input gives `503` with `"source": "unavailable"`.

- `GET /api/stats`, `/api/results`, `/api/leadtime`, `/api/hardware`: `stats.json`, `results.json`, `leadtime.json`, `hardware.json` as-is.
- `GET /api/cpacf/live` (alias `/api/cpacf`): `cpacf_live.json` as-is (live CPACF counter rates).
- `GET /api/alerts?limit=&since=&stage=`: newest alerts (max 1000). `stage=0` = already on a known scam list, `stage=1` also matches alerts with no stage.
- `GET /api/alerts/summary`: `known_total` (stage 0), `new_total` (stage ≥ 1 or none), `total`, `stage_column`.
- `GET /api/alerts/pubkey`: alert-signing public key `{key_id, alg: "Ed25519", public_key_pem}` from `data/alert_pubkey.pem`, `503` if missing.
- `GET /api/alerts/{id}`: one alert by `cert_id`, `404` if unknown.
- `GET /api/campaigns`: alerts grouped by domain template (e.g. `ezpass.com-*.win`).
- `GET /api/health`: data dir, whether the DB and each JSON file exist.
- `WS /ws/live`: `{"type": "stats"}` every 1 s, `{"type": "cpacf"}` every 2 s, `{"type": "alert"}` per new alert.
- `GET /api/blocklist`, `GET /api/pubkey`: signed extension blocklist and its public key (see below).

Start on the VM (from `~/scamouflage`):

```bash
SCAM_DB=/home/linux1/tolltrap/data/scamouflage.db .venv/bin/python api/server.py
```

From your laptop, open the tunnel, then use `http://localhost:8000`:

```bash
ssh -N -o ServerAliveInterval=30 -L 8000:127.0.0.1:8000 user@<vm-ip>
```

## Browser extension

The `extension/` folder is a Chrome extension that warns users when they open a flagged site.

- **The API publishes a list.** `GET /api/blocklist` on :8000 returns every flagged domain as a SHA-256 hash with its score and reasons, signed with its own Ed25519 key (`scamouflage-vm-1`, private key only on the VM in `keys/blocklist_ed25519.pem`; see CONTRACTS.md §5). `GET /api/pubkey` returns the matching public key.
- **The extension keeps a copy.** Every 30 minutes it downloads the list, verifies the signature with the bundled public key, and saves it in the browser. Invalid or older lists are rejected.
- **Checks happen in the browser.** For each site opened, it hashes the domain and its parents (e.g. `ezpass.com-xk2.win` and `com-xk2.win`) and looks them up locally. The server never sees what anyone browses.
- **On a match**, a full-page warning shows the score and reasons, with *Go back* and *Continue anyway*.

Serve the list on the VM (localhost only): `.venv/bin/python -m backend.blocklist_route --host 127.0.0.1 --port 8000`, or mount `setup_blocklist_route(app)` in the main API.

To run it: open the SSH tunnel (`ssh -L 8000:localhost:8000 user@vm`), go to `chrome://extensions`, turn on Developer mode, and click *Load unpacked* on `extension/`. Demo mode flags a harmless local test page, so the demo never opens a real scam site. After the blocklist key changes (`extension/config.js` `LIVE_KEYS`), click *reload* on the extension in `chrome://extensions`, or it rejects the new list.

## Privacy design

- **We never see your browsing.** The extension downloads the whole blocklist and checks each site on your own device. No visited URL or domain is ever sent to us.
- **The list contains only hashes.** The blocklist publishes SHA-256 hashes of flagged hostnames, not the domains.
- **Signed, so it can't be swapped.** The extension accepts the list only if its Ed25519 signature checks out against a public key built into the extension.
- **Only public data in.** The AI reads public Certificate Transparency logs and public phishing feeds. We collect nothing about users.
- **Locked-down server.** The API listens only on the VM's localhost and is reached through an SSH tunnel. Private signing keys are created on the VM and never leave it.

## Safety

We never visit scam sites. Domains are shown as plain text with links to [crt.sh](https://crt.sh) only. Signing keys never leave the VM and are git-ignored.

## IBM AI/ML labs

Both mandatory IBM AI/ML labs were run on our LinuxONE z17 VM on Oct 17, 2026. Notebooks with outputs and results are in [docs/labs/](docs/labs/README.md):

- **Fraud detection LSTM** (TensorFlow/Keras): 99.84% test accuracy and 6,912 sequences/s inference, with the `ibm-zdnn-plugin` 2.3.0 enabled. We didn't measure how much of the work ran on the NNPA AI accelerator.
- **Loan approval** (predictive + generative AI): XGBoost risk model (99.7% low risk), IBM Granite document extraction, BM25 retrieval over lending policies, and a final *Approve* recommendation.

## Team

| Name | Role |
|---|---|
| Shriya | Platform, live stream, crypto, model |
| Vaishnavi | Data, name model, decision engine |
| Swarna | Extension and integration |
| Shadow | Stage 3 domain verifier |
| Bhargav | Dashboard and UI |
| Jahir | Backend API and integration |

## Crypto (Role D) on the VM

```bash
.venv/bin/python -m alerts.keygen                       # once: signing key (keys/, never committed)
.venv/bin/python -m verify.check data/recordings/ct-20261017-152933.jsonl.gz --n 20000
sudo cpacfstatsd; sudo cpacfstats -e                    # optional: live hardware counters
.venv/bin/python -m bench.cpacf_ab data/recordings/ct-20261017-152933.jsonl.gz   # -> data/hardware.json
.venv/bin/python -m alerts.check                        # verify the newest alerts' signatures
.venv/bin/python -m alerts.check 42 --tamper            # demo: edited alert -> INVALID
.venv/bin/python -m bench.cpacf_ab --protkeys-only      # refresh protected_keys in data/hardware.json
.venv/bin/python -m bench.counters --once               # one 2 s sample of live CPACF rates
tmux new -d -s cpacf 'cd ~/scamouflage && .venv/bin/python -m bench.counters 2>&1 | tee -a data/cpacf.log'   # -> data/cpacf_live.json every 2 s
```

tmux sessions owned by Role D: `cpacf` (live counters). The signed blocklist is served by `backend/blocklist_route.py` (see CONTRACTS.md §5). Judges' summary with every number: [docs/crypto.md](docs/crypto.md).
