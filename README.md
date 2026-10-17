# Scamouflage

**Catch toll and USPS scam sites the moment their HTTPS certificate is issued, before the first text goes out.**

Scamouflage watches every new TLS certificate in the public Certificate Transparency logs. That's about 885 unique certificates per second, live, on an IBM LinuxONE (z17) VM. It verifies each certificate's signature and scores its domains with an ML model trained on real phishing feeds. When a domain looks like a toll or USPS smishing site (e.g. `ezpass.com-xyz.win`), it raises an alert signed with CPACF hardware crypto.

IBM Z Datathon 2026 · Track B (AI Secured)

## How it fits together

```
CT logs ─► certstream-server-go :8080 ─► ingest/consumer.py ─► verify ─► featurize ─► score ─► sign
                                                 │
                                                 ├─► data/scamouflage.db  (alerts, seen, labels)
                                                 │        └─► api :8000 /api/blocklist ─► browser extension
                                                 └─► data/stats.json ─► api :8000 ─► dashboard
```

Interfaces are in **[CONTRACTS.md](CONTRACTS.md)**. Read it before touching code.

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

`api/server.py` (aiohttp, `127.0.0.1:8000`) reads the consumer's DB read-only and the JSON files in `data/`. Each data response has `"source": "live"`, or `"mock"` when its input is missing.

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
ssh -N -o ServerAliveInterval=30 -L 8000:127.0.0.1:8000 linux1@148.100.79.76
```

## Browser extension

The `extension/` folder is a Chrome extension that warns users when they open a flagged site.

- **The API publishes a list.** `GET /api/blocklist` on :8000 returns every flagged domain as a SHA-256 hash with its score and reasons, signed with its own Ed25519 key (`scamouflage-vm-1`, private key only on the VM in `keys/blocklist_ed25519.pem`; see CONTRACTS.md §5). `GET /api/pubkey` returns the matching public key.
- **The extension keeps a copy.** Every 30 minutes it downloads the list, verifies the signature with the bundled public key, and saves it in the browser. Invalid or older lists are rejected.
- **Checks happen in the browser.** For each site opened, it hashes the domain and its parents (e.g. `ezpass.com-xk2.win` and `com-xk2.win`) and looks them up locally. The server never sees what anyone browses.
- **On a match**, a full-page warning shows the score and reasons, with *Go back* and *Continue anyway*.

Serve the list on the VM (localhost only): `.venv/bin/python -m backend.blocklist_route --host 127.0.0.1 --port 8000`, or mount `setup_blocklist_route(app)` in the main API.

To run it: open the SSH tunnel (`ssh -L 8000:localhost:8000 user@vm`), go to `chrome://extensions`, turn on Developer mode, and click *Load unpacked* on `extension/`. Demo mode flags a harmless local test page, so the demo never opens a real scam site. After the blocklist key changes (`extension/config.js` `LIVE_KEYS`), click *reload* on the extension in `chrome://extensions`, or it rejects the new list.

## Safety

We never visit scam sites. Domains are shown as plain text with links to [crt.sh](https://crt.sh) only. Signing keys never leave the VM and are git-ignored.

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
