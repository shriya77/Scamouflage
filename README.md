# Scamouflage

**Catch toll and USPS scam sites the moment their HTTPS certificate is issued, before the first text goes out.**

Scamouflage watches every new TLS certificate in the public Certificate Transparency logs. That's about 885 unique certificates per second, live, on an IBM LinuxONE (z17) VM. It verifies each certificate's signature and scores its domains with an ML model trained on real phishing feeds. When a domain looks like a toll or USPS smishing site (e.g. `ezpass.com-xyz.win`), it raises an alert signed with CPACF hardware crypto.

IBM Z Datathon 2026 · Track B (AI Secured)

## How it fits together

```
CT logs ─► certstream-server-go :8080 ─► ingest/consumer.py ─► verify ─► featurize ─► score ─► sign
                                                 │
                                                 ├─► data/scamouflage.db  (alerts, seen, labels)
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
```
