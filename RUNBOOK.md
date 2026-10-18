# Scamouflage runbook (VM)

Everything runs on the LinuxONE VM as `linux1`, from `~/scamouflage` (data in `~/tolltrap/data`,
reached through the `data` link). Python is always `~/scamouflage/.venv/bin/python`.

```bash
ssh user@<vm-ip>
cd ~/scamouflage
```

## What runs where

| tmux session | What | Started by | Log |
|---|---|---|---|
| `stream` | CT stream (certstream-server-go, :8080) | `bash infra/start_stream.sh` | `data/stream.log` |
| `consumer` | consumer + detection engine | `bash infra/start_consumer.sh ...` (below) | `data/consumer.log`, `data/consumer.supervise.log` |
| `cc-api` | API + website on 0.0.0.0:8000 (public), auto-restart | `bash infra/start_api.sh` | `data/api.log`, `data/api.supervise.log` |
| `cc-leadtime` | lead-time stat, hourly (`model/lead_time.py`) | see "Lead time" | `~/cc-logs/leadtime.log` |
| `cc-maint` | log rotation, disk check, DB backups, hourly | `tmux new -d -s cc-maint 'bash ~/scamouflage/infra/maintenance.sh'` | `data/maintenance.log` |
| `cpacf` | live CPACF counters (Role D) | see README | `data/cpacf.log` |
| `vaishnavi` | feeds loop: labels.db, hourly (Vaishnavi) | Vaishnavi | |

Never `tmux kill-server`. Only touch the sessions you own.

## Is it healthy?

```bash
curl -s localhost:8000/health | python3 -m json.tool
```

Healthy looks like this:
- `"ok": true`;
- `stats_age_s` under a few seconds;
- `lag_s` under 60 (normally under 1);
- `dropped_total` 0;
- every `engine.stage0..stage3` is `"real"`, `stage1_version` set, `engine.signing` true.

More detail:

```bash
bash infra/status.sh                               # sessions, stream port, stats, DB counts, disk
grep '^\[engine\]' data/consumer.log | tail -8      # startup: "workers reporting 3 of 3", every stage real
tail -f data/consumer.log                           # live counters every 10 s
.venv/bin/python -m alerts.check                    # newest alerts' signatures: VALID
```

## Start / stop / restart the consumer

Start, with the engine (the default):

```bash
bash infra/start_consumer.sh --workers 3 --labels-db /home/linux1/tolltrap/data/labels.db --models /home/linux1/tolltrap/data/models
```

It runs under `infra/supervise.sh`: if it crashes it is started again after 5 s (60 s after 5 crashes in 5 minutes). Every start/exit is logged in `data/consumer.supervise.log`.

Stop, cleanly and for good. A stop file first, so it isn't restarted, then Ctrl-C to the consumer's main Python process only (`-o` = oldest, not a worker or the wrapper shell). It finishes the Stage 3 queue for up to 15 s, then the session closes.

```bash
touch data/consumer.stop
kill -INT $(pgrep -o -f '^/home/linux1/scamouflage/.venv/bin/python -m ingest.consumer')
```

Restart (e.g. after `git pull`): stop as above, wait until `tmux has-session -t consumer` fails, then start again. The stream keeps running, so only the seconds in between are missed.

**Rollback to the old path** (no engine; featurize/score as before):

```bash
touch data/consumer.stop; kill -INT $(pgrep -o -f '^/home/linux1/scamouflage/.venv/bin/python -m ingest.consumer')
bash infra/start_consumer.sh --workers 3 --no-engine
```

Note: a consumer started before the supervised script existed has no auto-restart. It shows `ingest.consumer` directly under the tmux pane, with no `supervise.sh`. Restart it with the command above to get it.

## Start / stop the API + website

```bash
bash infra/start_api.sh                          # tmux cc-api, 0.0.0.0:8000 (public), auto-restart
touch ~/tolltrap/data/api.stop; tmux send-keys -t cc-api C-c    # stop for good
```

The default is all interfaces, so the public site stays up after a restart. `API_HOST=127.0.0.1 bash infra/start_api.sh`
keeps it VM-only (tunnel only).

Restart (e.g. after `git pull`). Keep the stop file until the session has closed, or the auto-restart
loop starts the old process again:

```bash
touch ~/tolltrap/data/api.stop; tmux send-keys -t cc-api C-c
while tmux has-session -t cc-api 2>/dev/null; do sleep 1; done
rm -f ~/tolltrap/data/api.stop; bash infra/start_api.sh
curl -s http://<vm-ip>:8000/health      # from your laptop: should answer
```

Check: `curl -s localhost:8000/health`, `curl -s 'localhost:8000/api/alerts?limit=3'`, `curl -s localhost:8000/ | head -3`.

## Seeing the website (demo)

Public: <http://148.100.79.76:8000/> (the VM firewall allows port 8000). The extension's default backend is
the same address.

Fallback if the port is ever closed, or the API was started with `API_HOST=127.0.0.1`: a tunnel from the demo laptop,

```bash
ssh -N -L 8000:localhost:8000 user@<vm-ip>
```

then open <http://localhost:8000/>, and set the extension's backend to `http://localhost:8000` in its options.

## Abuse reports to the registrar ("Report this site" in the extension)

`backend/abuse_report.py`, mounted by the API. The red warning page in the extension has a
"Report this site" button. It sends that one hostname to `POST /api/abuse/draft`; the server finds
the alert, looks up the registrar's abuse mailbox over RDAP (rdap.org only; the scam site is never
contacted), drafts a plain-text report from the signed alert, and returns it with a `mailto:` link.
The person sends it from their own mail program. The server sends nothing on that route and logs
nothing about the caller. Public, rate-limited per address (6/min, 40/h), and it refuses names that
have no alert with score ≥ 0.85 (the blocklist threshold) and a Stage 3 verified registration (or a
place on a public scam list), so it can't be used to look up arbitrary domains.

Operators also get `POST /api/abuse/report` (preview or server-side send) and the dispatch log
`GET /api/abuse/reports`, but only from loopback on the VM (what the SSH tunnel looks like to the
API) or with `X-Scamouflage-Token: $SCAM_ABUSE_TOKEN`. Everything is controlled by environment
variables read by the API process; nothing is stored in the repo.

| Variable | Default | Meaning |
|---|---|---|
| `SCAM_ABUSE_MODE` | `preview` | `off` (all routes 503), `preview` (drafts only), `send` (operators may send from the server) |
| `SCAM_ABUSE_DRAFTS_PER_MINUTE`, `SCAM_ABUSE_DRAFTS_PER_HOUR` | `6`, `40` | per-address limits on the extension's draft route |
| `SCAM_ABUSE_MIN_SCORE`, `SCAM_ABUSE_REQUIRE_VERIFIED` | blocklist threshold (`0.85`), `1` | eligibility bar; `REQUIRE_VERIFIED=0` also allows unverified high scores |
| `SCAM_ABUSE_TOKEN` | – | shared secret for operators who are not on loopback (`openssl rand -hex 24`) |
| `SCAM_SMTP_HOST`, `SCAM_SMTP_PORT` | –, `587` | SMTP relay for operator sends. `SCAM_SMTP_STARTTLS=0` only for local testing |
| `SCAM_SMTP_USER`, `SCAM_SMTP_PASS` | – | relay credentials (export in the tmux shell, never commit) |
| `SCAM_ABUSE_FROM`, `SCAM_ABUSE_REPLY_TO`, `SCAM_ABUSE_CC` | – | `From:` for operator sends (a mailbox you receive), optional Reply-To and CCs |
| `SCAM_ABUSE_ORG` | `Scamouflage (IBM Z Datathon 2026 team)` | who signs operator reports |
| `SCAM_ABUSE_TEST_TO` | – | **reroute every operator send here** (subject prefixed `[TEST, would go to ...]`) |
| `SCAM_PUBLIC_BASE` | – | e.g. `http://148.100.79.76:8000`; adds "signed alert JSON" and "public key" links to the report |
| `SCAM_ABUSE_MAX_PER_HOUR`, `SCAM_ABUSE_DEDUPE_HOURS` | `20`, `24` | operator send cap, and how long the same registered domain is refused a second send |
| `SCAM_ABUSE_RDAP_INTERVAL` | `2.0` | seconds between RDAP requests from the API process. Not shared with Stage 3 (consumer process); rdap.org counts both against the VM's IP |
| `SCAM_ABUSE_DB` | `DATA_DIR/takedowns.db` | contact cache + operator dispatch log (the alerts DB stays read-only) |

Check: `curl -s localhost:8000/api/abuse/config`;
`curl -s -X POST -H 'Content-Type: application/json' -d '{"hostname":"<an alerted hostname>"}' localhost:8000/api/abuse/draft`;
from outside, `curl -s -o /dev/null -w '%{http_code}\n' http://148.100.79.76:8000/api/abuse/reports` must be 403.

## Lead time ("caught before the blocklists")

Already running hourly in `cc-leadtime`. To start it again:

```bash
tmux new -d -s cc-leadtime "cd ~/scamouflage && while true; do date -u +%FT%TZ; env -u SCAM_DB .venv/bin/python -W ignore model/lead_time.py --alerts-db /home/linux1/tolltrap/data/scamouflage.db --labels-db /home/linux1/tolltrap/data/labels.db --out /home/linux1/tolltrap/data/leadtime.json; sleep 3600; done >> /home/linux1/cc-logs/leadtime.log 2>&1"
```

Always pass `--labels-db` explicitly. The script's default is `$SCAM_DB`, which in the consumer/API environment is the alerts DB, not labels.db.

## Disk, logs, backups

`infra/maintenance.sh` (tmux `cc-maint`) runs every hour:
- **Logs:** `*.log` in the data folder are rotated past 100 MB (copy + truncate, 3 kept, gzipped).
- **Disk:** free disk is logged, with a WARNING under 5 GB.
- **Backups:** every 4 h, `scamouflage.db` (SQLite online backup) and `stats.json` are copied to `~/tolltrap/backups/`, keeping the last 3.

Check: `tail data/maintenance.log`, `ls -lh ~/tolltrap/backups/`, `df -h /`.

Restore a backup (consumer stopped first):

```bash
cp ~/tolltrap/backups/scamouflage-YYYYmmdd-HHMM.db ~/tolltrap/data/scamouflage.db
```

## When something is wrong

| Symptom | Look at | Usually |
|---|---|---|
| `/health` `ok: false`, `stats_age_s` large | `tmux ls`, `tail data/consumer.log`, `tail data/consumer.supervise.log` | consumer down: start it (above) |
| `lag_s` growing | `/api/stats` `queue_depth`, `dropped_total`, `engine_ms_per_cert` | stream backlog; check `stream` session and CPU (`uptime`) |
| an engine stage `"stub"` | `grep '^\[engine\]' data/consumer.log` | model files or labels.db missing; fix the path, restart the consumer |
| `engine.signing` false / `[engine] WARNING: alerts will be saved UNSIGNED` | `ls -l keys/alert_ed25519.pem` | key missing; never copy keys off the VM |
| Stage 3 `failed_by_reason.rate_limited` high | `/api/stats` `stage3` | registry RDAP limits (e.g. .top); HIGH names still alert on the score, MAYBE stay safe |
| API 503 `source: unavailable` | `curl localhost:8000/health` `files` | that data file isn't written yet (not a bug; nothing is faked) |
