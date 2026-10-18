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
| `cc-api` | API + website on 127.0.0.1:8000, auto-restart | `bash infra/start_api.sh` | `data/api.log`, `data/api.supervise.log` |
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
bash infra/start_api.sh                          # tmux cc-api, 127.0.0.1:8000, auto-restart
touch ~/tolltrap/data/api.stop; tmux send-keys -t cc-api C-c    # stop for good
```

Check: `curl -s localhost:8000/health`, `curl -s 'localhost:8000/api/alerts?limit=3'`, `curl -s localhost:8000/ | head -3`.

## Seeing the website (demo)

Port 8000 is not reachable from the internet (the VM firewall only lets SSH in). On the demo laptop:

```bash
ssh -N -L 8000:localhost:8000 user@<vm-ip>
```

then open <http://localhost:8000/>. The browser extension uses `http://localhost:8000/api/blocklist` through the same tunnel.

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
