#!/usr/bin/env bash
# One-look health check for the whole platform.
REPO=$(cd "$(dirname "$0")/.." && pwd)
echo "== tmux sessions";   tmux ls 2>/dev/null || echo "(none)"
echo "== stream port 8080"; (ss -ltn | grep -q ':8080 ') && echo up || echo DOWN
echo "== stats.json";      python3 -c "import json;d=json.load(open('$REPO/data/stats.json'));print({k:d[k] for k in ('uptime_s','certs_per_s','processed_total','alerts_total','queue_depth','dropped_total','lag_s')})" 2>/dev/null || echo "(no stats yet)"
echo "== db";              python3 -c "
import sqlite3;c=sqlite3.connect('$REPO/data/scamouflage.db')
for t in ('alerts','seen','labels'): print(t, c.execute(f'select count(*) from {t}').fetchone()[0])" 2>/dev/null || echo "(no db yet)"
echo "== disk";            df -h / | tail -1
