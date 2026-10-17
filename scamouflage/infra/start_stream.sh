#!/usr/bin/env bash
# Starts the certstream-server-go CT stream in tmux session "stream" (port 8080, localhost only).
# Binary + config live in ~/tolltrap (built during setup). Safe to re-run: does nothing if running.
set -euo pipefail
BASE=${STREAM_HOME:-$HOME/tolltrap}
if tmux has-session -t stream 2>/dev/null; then echo "stream already running"; exit 0; fi
# Sanity: recovery and kafka must be off or the stream replays from index 0 / spams logs
grep -n "enabled:" "$BASE/config.yaml" | head -20
mkdir -p "$BASE/data"
tmux new -d -s stream "cd $BASE && $BASE/bin/certstream-server-go --config config.yaml > $BASE/data/stream.log 2>&1"
sleep 3 && tail -5 "$BASE/data/stream.log"
