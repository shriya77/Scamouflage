#!/usr/bin/env bash
# Starts the Scamouflage consumer in tmux session "consumer". Run from anywhere.
# Usage: infra/start_consumer.sh [extra consumer args, e.g. --workers 3]
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
if tmux has-session -t consumer 2>/dev/null; then echo "consumer already running (tmux attach -t consumer)"; exit 0; fi
mkdir -p "$REPO/data"
tmux new -d -s consumer "cd $REPO && $REPO/.venv/bin/python -m ingest.consumer $* 2>&1 | tee -a data/consumer.log"
sleep 3 && tail -3 "$REPO/data/consumer.log" && cat "$REPO/data/stats.json" | head -c 400; echo
