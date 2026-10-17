#!/usr/bin/env bash
# Starts the Scamouflage consumer in tmux session "consumer", restarted automatically if it
# crashes (infra/supervise.sh). Run from anywhere.
# Usage: infra/start_consumer.sh [extra consumer args]
#   engine (default):  infra/start_consumer.sh --workers 3 --labels-db ~/tolltrap/data/labels.db --models ~/tolltrap/data/models
#   old path:          infra/start_consumer.sh --workers 3 --no-engine
# Stop for good (no restart):  touch data/consumer.stop; then Ctrl-C the consumer (or kill -INT its pid)
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
if tmux has-session -t consumer 2>/dev/null; then echo "consumer already running (tmux attach -t consumer)"; exit 0; fi
mkdir -p "$REPO/data"
PY=${PYTHON:-$REPO/.venv/bin/python}
[ -x "$PY" ] || { echo "no python at $PY (set PYTHON=...)"; exit 1; }
# pipefail: the loop must see the consumer's exit code, not tee's
tmux new -d -s consumer "cd $REPO && LOG_DIR=$REPO/data bash $REPO/infra/supervise.sh consumer -- \
  bash -c 'set -o pipefail; $PY -m ingest.consumer $* 2>&1 | tee -a data/consumer.log'"
sleep 3 && tail -3 "$REPO/data/consumer.log" && cat "$REPO/data/stats.json" | head -c 400; echo
