#!/usr/bin/env bash
# Starts the API + website (api/server.py, aiohttp) in tmux session "cc-api" on port 8000,
# restarted automatically if it crashes (infra/supervise.sh).
#   infra/start_api.sh                 # 127.0.0.1:8000 (reach it with: ssh -L 8000:localhost:8000 linux1@<vm>)
#   API_HOST=0.0.0.0 infra/start_api.sh   # all interfaces (only useful if the firewall allows it)
# Stop for good:  touch ~/tolltrap/data/api.stop; then Ctrl-C in the session
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
SESSION=${API_SESSION:-cc-api}
DATA=${DATA_DIR:-$HOME/tolltrap/data}
if tmux has-session -t "$SESSION" 2>/dev/null; then echo "$SESSION already running (tmux attach -t $SESSION)"; exit 0; fi
tmux new -d -s "$SESSION" "cd $REPO && LOG_DIR=$DATA bash $REPO/infra/supervise.sh api -- \
  env SCAM_DB=$DATA/scamouflage.db DATA_DIR=$DATA LABELS_DB=$DATA/labels.db \
  API_HOST=${API_HOST:-127.0.0.1} API_PORT=${API_PORT:-8000} \
  bash -c '$REPO/.venv/bin/python api/server.py 2>&1 | tee -a $DATA/api.log'"
sleep 3 && tail -3 "$DATA/api.log"
