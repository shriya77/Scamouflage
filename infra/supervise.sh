#!/usr/bin/env bash
# Keep a long-running command alive: restart it when it exits, until a stop file appears.
#   infra/supervise.sh NAME -- command args...
# Every start/exit is appended to $LOG_DIR/NAME.supervise.log (default ~/tolltrap/data).
# Stop for good:   touch $LOG_DIR/NAME.stop  (then Ctrl-C / kill the command once)
# If it crashes 5 times within 5 minutes, it waits 60 s before trying again (no tight crash loop).
set -uo pipefail
NAME=${1:?usage: supervise.sh NAME -- command...}
shift
[ "${1:-}" = "--" ] && shift
LOG_DIR=${LOG_DIR:-$HOME/tolltrap/data}
LOG="$LOG_DIR/$NAME.supervise.log"
STOP="$LOG_DIR/$NAME.stop"
mkdir -p "$LOG_DIR"
rm -f "$STOP"
crashes=()
while true; do
  echo "$(date -u +%FT%TZ) start: $*" >> "$LOG"
  "$@"
  code=$?
  echo "$(date -u +%FT%TZ) exit $code" >> "$LOG"
  if [ -e "$STOP" ]; then
    echo "$(date -u +%FT%TZ) stop file found, not restarting" >> "$LOG"
    rm -f "$STOP"
    exit "$code"
  fi
  now=$(date +%s)
  crashes+=("$now")
  recent=()
  for t in "${crashes[@]}"; do [ $((now - t)) -lt 300 ] && recent+=("$t"); done
  crashes=("${recent[@]}")
  if [ "${#crashes[@]}" -ge 5 ]; then
    echo "$(date -u +%FT%TZ) ${#crashes[@]} exits in 5 min, waiting 60 s" >> "$LOG"
    sleep 60
  else
    sleep 5
  fi
done
