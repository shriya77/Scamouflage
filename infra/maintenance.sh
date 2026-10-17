#!/usr/bin/env bash
# Hourly housekeeping so nothing fills the disk overnight. Run in tmux:
#   tmux new -d -s cc-maint 'bash ~/scamouflage/infra/maintenance.sh'
# Every hour:  rotate *.log in the data folder (>100 MB: copy + truncate, keep 3 gzipped)
#              warn in maintenance.log if free disk < 5 GB
# Every 4 h:   back up scamouflage.db (sqlite online backup) + stats.json, keep the last 3
# Read-only on everything except the logs it rotates and the backup folder.
set -uo pipefail
DATA=${DATA_DIR:-$HOME/tolltrap/data}
BACKUP=${BACKUP_DIR:-$HOME/tolltrap/backups}
LOG=$DATA/maintenance.log
REPO=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$BACKUP"
i=0
while true; do
  ts=$(date -u +%FT%TZ)
  # rotation: logrotate with our own config + state file (no root, no system config)
  sed "s#@DATA@#$DATA#g" "$REPO/infra/logrotate.conf" > "$BACKUP/.logrotate.conf"
  /usr/sbin/logrotate -s "$BACKUP/.logrotate.state" "$BACKUP/.logrotate.conf" >> "$LOG" 2>&1
  free_kb=$(df -Pk "$DATA" | awk 'NR==2 {print $4}')
  echo "$ts disk free $((free_kb / 1024 / 1024)) GB" >> "$LOG"
  [ "$free_kb" -lt $((5 * 1024 * 1024)) ] && echo "$ts WARNING: less than 5 GB free" >> "$LOG"
  if [ $((i % 4)) -eq 0 ]; then
    stamp=$(date -u +%Y%m%d-%H%M)
    if sqlite3 "$DATA/scamouflage.db" ".timeout 30000" ".backup '$BACKUP/scamouflage-$stamp.db'"; then
      cp -f "$DATA/stats.json" "$BACKUP/stats-$stamp.json" 2>/dev/null
      echo "$ts backup scamouflage-$stamp.db ($(du -h "$BACKUP/scamouflage-$stamp.db" | cut -f1))" >> "$LOG"
    else
      echo "$ts WARNING: backup failed" >> "$LOG"
    fi
    ls -1t "$BACKUP"/scamouflage-*.db 2>/dev/null | tail -n +4 | xargs -r rm -f
    ls -1t "$BACKUP"/stats-*.json 2>/dev/null | tail -n +4 | xargs -r rm -f
  fi
  i=$((i + 1))
  sleep 3600
done
