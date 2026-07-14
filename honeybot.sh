#!/bin/bash
# Secure absolute path routing configuration for Phase 1
LOG_DIR="/home/ubuntu/honeybot_files"
LOG_FILE="$LOG_DIR/honeybot.log"

# Verify directory infrastructure and enforce restricted permissions
mkdir -p "$LOG_DIR"
touch "$LOG_FILE"
chmod 640 "$LOG_FILE"

echo "[*] HoneyBot Phase 1 active on port 22..."

while true; do
  # Bind netcat to capture a single incoming TCP stream cleanly.
  # Inject simulated OpenSSH banner into the pipeline using a timed background subshell.
  (sleep 0.2; echo "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1") | nc -6lvp 22 2>&1 | while read -r line; do
    TIMESTAMP_LINE=$(date "+%Y-%m-%d %H:%M:%S")
    if [[ "$line" == *"Connection received"* || "$line" == *"connect to"* ]]; then
      echo "[$TIMESTAMP_LINE] [ALERT] CONNECTION DETECTED!: $line" >> "$LOG_FILE"
    else
      echo "[$TIMESTAMP_LINE] [TRAFFIC] : $line" >> "$LOG_FILE"
    fi
  done
  # Forcefully release TCP Port 22 to prevent socket hung states in TIME_WAIT
  sudo fuser -k 22/tcp >/dev/null 2>&1
  sleep 0.5
done
