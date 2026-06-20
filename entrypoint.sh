#!/usr/bin/env sh
# 容器啟動:綁定到平台指派的埠(Zeabur 注入 PORT;否則用 SENTINEL_PORT;預設 5000)。
set -e

PORT_VALUE="${PORT}"
case "$PORT_VALUE" in
  ''|*[!0-9]*) PORT_VALUE="${SENTINEL_PORT}";;
esac
case "$PORT_VALUE" in
  ''|*[!0-9]*) PORT_VALUE=5000;;
esac

echo "[entrypoint] Sentinel 監聽 0.0.0.0:${PORT_VALUE}"
# 單一 worker 讓記憶體中的掃描任務狀態一致;多執行緒處理併發。
exec gunicorn -w 1 --threads 8 --timeout 120 -b "0.0.0.0:${PORT_VALUE}" app:app
