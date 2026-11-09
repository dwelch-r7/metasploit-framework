#!/bin/sh
set -eu
Xvfb -displayfd 3 -screen 0 320x240x24 -nolisten tcp 3>/tmp/xvfb-ready &
# Xvfb writes the display number after it starts accepting connections.
display=$(python3 - <<'PY'
from pathlib import Path
import time
deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    value = Path('/tmp/xvfb-ready').read_text().strip()
    if value.isdigit():
        print(value)
        break
    time.sleep(0.05)
else:
    raise TimeoutError('Xvfb did not become ready')
PY
)
set -- -display ":$display" -forever -shared -rfbport 5900 -rfbversion "$RFB_VERSION" -desktop ModuleTargetVNC -o /tmp/x11vnc.log
if [ "$AUTH_MODE" = password ]; then
  x11vnc -storepasswd labvnc42 /tmp/vnc-password >/dev/null
  set -- "$@" -rfbauth /tmp/vnc-password
else
  test "$AUTH_MODE" = none
  set -- "$@" -nopw
fi
exec x11vnc "$@"
