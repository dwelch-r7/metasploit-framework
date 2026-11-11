#!/bin/bash
set -euo pipefail
mkdir -p /runtime
/bin/ollama serve &
app_pid=$!
cleanup() {
  kill -TERM "$app_pid" 2>/dev/null || true
  wait "$app_pid" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 143' TERM
python3 /lab/native_probe.py bootstrap baseline | tee /runtime/bootstrap.json
touch /runtime/ready
wait "$app_pid"
