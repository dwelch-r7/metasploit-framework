#!/bin/sh
set -eu
cd /runtime
if ! node /lab/verify.js "$1" /runtime; then
  npm ci --ignore-scripts --legacy-peer-deps --no-audit --no-fund
  node /lab/verify.js "$1" /runtime
fi
