#!/bin/sh
# Use the real installed CLI. The object store and BLAS thread limits fit the
# measured laptop budget; they do not replace Ray services or HTTP handlers.
set -eu
exec ray start --head --num-cpus=1 --num-gpus=0 \
  --object-store-memory=83886080 --memory=268435456 \
  --include-dashboard=true --dashboard-host=0.0.0.0 --dashboard-port="$MODULE_TARGET_RAY_HEAD_PORT" \
  --dashboard-agent-listen-port="$MODULE_TARGET_RAY_AGENT_PORT" --disable-usage-stats --block
