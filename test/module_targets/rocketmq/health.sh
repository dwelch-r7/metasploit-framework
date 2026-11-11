#!/bin/bash
set -euo pipefail
for service in nameserver broker; do kill -0 "$(cat /tmp/module-target-rocketmq/$service.pid)"; done
grep -q 'boot success' /tmp/module-target-rocketmq/nameserver.log
grep -q 'boot success' /tmp/module-target-rocketmq/broker.log
# Do not repeatedly start a third JVM under the target's CPU/PID cap. The
# separate native SDK preflight verifies the registered route before any owner.
exec 3<>/dev/tcp/127.0.0.1/9876
exec 3>&-
exec 4<>/dev/tcp/127.0.0.1/10921
exec 4>&-
