#!/bin/bash
set -euo pipefail
exec java -XX:+UseSerialGC -XX:ActiveProcessorCount=1 -Xms16m -Xmx48m -Xss256k -XX:MaxMetaspaceSize=64m -XX:ReservedCodeCacheSize=16m -XX:MaxDirectMemorySize=32m -Duser.home=/home/rocketmq -cp "/lab/classes:$ROCKETMQ_HOME/conf:$ROCKETMQ_HOME/lib/*" NativeProbe "$@"
