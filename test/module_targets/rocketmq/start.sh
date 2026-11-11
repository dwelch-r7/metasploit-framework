#!/bin/bash
set -euo pipefail
cd "$ROCKETMQ_HOME/bin"
mkdir -p /tmp/module-target-rocketmq/store
ip=$(hostname -i)
[[ "$ip" != *' '* ]]
cat > /tmp/module-target-rocketmq/broker.conf <<EOF
brokerClusterName=module-target
brokerName=module-target-${ROCKETMQ_VERSION}
brokerId=0
brokerIP1=$ip
namesrvAddr=127.0.0.1:9876
listenPort=10921
rocketmqHome=$ROCKETMQ_HOME
filterServerNums=0
storePathRootDir=/tmp/module-target-rocketmq/store
mapedFileSizeCommitLog=16777216
mapedFileSizeConsumeQueue=300000
transientStorePoolEnable=false
sendMessageThreadPoolNums=1
pullMessageThreadPoolNums=1
queryMessageThreadPoolNums=1
adminBrokerThreadPoolNums=1
clientManageThreadPoolNums=1
heartbeatThreadPoolNums=1
consumerManageThreadPoolNums=1
putMessageFutureThreadPoolNums=1
litePullMessageThreadPoolNums=1
ackMessageThreadPoolNums=1
processReplyMessageThreadPoolNums=1
loadBalanceProcessorThreadPoolNums=1
recoverThreadPoolNums=1
endTransactionThreadPoolNums=1
reviveQueueNum=1
serverWorkerThreads=2
serverSelectorThreads=1
clientWorkerThreads=1
clientCallbackExecutorThreads=1
clientSelectorThreads=1
EOF
# Normal JVM/resource configuration; the distribution's server classes and
# request handlers are unchanged. Vendor launch scripts default to multi-GB heaps.
flags=(-XX:+UseSerialGC -XX:ActiveProcessorCount=1 -Xss256k -XX:MaxMetaspaceSize=96m -XX:ReservedCodeCacheSize=32m -XX:MaxDirectMemorySize=64m -Duser.home=/home/rocketmq -Drocketmq.home.dir="$ROCKETMQ_HOME")
java "${flags[@]}" -Xms32m -Xmx64m -cp "$ROCKETMQ_HOME/conf:$ROCKETMQ_HOME/lib/*" org.apache.rocketmq.namesrv.NamesrvStartup > /tmp/module-target-rocketmq/nameserver.log 2>&1 &
nameserver=$!
java "${flags[@]}" -Xms64m -Xmx160m -cp "$ROCKETMQ_HOME/conf:$ROCKETMQ_HOME/lib/*" org.apache.rocketmq.broker.BrokerStartup -c /tmp/module-target-rocketmq/broker.conf > /tmp/module-target-rocketmq/broker.log 2>&1 &
broker=$!
printf '%s\n' "$nameserver" > /tmp/module-target-rocketmq/nameserver.pid
printf '%s\n' "$broker" > /tmp/module-target-rocketmq/broker.pid
trap 'kill "$nameserver" "$broker" 2>/dev/null || true; wait || true' EXIT
# A failed child fails the fixture instead of leaving a healthy-looking shell.
while kill -0 "$nameserver" 2>/dev/null && kill -0 "$broker" 2>/dev/null; do sleep 1; done
cat /tmp/module-target-rocketmq/nameserver.log /tmp/module-target-rocketmq/broker.log
exit 1
