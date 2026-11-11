#!/bin/bash
set -euo pipefail
source /lab/settings.sh
mkdir -p /lab/classes /lab/payload
javac -J-Xmx64m -J-XX:ActiveProcessorCount=1 -d /lab/payload /lab/source/ProbePayload.java /lab/source/ProbePayloadMBean.java
jar --create --file /lab/probe.jar -C /lab/payload .
javac -J-Xmx64m -J-XX:ActiveProcessorCount=1 "${JDK_EXPORTS[@]}" -cp /lab/probe.jar -d /lab/classes \
  /lab/source/LabConfig.java /lab/source/LabState.java /lab/source/LabStateMBean.java \
  /lab/source/LabEcho.java /lab/source/LabEchoImpl.java /lab/source/Main.java /lab/source/LabHealth.java /lab/source/NativeProbe.java
# Payload classes remain outside the server class path. The tests require the
# real vendor loader to obtain them from the owned HTTP codebase.
test ! -e /lab/classes/ProbePayload.class
