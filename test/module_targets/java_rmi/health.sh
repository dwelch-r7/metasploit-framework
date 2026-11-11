#!/bin/bash
set -euo pipefail
source /lab/settings.sh
exec java -Xms8m -Xmx16m -XX:+UseSerialGC -XX:ActiveProcessorCount=1 -cp /lab/classes LabHealth
