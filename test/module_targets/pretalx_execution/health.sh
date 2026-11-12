#!/bin/bash
set -euo pipefail
# Starting Python here could execute an installed startup hook repeatedly.
exec 3<>/dev/tcp/127.0.0.1/8000
printf 'GET /orga/login/ HTTP/1.1\r\nHost: target:8000\r\nConnection: close\r\n\r\n' >&3
IFS= read -r status <&3
[[ "$status" == *' 200 '* ]]
