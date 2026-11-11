#!/bin/bash
set -euo pipefail
exec 3<>/dev/tcp/127.0.0.1/80
printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' >&3
IFS= read -r status <&3
[[ "$status" == HTTP/1.*' 200 '* ]]
