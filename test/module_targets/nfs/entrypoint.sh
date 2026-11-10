#!/bin/sh
set -eu
mkdir -p /run/rpcbind
python3 - <<'PY'
import ipaddress
import pathlib
import subprocess

address = subprocess.check_output(['ip', '-4', '-o', 'address', 'show', 'dev', 'eth0', 'scope', 'global'], text=True).split()[3]
network = ipaddress.ip_interface(address).network
source = pathlib.Path('/etc/module-target/exports').read_text()
source = source.replace('RUNTIME_CIDR', str(network))
source = source.replace('RUNTIME_NETMASK', f'{network.network_address}/{network.netmask}')
pathlib.Path('/run/module-target.exports').write_text(source)
PY
rpcbind -w
exec "$@"
