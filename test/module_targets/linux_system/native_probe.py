"""Read real namespace, package, user and configuration data outside Framework."""
import base64
import json
from pathlib import Path
import subprocess


def command(*argv):
    process = subprocess.run(argv, capture_output=True, check=False)
    commands.append(dict(argv=argv, exitstatus=process.returncode,
                         stdout=base64.b64encode(process.stdout).decode('ascii'),
                         stderr=base64.b64encode(process.stderr).decode('ascii')))
    return process


commands = []
uid = command('id', '-u').stdout.decode().strip()
username = command('id', '-un').stdout.decode().strip()
assert (uid, username) in (('0', 'root'), ('1000', 'labuser'))
release = Path('/etc/os-release').read_text()
assert 'ID=ubuntu' in release and 'VERSION_ID="22.04"' in release
cron = command('crontab', '-l')
assert cron.returncode == 0 and b'module-target-' in cron.stdout
addresses = command('ip', '-j', 'address', 'show')
assert addresses.returncode == 0
network = json.loads(addresses.stdout)
assert any(address['family'] == 'inet6' for interface in network for address in interface.get('addr_info', []))
firewall = command('iptables', '-L')
if uid == '0':
    assert firewall.returncode == 0 and b'module-target-firewall-proof' in firewall.stdout
else:
    assert firewall.returncode != 0 and b'Permission denied' in firewall.stderr

files = {}
for filename in ('/etc/passwd', '/etc/resolv.conf', '/etc/hosts', '/etc/ssh/sshd_config',
                 '/home/labuser/.ssh/id_ed25519', '/home/labuser/.ssh/id_ed25519.pub'):
    files[filename] = base64.b64encode(Path(filename).read_bytes()).decode('ascii')
packages = command('dpkg', '-l')
assert packages.returncode == 0
for package in (b'cron', b'net-tools', b'openssh-server', b'iptables'):
    assert package in packages.stdout
protections = {}
for name, filename in (('aslr', '/proc/sys/kernel/randomize_va_space'),
                       ('kptr', '/proc/sys/kernel/kptr_restrict'),
                       ('dmesg', '/proc/sys/kernel/dmesg_restrict')):
    protections[name] = Path(filename).read_text().strip()
assert Path('/usr/sbin/iptables').is_file()
ports = command('netstat', '-tulpn')
assert ports.returncode == 0 and b':8080 ' in ports.stdout
print(json.dumps(dict(uid=uid, username=username, hostname=command('hostname').stdout.decode().strip(),
                     kernel=command('uname', '-r').stdout.decode().strip(), release=release,
                     cron=base64.b64encode(cron.stdout).decode('ascii'),
                     packages=base64.b64encode(packages.stdout).decode('ascii'),
                     network=network, files=files, protections=protections, commands=commands)))
