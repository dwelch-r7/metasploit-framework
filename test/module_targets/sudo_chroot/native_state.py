"""Physical configuration, artifact and process evidence for the disposable lab."""
from pathlib import Path
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys

FILES = ['/etc/passwd', '/etc/group', '/etc/nsswitch.conf', '/etc/sudoers', '/etc/sudo.conf',
         '/etc/pam.d/sudo', '/home/lab/foreign', '/usr/local/bin/sudo',
         '/usr/local/share/module-target/sudo-source', '/usr/local/share/module-target/packages']

def metadata(path):
    info = path.lstat()
    value = dict(uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode))
    if path.is_symlink():
        value['link'] = os.readlink(path)
    elif path.is_file():
        value.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), size=info.st_size)
    elif path.is_dir():
        value['directory'] = True
    else:
        raise ValueError('Unexpected target artifact: ' + str(path))
    return value

def snapshot():
    return {name: metadata(Path(name)) if Path(name).exists() else None for name in FILES}

def temporary_files():
    return {str(path.relative_to('/tmp')): metadata(path) for path in sorted(Path('/tmp').rglob('*'))}

def state():
    processes = []
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal() or int(path.name) == os.getpid():
            continue
        try:
            info = dict(line.split(':', 1) for line in (path / 'status').read_text().splitlines())
            fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
            processes.append(dict(pid=int(path.name), uid=int(info['Uid'].split()[1]),
                                  ppid=int(fields[1]), birth=fields[19], state=fields[0],
                                  argv_base64=base64.b64encode((path / 'cmdline').read_bytes()).decode()))
        except FileNotFoundError:
            continue
    connections = []
    for family in ['tcp', 'tcp6']:
        for line in Path('/proc/net', family).read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] != '0A':
                connections.append(dict(family=family, local=fields[1], peer=fields[2], state=fields[3], inode=fields[9]))
    return dict(files=snapshot(), tmp=temporary_files(), processes=sorted(processes, key=lambda row: row['pid']),
                connections=sorted(connections, key=lambda row: (row['family'], row['local'], row['peer'])))

def fixture_path(name):
    assert re.fullmatch(r'/tmp/module-target-sudo-[a-z0-9_-]+(?:\.elf)?', name), name
    return Path(name)

def main():
    action, *arguments = sys.argv[1:]
    if action == 'state':
        result = state()
    elif action in ['file', 'remove']:
        path = fixture_path(arguments[0])
        if action == 'remove' and path.exists():
            path.unlink()
        result = dict(exists=False) if not path.exists() else dict(exists=True, **metadata(path), base64=base64.b64encode(path.read_bytes()).decode())
    elif action == 'launch':
        path = fixture_path(arguments[0])
        assert path.name in ['module-target-sudo-entry-shell.elf', 'module-target-sudo-entry-meterpreter.elf']
        assert path.read_bytes().startswith(b'\x7fELF')
        os.chown(path, 1001, 1001)
        path.chmod(0o700)
        environment = dict(os.environ, HOME='/home/lab', USER='lab', LOGNAME='lab', SHELL='/bin/bash',
                           PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')
        output = path.with_suffix('.log')
        with output.open('ab') as handle:
            os.chown(output, 1001, 1001)
            child = subprocess.Popen([str(path)], cwd='/home/lab', user=1001, group=1001, extra_groups=[],
                                     env=environment, stdin=subprocess.DEVNULL, stdout=handle,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        result = dict(pid=child.pid, path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    elif action == 'command-control':
        command = base64.b64decode(arguments[0]).decode()
        result = subprocess.run(['/bin/sh', '-c', command], user=1001, group=1001, extra_groups=[],
                                cwd='/home/lab', capture_output=True, timeout=10)
        result = dict(exit=result.returncode, stdout_base64=base64.b64encode(result.stdout).decode(),
                      stderr_base64=base64.b64encode(result.stderr).decode())
    elif action == 'reset-created':
        # The caller first proves the fresh container's original /tmp is empty.
        # Match the complete captured tree before removing only its new entries.
        expected = json.loads(base64.b64decode(arguments[0]))
        assert expected == temporary_files()
        for path in list(Path('/tmp').iterdir()):
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()
        result = dict(tmp=temporary_files())
    else:
        raise ValueError(action)
    print(json.dumps(result))

if __name__ == '__main__':
    main()
