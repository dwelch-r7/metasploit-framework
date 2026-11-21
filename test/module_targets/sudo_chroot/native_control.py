"""Genuine unprivileged compiler/NSS controls; no Framework module is invoked."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

version = sys.argv[1]
assert version in ['1.9.16p2', '1.9.17p1']
vulnerable = version == '1.9.16p2'
environment = dict(os.environ, HOME='/home/lab', USER='lab', LOGNAME='lab', SHELL='/bin/bash',
                   PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')
report = dict(version=version, vulnerable=vulnerable, module_invoked=False, commands=[])
from native_state import snapshot

def command(label, argv, cwd=None):
    process = subprocess.run(argv, cwd=cwd, env=environment, user=1001, group=1001,
                             extra_groups=[], stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    row = dict(label=label, argv=argv, exit=process.returncode, stdout=process.stdout.decode(errors='backslashreplace'),
               stderr=process.stderr.decode(errors='backslashreplace'))
    report['commands'].append(row)
    return row

before = snapshot()
assert os.geteuid() == 0 and before['/usr/local/bin/sudo']['uid'] == 0
assert before['/usr/local/bin/sudo']['mode'] & stat.S_ISUID
stage = Path(tempfile.mkdtemp(prefix='module-target-sudo-native-', dir='/tmp'))
os.chown(stage, 1001, 1001)
proof = stage / 'proof.json'
nonce = uuid.uuid4().hex
try:
    report['identity'] = command('initial-identity', ['/usr/bin/id'])
    assert report['identity']['exit'] == 0 and 'uid=1001(lab)' in report['identity']['stdout']
    report['sudo_version'] = command('actual-sudo-version', ['sudo', '--version'])
    assert report['sudo_version']['exit'] == 0 and report['sudo_version']['stdout'].startswith('Sudo version ' + version + '\n')
    report['source'] = Path('/usr/local/share/module-target/sudo-source').read_text().splitlines()
    assert report['source'][0] == version
    report['baseline'] = before
    report['ordinary_sudo'] = command('ordinary-unprivileged-denial', ['sudo', '-n', '/usr/bin/id'])
    assert report['ordinary_sudo']['exit'] != 0 and 'uid=0(' not in report['ordinary_sudo']['stdout']
    for name in ['anchor', 'anchor/etc', 'libnss_']:
        path = stage / name
        path.mkdir()
        os.chown(path, 1001, 1001)
    shutil.copyfile('/etc/group', stage / 'anchor/etc/group')
    os.chown(stage / 'anchor/etc/group', 1001, 1001)
    nss = stage / 'anchor/etc/nsswitch.conf'
    nss.write_text('passwd: files\n')
    os.chown(nss, 1001, 1001)
    code = '#define _GNU_SOURCE\n#include <unistd.h>\n#include <fcntl.h>\n#include <stdio.h>\n#include <sys/stat.h>\n'
    code += '__attribute__((constructor)) static void native_proof(void) {\n'
    code += 'uid_t real, effective, saved; getresuid(&real,&effective,&saved); int result=setresuid(0,0,0);\n'
    code += 'char text[512]; int length=snprintf(text,sizeof(text),'
    code += json.dumps('{"nonce":"' + nonce + '","before_real":%ld,"before_effective":%ld,"after_real":%ld,"after_effective":%ld,"setresuid":%d,"pid":%ld}\n')
    code += ',(long)real,(long)effective,(long)getuid(),(long)geteuid(),result,(long)getpid());\n'
    code += 'int fd=open(' + json.dumps(str(proof)) + ',O_WRONLY|O_CREAT|O_EXCL,0644);\n'
    code += 'if(fd<0) _exit(43); if(write(fd,text,length)!=length) _exit(44); close(fd); _exit(0); }\n'
    source = stage / 'proof.c'
    source.write_text(code)
    os.chown(source, 1001, 1001)
    library = stage / 'libnss_/control.so.2'
    compiled = command('unprivileged-shared-library-compile', ['gcc', '-shared', '-fPIC', '-o', str(library), str(source)], str(stage))
    assert compiled['exit'] == 0 and library.stat().st_uid == 1001 and library.read_bytes().startswith(b'\x7fELF')
    report['library_sha256'] = hashlib.sha256(library.read_bytes()).hexdigest()
    direct = command('unprivileged-direct-loader-positive', ['python3', '-c', 'import ctypes;ctypes.CDLL(' + repr(str(library)) + ')'], str(stage))
    direct_proof = json.loads(proof.read_text())
    report['direct_loader'] = dict(command=direct, proof=direct_proof, file_uid=proof.stat().st_uid)
    assert direct['exit'] == 0 and proof.stat().st_uid == 1001 and direct_proof['nonce'] == nonce
    assert direct_proof['before_real'] == direct_proof['before_effective'] == direct_proof['after_real'] == direct_proof['after_effective'] == 1001
    assert direct_proof['setresuid'] == -1 and not Path('/proc', str(direct_proof['pid'])).exists()
    proof.unlink()
    benign = command('benign-nss-denial', ['sudo', '-R', 'anchor', 'anchor'], str(stage))
    assert benign['exit'] != 0 and not proof.exists()
    nss.write_text('passwd: /control\n')
    report['attempts'] = []
    for index in range(2):
        attempt = command('actual-nss-' + str(index), ['sudo', '-R', 'anchor', 'anchor'], str(stage))
        entry = dict(command=attempt, proof_exists=proof.exists())
        if proof.exists():
            entry.update(proof=json.loads(proof.read_text()), file_uid=proof.stat().st_uid)
        report['attempts'].append(entry)
        if vulnerable:
            data = entry['proof']
            assert attempt['exit'] == 0 and entry['file_uid'] == 0 and data['nonce'] == nonce
            assert data['before_effective'] == data['after_real'] == data['after_effective'] == 0 and data['setresuid'] == 0
            assert not Path('/proc', str(data['pid'])).exists()
            proof.unlink()
        else:
            assert attempt['exit'] != 0 and not proof.exists()
    assert hashlib.sha256(library.read_bytes()).hexdigest() == report['library_sha256']
    report['resources'] = {name: Path('/sys/fs/cgroup', name).read_text() for name in ['memory.events', 'pids.events']}
    memory = dict(line.split() for line in report['resources']['memory.events'].splitlines())
    pids = dict(line.split() for line in report['resources']['pids.events'].splitlines())
    assert memory['oom'] == memory['oom_kill'] == pids['max'] == '0'
    report['native_operations_passed'] = True
finally:
    report['final_snapshot'] = snapshot()
    shutil.rmtree(stage)
    report['owned_stage_absent'] = not stage.exists()
    report['original_state_preserved'] = report['final_snapshot'] == before
    report['passed'] = report.get('native_operations_passed', False) and report['owned_stage_absent'] and report['original_state_preserved']
    print(json.dumps(report))
assert report['passed']
