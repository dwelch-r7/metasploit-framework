"""Validate the real daemon through its independent native CLI and wire banner."""
import json
import os
import socket
import sys
import tempfile
import subprocess

records = []


def command(*arguments, password=None, success=True):
    env = os.environ.copy()
    env['RSYNC_PASSWORD'] = password or ''
    argv = ['rsync', '--contimeout=2', '--timeout=2', *arguments]
    result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=5)
    records.append(dict(argv=argv, exitstatus=result.returncode,
                        stdout=result.stdout, stderr=result.stderr))
    if success and result.returncode != 0:
        raise RuntimeError(records[-1])
    return result


version = subprocess.run(['rsync', '--version'], check=True, capture_output=True, text=True).stdout
with socket.create_connection(('127.0.0.1', 873), timeout=2) as client:
    greeting = client.recv(4096).decode('ascii')
assert greeting.startswith('@RSYNCD: '), greeting
listing = command('--list-only', 'rsync://127.0.0.1/').stdout
if sys.argv[1:] == ['empty']:
    assert listing.strip() == '', listing
else:
    assert all(name in listing for name in ('public', 'locked', 'blank')), listing
    assert 'hidden' not in listing, listing
    with tempfile.TemporaryDirectory() as temporary:
        for share, user, password in (('public', '', None), ('locked', 'labuser@', 'labpassword'), ('hidden', '', None)):
            destination = os.path.join(temporary, share)
            command('rsync://' + user + '127.0.0.1/' + share + '/proof.txt', destination, password=password)
            with open(destination) as proof:
                assert proof.read() == 'rsync-module-target-proof\n'
        denied = command('rsync://labuser@127.0.0.1/locked/proof.txt', os.path.join(temporary, 'denied'), password='wrong-password', success=False)
        assert denied.returncode != 0 and 'auth failed' in denied.stderr, denied.stderr
        assert not os.path.exists(os.path.join(temporary, 'denied'))
print(json.dumps(dict(version=version, greeting=greeting, listing=listing, commands=records)))
