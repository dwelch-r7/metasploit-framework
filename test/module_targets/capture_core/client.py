"""Run genuine standard-library clients and bounded packet capture in the client namespace."""
import argparse
import ftplib
import json
import imaplib
import os
import poplib
import select
import signal
import smtplib
import socket
import subprocess
import sys
import time


def sniff(args):
    path = os.path.abspath(args.file)
    if not path.startswith('/artifacts/') or not path.endswith('.pcap'):
        raise ValueError('Capture output must belong to the target artifact directory')
    command = ['tcpdump', '-i', 'eth0', '--immediate-mode', '-U', '-s', '0', '-Z', 'root', '-w', path, 'tcp', 'port', str(args.port)]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    lines = []
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            ready, _, _ = select.select([process.stderr], [], [], max(0, deadline-time.monotonic()))
            if not ready:
                break
            line = process.stderr.readline()
            lines.append(line)
            if 'listening on eth0' in line:
                print(json.dumps({'ready': True, 'pid': process.pid, 'argv': command}), flush=True)
                select.select([sys.stdin], [], [], 15)
                return
            if process.poll() is not None:
                break
        raise RuntimeError('tcpdump did not become ready: ' + ''.join(lines))
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        try:
            _, remaining = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            _, remaining = process.communicate(timeout=5)
        print(json.dumps({'status': process.returncode, 'stderr': ''.join(lines)+remaining, 'bytes': os.path.getsize(path) if os.path.exists(path) else None}), flush=True)


def mail(args):
    username = os.environ.get('CAPTURE_USERNAME', '')
    password = os.environ.get('CAPTURE_PASSWORD', '')
    if args.protocol == 'ftp-user-only':
        with ftplib.FTP(timeout=3) as client:
            print(client.connect(args.host, args.port))
            print(client.sendcmd('USER ' + username))
    elif args.protocol == 'imap-no-auth':
        with imaplib.IMAP4(args.host, args.port, timeout=3) as client:
            print(client.noop())
    elif args.protocol == 'pop3':
        client = poplib.POP3(args.host, args.port, timeout=3)
        client.set_debuglevel(2)
        print(client.getwelcome())
        if args.mode != 'no-auth':
            print(client.user(username))
        if args.mode == 'auth':
            print(client.pass_(password))
            print(client.stat())
        print(client.quit())
    else:
        with smtplib.SMTP(args.host, args.port, timeout=3) as client:
            client.set_debuglevel(1)
            print(client.ehlo())
            client.user, client.password = username, password
            if args.mode in ['data', 'data-rset']:
                message = b'Subject: Module target capture\r\n\r\nmodule-target-message-proof\r\n'
                if args.mode == 'data-rset':
                    message += b'RSET\r\nmodule-target-after-rset-proof\r\n'
                print(client.sendmail('sender@module-target.test', ['module_target@module-target.test'], message))
            elif args.mode != 'no-auth':
                mode = args.mode.removesuffix('-challenge')
                method = {'LOGIN': client.auth_login, 'PLAIN': client.auth_plain, 'CRAM-MD5': client.auth_cram_md5}[mode]
                print(client.auth(mode, method, initial_response_ok=not args.mode.endswith('-challenge')))


parser = argparse.ArgumentParser()
sub = parser.add_subparsers(dest='action', required=True)
sub.add_parser('identity')
cap = sub.add_parser('sniff')
cap.add_argument('--port', type=int, required=True)
cap.add_argument('--file', required=True)
for name in ['ftp-user-only', 'pop3', 'smtp', 'imap-no-auth']:
    action = sub.add_parser(name)
    action.add_argument('--host', required=True)
    action.add_argument('--port', type=int, required=True)
    action.add_argument('--mode', default='auth')
args = parser.parse_args()
if args.action == 'identity':
    print(json.dumps({'python': sys.version, 'client_ip': socket.gethostbyname('client'), 'packages': open('/opt/module-target-client-packages.txt', encoding='utf-8').read(), 'psql': subprocess.check_output(['psql', '--version'], text=True)}))
elif args.action == 'sniff':
    sniff(args)
else:
    args.protocol = args.action
    mail(args)
