"""Exercise standard clients against genuine Dovecot and Exim authentication."""
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path('test/module_targets/capture_core').resolve()))
from native_client import NativeClients

clients = NativeClients()
accounts = json.loads(Path('test/module_targets/capture_core/accounts.json').read_text())
user, password = accounts['username'], accounts['edge_password']


def command(service, *args, stdin=None, status=0):
    row = clients.command(service, *args, stdin=stdin)
    assert row['status'] == status, row
    return row


identity = command('client','python3','/opt/module-target-client.py','identity')
command('curl','curl','--version')
mail_version = command('native_mail','dovecot','--version')
smtp_version = command('native_smtp','exim4','-bV')
assert '2.3.16' in mail_version['stdout']
assert 'Exim version 4.95' in smtp_version['stdout']
command('native_smtp','rm','-f','--','/var/spool/exim4/module-target-mail/capture-message')
# Dovecot's account policy is narrower than the IMAP astring grammar.
allowed = command('native_mail','doveconf','-h','auth_username_chars')['stdout'].strip()
command('native_mail','sh','-c','printf "\nauth_username_chars = %s\n" "$1" >> /etc/dovecot/dovecot.conf','sh',allowed+'}]')
imap_accounts = [(user, password)] + [(accounts['imap_'+suffix+'_username'], accounts['imap_'+suffix+'_password']) for suffix in ['closing_brace','closing_bracket']]
for account, secret in imap_accounts:
    hashed = command('native_mail','doveadm','pw','-s','SHA512-CRYPT','-p',secret)['stdout'].strip()
    command('native_mail','sh','-c','printf "%s:%s\n" "$1" "$2" >> /etc/dovecot/users','sh',account,hashed)
command('native_mail','doveadm','reload')
assert command('native_mail','doveconf','-h','auth_username_chars')['stdout'].strip() == allowed+'}]'
for account, secret in imap_accounts:
    verified = command('native_mail','doveadm','auth','test',account,secret)
    assert 'auth succeeded' in verified['stdout'], verified
rejected = command('native_mail','doveadm','auth','test',user,'module-target-rejected',status=77)
assert 'auth failed' in rejected['stdout'],rejected
pop = clients.capture('native-pop3-edge',110,'client','env','CAPTURE_USERNAME='+user,'CAPTURE_PASSWORD='+password,'python3','/opt/module-target-client.py','pop3','--host','native_mail','--port','110','--mode','auth')
assert pop['status']==0 and '+OK' in pop['stdout'],pop
imap = clients.capture('native-imap-edge',143,'curl','curl','--silent','--show-error','--max-time','5','--noproxy','*','--trace-ascii','-','--user',user+':'+password,'--login-options','AUTH=+LOGIN','imap://native_mail/')
assert imap['status']==0,imap
for suffix, (account, secret) in zip(['closing-brace','closing-bracket'], imap_accounts[1:]):
    accepted = clients.capture('native-imap-'+suffix,143,'curl','curl','--silent','--show-error','--max-time','5','--noproxy','*','--trace-ascii','-','--user',account+':'+secret,'--login-options','AUTH=+LOGIN','imap://native_mail/')
    assert accepted['status']==0,accepted
no_auth = clients.capture('native-imap-no-auth',143,'client','python3','/opt/module-target-client.py','imap-no-auth','--host','native_mail','--port','143')
assert no_auth['status']==0,no_auth
for mode in ['LOGIN','LOGIN-challenge','PLAIN','PLAIN-challenge','CRAM-MD5']:
    args = ['env','CAPTURE_USERNAME='+user,'CAPTURE_PASSWORD='+password,'python3','/opt/module-target-client.py','smtp','--host','native_smtp','--port','25','--mode',mode]
    result = clients.capture('native-smtp-'+mode.lower(),25,'client',*args)
    assert result['status']==0 and '235' in result['stdout'], result
for mode in ['data','data-rset']:
    sent = clients.capture('native-smtp-'+mode,25,'client','python3','/opt/module-target-client.py','smtp','--host','native_smtp','--port','25','--mode',mode)
    assert sent['status']==0,sent
command('native_smtp','exim4','-qff')
message = command('native_smtp','cat','/var/spool/exim4/module-target-mail/capture-message')
assert 'module-target-message-proof' in message['stdout'] and 'RSET' in message['stdout'] and 'module-target-after-rset-proof' in message['stdout'],message
schema = command('reporting_db','env','PGPASSWORD=module-target-framework-db-password','psql','-h','127.0.0.1','-U','module_framework','-d','module_targets','-Atc',"SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
assert schema['stdout'].strip()=='0',schema
# Deliberate network authentication failures come last, so any native login
# penalty cannot delay a subsequent positive Dovecot control.
denied = clients.capture('native-imap-denied',143,'curl','curl','--silent','--show-error','--max-time','5','--noproxy','*','--trace-ascii','-','--user',user+':module-target-rejected','--login-options','AUTH=+LOGIN','imap://native_mail/')
assert denied['status']==67,denied
result={'client_ip':json.loads(identity['stdout'])['client_ip'],'commands':clients.commands,'wire_captures':sorted(p.name for p in clients.artifacts.glob('native-*.pcap'))}
(clients.artifacts/'native-mail.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
