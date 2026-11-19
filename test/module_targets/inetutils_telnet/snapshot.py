from pathlib import Path
import hashlib,json,os
files=['/usr/sbin/telnetd','/usr/sbin/inetutils-inetd','/usr/bin/telnet','/bin/login','/etc/passwd','/etc/shadow','/etc/group','/etc/pam.d/login','/etc/pam.d/common-auth','/etc/pam.d/common-account','/opt/module-target-inetd.conf','/opt/module-target-packages.tsv']
processes=[]
for entry in Path('/proc').iterdir():
 if not entry.name.isdigit():continue
 try:
  args=(entry/'cmdline').read_bytes().split(b'\0');name=args[0].decode(errors='replace') if args else ''
  if name.endswith('/inetutils-inetd') or name.endswith('/telnetd') or name in ['telnetd','login','/bin/login','-bash','/bin/bash']:
   status=(entry/'status').read_text().splitlines();processes.append({'pid':int(entry.name),'argv':[x.decode(errors='replace')for x in args if x],'uids':next(x for x in status if x.startswith('Uid:'))})
 except(FileNotFoundError,ProcessLookupError):pass
resources={}
for name in ['memory.events','pids.events','memory.current','memory.peak','pids.current']:
 p=Path('/sys/fs/cgroup')/name
 if p.exists():resources[name]=p.read_text()
print(json.dumps({'files':{name:hashlib.sha256(Path(name).read_bytes()).hexdigest()for name in files},'processes':processes,'proof_files':[str(x)for x in Path('/tmp').glob('module-target-*') if x.is_file()],'resources':resources,'os_release':Path('/etc/os-release').read_text()}))
