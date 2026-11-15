import os,signal,subprocess,time
children=[]
def stop(signum=None,frame=None):
 for child in children:
  if child.poll() is None: child.terminate()
 for child in children:
  try: child.wait(timeout=15)
  except subprocess.TimeoutExpired: child.kill()
 raise SystemExit(0 if signum else 1)
signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
children.append(subprocess.Popen(['/usr/sbin/cron','-f','-L','15']))
children.append(subprocess.Popen(['/usr/local/bin/registry','serve','/etc/docker/registry/native.yml']))
children.append(subprocess.Popen(['/usr/sbin/nginx','-c','/etc/nginx/nginx.conf']))
children.append(subprocess.Popen(['dockerd','--host=tcp://0.0.0.0:2375','--host=unix:///var/run/docker.sock','--tls=false','--storage-driver=vfs','--bip=10.211.0.1/24','--iptables=false','--ip6tables=false','--ip-forward=false','--ip-masq=false','--exec-opt','native.cgroupdriver=cgroupfs']))
while all(child.poll() is None for child in children): time.sleep(0.2)
stop()
