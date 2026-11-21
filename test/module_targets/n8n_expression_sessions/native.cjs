// Read-only Linux process/socket evidence using the victim's existing Node.
// Field definitions: https://docs.kernel.org/filesystems/proc.html
const fs = require('node:fs');
const net = require('node:net');
const dns = require('node:dns').promises;
const [action, argument, extra] = process.argv.slice(2);
const safePath = value => {
  if (!/^\/tmp\/module-target-nworkflow-[a-z0-9_-]+$/.test(value)) throw Error('Invalid fixture path');
  return value;
};
const readFile = value => fs.existsSync(safePath(value)) ? {
  exists: true, uid: fs.statSync(value).uid, base64: fs.readFileSync(value).toString('base64')
} : {exists: false};

async function main() {
  if (action === 'file') return readFile(argument);
  if (action === 'remove') {
    fs.rmSync(safePath(argument), {force: true});
    return readFile(argument);
  }
  if (action === 'callback') {
    const host = (await dns.lookup('host.docker.internal', {family: 4})).address;
    const identity = {host, token: argument, uid: process.getuid(), pid: process.pid, ppid: process.ppid};
    await new Promise((resolve, reject) => {
      const peer = net.createConnection({host, port: Number(extra)});
      let data = '';
      peer.setTimeout(8000, () => peer.destroy(Error('Callback timed out')));
      peer.on('error', reject);
      peer.on('connect', () => peer.write(JSON.stringify(identity) + '\n'));
      peer.on('data', chunk => {
        data += chunk;
        if (!data.includes('\n')) return;
        if (data !== 'ACK:' + argument + '\n') return peer.destroy(Error('Incorrect callback acknowledgement'));
        peer.end();
      });
      peer.on('close', failed => failed ? reject(Error('Callback failed')) : resolve());
    });
    return identity;
  }
  if (action !== 'state') throw Error('Unknown native action');
  const port = Number(argument);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw Error('Invalid observation port');
  const processes = [];
  for (const name of fs.readdirSync('/proc').filter(value => /^\d+$/.test(value))) {
    const pid = Number(name), base = '/proc/' + name;
    if (pid === process.pid) continue;
    try {
      const stat = fs.readFileSync(base + '/stat', 'utf8');
      const fields = stat.slice(stat.lastIndexOf(')') + 1).trim().split(/\s+/);
      const status = fs.readFileSync(base + '/status', 'utf8');
      const uid = status.match(/^Uid:\s+(\d+)/m)[1];
      const command = fs.readFileSync(base + '/cmdline', 'utf8').replaceAll('\0', ' ').trim();
      const connection_inodes = [];
      try {
        for (const fd of fs.readdirSync(base + '/fd')) {
          try {
            const socket = fs.readlinkSync(base + '/fd/' + fd).match(/^socket:\[(\d+)\]$/);
            if (socket) connection_inodes.push(socket[1]);
          } catch (error) { if (error.code !== 'ENOENT') throw error; }
        }
      } catch (error) {
        // The stock init is root-owned; do not grant ptrace/root to inspect it.
        if (error.code !== 'EACCES' || uid !== '0') throw error;
      }
      processes.push({pid, ppid: Number(fields[1]), state: fields[0], birth: fields[19], uid, command, connection_inodes: connection_inodes.sort()});
    } catch (error) {
      if (error.code !== 'ENOENT' || fs.existsSync(base)) throw error;
    }
  }
  const connections = [];
  for (const table of ['tcp', 'tcp6']) {
    for (const line of fs.readFileSync('/proc/net/' + table, 'utf8').trim().split('\n').slice(1)) {
      const fields = line.trim().split(/\s+/);
      if (parseInt(fields[2].split(':')[1], 16) === port && fields[3] !== '06') {
        connections.push({local: fields[1], remote: fields[2], state: fields[3], inode: fields[9]});
      }
    }
  }
  return {processes: processes.sort((left, right) => left.pid - right.pid), connections};
}
main().then(value => console.log(JSON.stringify(value))).catch(error => {console.error(error); process.exitCode = 1;});
