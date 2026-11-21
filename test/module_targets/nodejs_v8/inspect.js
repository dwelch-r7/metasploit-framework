'use strict';

var fs = require('fs');
var crypto = require('crypto');
var action = process.argv[2];
var argument = process.argv[3];

function file(path, includeBytes) {
  if (!fs.existsSync(path)) return {exists: false};
  var stat = fs.statSync(path);
  var bytes = fs.readFileSync(path);
  var result = {exists: true, uid: stat.uid, mode: stat.mode, sha256: crypto.createHash('sha256').update(bytes).digest('hex')};
  if (includeBytes !== false) result.base64 = bytes.toString('base64');
  return result;
}

function processRow(pid) {
  if (!/^\d+$/.test(String(pid))) throw Error('Invalid PID');
  try {
      var raw = fs.readFileSync('/proc/' + pid + '/stat', 'utf8');
      var fields = raw.slice(raw.lastIndexOf(')') + 2).trim().split(/\s+/);
      var status = fs.readFileSync('/proc/' + pid + '/status', 'utf8');
      return {pid: Number(pid), ppid: Number(fields[1]), birth: fields[19], state: fields[0],
        uid: Number(status.match(/^Uid:\s+(\d+)/m)[1]),
        command: fs.readFileSync('/proc/' + pid + '/cmdline', 'utf8').replace(/\0/g, ' ').trim()};
    } catch (error) {
      if (error.code !== 'ENOENT' && error.code !== 'ESRCH') throw error;
      return null;
    }
}

function state() {
  var callbackPort = Number(argument);
  if (!Number.isInteger(callbackPort) || callbackPort < 1 || callbackPort > 65535) throw Error('Invalid callback port');
  var callbackHex = ('0000' + callbackPort.toString(16).toUpperCase()).slice(-4);
  var rows = fs.readdirSync('/proc').filter(function (pid) { return /^\d+$/.test(pid); }).map(processRow).filter(Boolean);
  var candidates = rows.filter(function (row) { return row.command.split(' ').indexOf('/opt/module-target-nodejs/application.js') !== -1; });
  // docker-init repeats the child's argv; it is not the JavaScript process.
  var selected = candidates.filter(function (row) { return row.command.split(' ')[0].indexOf('docker-init') === -1; });
  if (selected.length !== 1) throw Error('Expected exactly one real debugger process: ' + JSON.stringify(candidates));
  for (var count = 0; count < rows.length; count++) {
    var children = rows.filter(function (row) {
      return selected.some(function (parent) { return row.ppid === parent.pid; }) &&
        !selected.some(function (known) { return known.pid === row.pid; });
    });
    if (!children.length) break;
    selected = selected.concat(children);
  }
  var connections = fs.readFileSync('/proc/net/tcp', 'utf8').trim().split('\n').slice(1).map(function (line) {
    var fields = line.trim().split(/\s+/);
    return {local: fields[1], remote: fields[2], state: fields[3], uid: Number(fields[7]), inode: fields[9]};
  }).filter(function (row) {
    // Keep half-closed sockets too; only TIME_WAIT/inode-zero is kernel residue.
    return row.remote.split(':')[1] === callbackHex && row.state !== '06' && row.inode !== '0';
  });
  var files = {};
  fs.readdirSync('/tmp').filter(function (name) { return name.indexOf('module-target-nodejs-') === 0; }).sort().forEach(function (name) {
    files['/tmp/' + name] = file('/tmp/' + name);
  });
  return {processes: selected.sort(function (left, right) { return left.pid - right.pid; }), connections: connections, files: files,
    selection_candidates: candidates.map(function (row) { return {pid: row.pid, command: row.command}; })};
}

if (action === 'callback') {
  var token = process.argv[4];
  require('dns').lookup('host.docker.internal', function (error, host) {
    if (error) throw error;
    var socket = require('net').connect(Number(argument), host, function () {
      socket.write(JSON.stringify({token: token, host: host, uid: process.getuid()}) + '\n');
    });
    socket.setTimeout(6000, function () { throw Error('Native callback timed out'); });
    socket.on('data', function (bytes) {
      if (bytes.toString().trim() !== 'ACK:' + token) throw Error('Native callback ACK mismatch');
      socket.end();
      console.log(JSON.stringify({host: host, uid: process.getuid(), acknowledged: true}));
    });
    socket.on('error', function (failure) { throw failure; });
  });
} else {
  var result;
  if (action === 'state') result = state();
  else if (action === 'metadata') result = {uid: process.getuid(), version: process.version, binary: file(process.execPath, false), application: file('/opt/module-target-nodejs/application.js')};
  else if (action === 'process') {
    var row = processRow(argument);
    result = row ? {exists: true, process: row} : {exists: false};
  }
  else if (action === 'file') {
    if (!/^\/tmp\/module-target-nodejs-(?:session|native)-[a-zA-Z0-9_-]+$/.test(argument)) throw Error('Unexpected task artifact path');
    if (process.argv[4] === 'remove' && fs.existsSync(argument)) fs.unlinkSync(argument);
    result = file(argument);
  } else throw Error('Unknown native observation action');
  console.log(JSON.stringify(result));
}
