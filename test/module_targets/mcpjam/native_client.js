// Independent HTTP/filesystem/process observations inside the real target.
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const args = JSON.parse(process.argv[1]);
const hash = data => crypto.createHash('sha256').update(data).digest('hex');
const emit = value => console.log(JSON.stringify(value));
if (args.action === 'http') {
  const data = args.body == null ? null : Buffer.from(JSON.stringify(args.body), 'utf8');
  const headers = { 'Content-Type': 'application/json', ...(args.headers || {}) };
  if (data) headers['Content-Length'] = data.length;
  const start = process.hrtime.bigint();
  const request = http.request({ hostname: args.host || '127.0.0.1', port: 6274, path: args.path, method: args.method || (data ? 'POST' : 'GET'), headers }, response => {
    const chunks = [];
    response.on('data', chunk => chunks.push(chunk));
    response.on('end', () => {
      const body = Buffer.concat(chunks);
      let document;
      try { document = JSON.parse(body); } catch {}
      emit({ status: response.statusCode, headers: response.headers, body_base64: body.toString('base64'), body_sha256: hash(body), document, seconds: Number(process.hrtime.bigint() - start) / 1e9 });
    });
  });
  request.setTimeout(20000, () => request.destroy(Object.assign(new Error('Native HTTP timeout'), { code: 'NATIVE_TIMEOUT' })));
  request.on('error', error => emit({ transport_error: error.code, message: error.message }));
  if (data) request.write(data);
  request.end();
} else if (args.action === 'metadata') {
  const packageInfo = JSON.parse(fs.readFileSync('package.json'));
  const sdk = JSON.parse(fs.readFileSync('node_modules/@modelcontextprotocol/sdk/package.json'));
  const executables = {};
  for (const name of ['node', 'wget', 'sh', 'bash', 'python3', 'nc', 'perl']) {
    executables[name] = null;
    for (const directory of (process.env.PATH || '').split(':')) {
      const candidate = require('path').join(directory, name);
      try { fs.accessSync(candidate, fs.constants.X_OK); executables[name] = candidate; break; } catch {}
    }
  }
  emit({ version: packageInfo.version, node: process.version, uid: process.getuid(), sdk_version: sdk.version,
    bundle_sha256: hash(fs.readFileSync('dist/server/index.js')), sdk_bundle_sha256: hash(fs.readFileSync('sdk/dist/index.js')), executables });
} else if (args.action === 'processes') {
  const rows = [];
  for (const name of fs.readdirSync('/proc').filter(name => /^\d+$/.test(name))) {
    const pid = Number(name);
    if (pid === process.pid) continue;
    try {
      const stat = fs.readFileSync('/proc/' + name + '/stat', 'utf8');
      const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
      const uid = Number(fs.readFileSync('/proc/' + name + '/status', 'utf8').match(/^Uid:\s+(\d+)/m)[1]);
      rows.push({ pid, ppid: Number(fields[1]), start: fields[19], uid, state: fields[0], argv_base64: fs.readFileSync('/proc/' + name + '/cmdline').toString('base64') });
    } catch (error) { if (!['ENOENT', 'ESRCH'].includes(error.code)) throw error; }
  }
  emit(rows.sort((left, right) => left.pid - right.pid));
} else {
  if (typeof args.path !== 'string' || !args.path.startsWith('/tmp/module-target-mcpjam-')) throw Error('Unowned native file path');
  if (args.action === 'exists') emit(fs.existsSync(args.path));
  else if (args.action === 'unlink') { fs.unlinkSync(args.path); emit(true); }
  else if (args.action === 'read') {
    const data = fs.readFileSync(args.path);
    emit({ base64: data.toString('base64'), sha256: hash(data), uid: fs.statSync(args.path).uid });
  } else throw Error('Unknown native action');
}
