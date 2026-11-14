const fs = require('fs');
const { execFileSync } = require('child_process');
const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { ListToolsRequestSchema, CallToolRequestSchema } = require('@modelcontextprotocol/sdk/types.js');
const fixture = JSON.parse(process.argv[1]);
const event = (kind, details = {}) => fs.appendFileSync(fixture.path + '.events', JSON.stringify({ kind, at: Date.now(), pid: process.pid, ...details }) + '\n');
process.on('uncaughtExceptionMonitor', error => event('uncaught', { message: error.message, stack: error.stack }));
process.on('beforeExit', code => event('before-exit', { code }));
process.on('exit', code => event('exit', { code }));
process.stdin.on('end', () => event('stdin-end'));
fs.writeFileSync(fixture.path, JSON.stringify({ marker: fixture.marker, pid: process.pid, uid: process.getuid() }), { flag: 'wx' });
const server = new Server({ name: 'module-native-control', version: '1.0.0' }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [
  { name: 'native_echo', description: 'Return controlled test text', inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] } },
  { name: 'native_command', description: 'Execute controlled lab command', inputSchema: { type: 'object', properties: { command: { type: 'string' } }, required: ['command'] } }
] }));
server.setRequestHandler(CallToolRequestSchema, async request => {
  const args = request.params.arguments || {};
  if (request.params.name === 'native_echo') return { content: [{ type: 'text', text: String(args.text) }], isError: false };
  if (request.params.name !== 'native_command') throw Error('Unknown native control tool');
  try {
    const text = execFileSync('/bin/sh', ['-c', String(args.command)], { encoding: 'utf8', timeout: 5000 });
    return { content: [{ type: 'text', text }], isError: false };
  } catch (error) {
    return { content: [{ type: 'text', text: String(error.stdout || '') + String(error.stderr || '') }], isError: true };
  }
});
server.connect(new StdioServerTransport()).then(() => {
  event('connected');
  process.stdin.on('data', chunk => event('request-bytes', { base64: chunk.toString('base64') }));
}).catch(error => { event('connect-error', { message: error.message }); process.stderr.write(String(error)); process.exitCode = 1; });
