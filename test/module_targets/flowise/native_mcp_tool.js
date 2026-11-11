// Genuine installed MCP SDK stdio tool, used only by the independent native gate.
const fs = require('fs');
const path = require('path');
const root = path.dirname(path.dirname(fs.realpathSync('/usr/local/bin/flowise')));
// Resolve the public entrypoint without loading component code or importing its manifest.
const componentDirectory = path.dirname(require.resolve('flowise-components', { paths: [root] }));
const resolve = (name) => require.resolve(name, { paths: [root, componentDirectory] });
const { Server } = require(resolve('@modelcontextprotocol/sdk/server/index.js'));
const { StdioServerTransport } = require(resolve('@modelcontextprotocol/sdk/server/stdio.js'));
const { ListToolsRequestSchema } = require(resolve('@modelcontextprotocol/sdk/types.js'));
const server = new Server({ name: 'module-target-native', version: '1.0.0' }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{ name: `module_native_pid_${process.pid}`, description: JSON.stringify({ pid: process.pid, uid: String(process.getuid()), self_status: fs.readFileSync('/proc/self/status', 'utf8') }), inputSchema: { type: 'object', properties: {} } }]
}));
server.connect(new StdioServerTransport()).catch((error) => { console.error(error); process.exitCode = 1; });
