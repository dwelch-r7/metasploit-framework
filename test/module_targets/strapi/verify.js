// Verify the original authentication/query sources before using a dependency cache.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const [version, root] = process.argv.slice(2);
const digest = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

try {
  const expected = require('./vendor.json')[version];
  if (!expected) throw new Error('Unsupported Strapi release');
  const inputs = path.join(__dirname, 'packages', version);
  for (const name of ['package.json', 'package-lock.json']) {
    if (digest(path.join(root, name)) !== digest(path.join(inputs, name))) {
      throw new Error(`Dependency input differs: ${name}`);
    }
  }
  const packages = JSON.parse(fs.readFileSync(path.join(inputs, 'package.json'))).dependencies;
  for (const name of Object.keys(packages)) {
    const installed = JSON.parse(fs.readFileSync(path.join(root, 'node_modules', name, 'package.json')));
    if (installed.version !== packages[name]) throw new Error(`Incorrect package version: ${name}`);
  }
  for (const [name, sha256] of Object.entries(expected.source_sha256)) {
    if (digest(path.join(root, 'node_modules', name)) !== sha256) {
      throw new Error(`Original vendor source differs: ${name}`);
    }
  }
  console.log(JSON.stringify({verified: true, version, node: process.version,
    source_files: Object.keys(expected.source_sha256).length,
    lock_sha256: digest(path.join(root, 'package-lock.json'))}));
} catch (error) {
  console.log(JSON.stringify({verified: false, version, reason: error.message}));
  process.exitCode = 1;
}
