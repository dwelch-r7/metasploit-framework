// Independent native-file control: Node's built-in crypto, no Framework code.
import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { pbkdf2Sync, createDecipheriv, createHash } from 'node:crypto';

const [propertiesPath, flowPath] = process.argv.slice(2);
const rawProperties = readFileSync(propertiesPath);
const properties = Object.fromEntries(rawProperties.toString().split(/\r?\n/).filter(line => line && !line.startsWith('#')).map(line => {
  const separator = line.indexOf('=');
  return [line.slice(0, separator), line.slice(separator + 1)];
}));
if (properties['nifi.sensitive.props.algorithm'] !== 'NIFI_PBKDF2_AES_GCM_256') throw new Error('Unexpected native NiFi algorithm');
const key = pbkdf2Sync(properties['nifi.sensitive.props.key'], 'NiFi Static Salt', 160000, 32, 'sha512');
const rawFlow = readFileSync(flowPath);
const flow = JSON.parse(gunzipSync(rawFlow));
const decrypted = [];
function visit(value, path = []) {
  if (typeof value === 'string' && value.startsWith('enc{')) {
    if (!/^enc\{(?:[0-9a-f]{2}){32,}\}$/.test(value)) throw new Error('Unexpected native encrypted field format');
    const data = Buffer.from(value.slice(4, -1), 'hex');
    const decipher = createDecipheriv('aes-256-gcm', key, data.subarray(0, 16));
    decipher.setAuthTag(data.subarray(-16));
    const plaintext = Buffer.concat([decipher.update(data.subarray(16, -16)), decipher.final()]).toString('utf8');
    decrypted.push({ path, ciphertext: value, plaintext });
    return;
  }
  if (Array.isArray(value)) return value.forEach((item, index) => visit(item, [...path, index]));
  if (value && typeof value === 'object') Object.entries(value).forEach(([name, item]) => visit(item, [...path, name]));
}
visit(flow);
console.log(JSON.stringify({ algorithm: properties['nifi.sensitive.props.algorithm'], iterations: 160000, properties_sha256: createHash('sha256').update(rawProperties).digest('hex'), flow_sha256: createHash('sha256').update(rawFlow).digest('hex'), decrypted }));
