import { readFileSync } from 'node:fs';
import { pbkdf2Sync, createCipheriv } from 'node:crypto';

const fixture = (name) => new URL(name, import.meta.url);
const properties = readFileSync(fixture('nifi.properties'), 'utf8');
const secret = properties.match(/^nifi\.sensitive\.props\.key=(.+)$/m)[1];
const key = pbkdf2Sync(secret, 'NiFi Static Salt', 160000, 32, 'sha512');
const nonce = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
const plaintext = 'Café "quoted" ' + String.raw`\1 \& \\ $1` + '\nnext line';
const cipher = createCipheriv('aes-256-gcm', key, nonce);
const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
const flow = JSON.parse(readFileSync(fixture('flow.json'), 'utf8'));
const index = flow.rootGroup.processors.findIndex((item) => item.type === 'org.apache.nifi.processors.standard.GetHTTP');
if (index < 0) throw new Error('Native GetHTTP processor absent');
console.log(JSON.stringify({
  kind: 'Derived Node built-in crypto encoding control, not a native vendor capture',
  path: ['rootGroup', 'processors', index, 'properties', 'Password'],
  plaintext,
  encrypted: `enc{${nonce.toString('hex')}${ciphertext.toString('hex')}${cipher.getAuthTag().toString('hex')}}`,
}, null, 2));
