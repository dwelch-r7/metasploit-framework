These files come from genuine Apache NiFi 1.21.0 in the disposable
`nifi_credentials` lab, invocation `20261110T113803-8848a1`. Its original
module SHA256 was
`cda059b0ce5971a689626ed8c65f03282727bde79c9e6828c511c084418847bc`.
The complete original console/native/SQL/loot records are retained separately.

`nifi.properties`, `login-identity-providers.xml`, `authorizers.xml` and
`crypto.json` are byte-identical to their named capture files.
`flow.json` is the captured `native-flow.json.gz` after gzip decompression only.
`provenance.json` records every source and fixture hash, native keytool store
entries, actual identity and stored-secret values. `crypto.json` was produced
independently from the vendor ciphertext using host Node's built-in
PBKDF2-SHA512/AES-256-GCM, then checked against API-configured plaintext and
the actual GetHTTP authentication control. All credentials belong to this
destroyed disposable fixture; they are not operator or external-service secrets.

The native database password contains both quotes and a backslash. The
private-key entry and trust certificate reside in separate PKCS12 files.
These captures exercise JSON escaping, store association, exact secret
collection and truthful session-origin credential reporting. The vendor
authorizers file contains no configured Azure client secret, so this fixture
does not qualify that authorizer branch or external Azure authentication.

`derived-utf8-secret.json` is a separate Node built-in crypto encoding control,
not a captured vendor configuration. It replaces only the actual GetHTTP
password field with Unicode, quotes, newlines and literal substitution escapes.
Its deterministic nonce is solely a unit-fixture input. The native crypto
parameters and key are retained. Run the adjacent `derive-utf8-secret.mjs`
with Node to reproduce the exact JSON fixture; it uses only built-in crypto.

The specs also derive identity-only, missing-key, missing-algorithm,
unsupported-algorithm, empty/unreadable-file, empty-component and corrupt-tag
boundaries from these files. The corrupt-tag case flips one authentication-tag
hex character; it is not claimed to be a NiFi-accepted live flow. The actual
native lab independently exercises its file-based corrupt-tag boundary.

Credential API calls are checked without a database. The functional lab checks
real shell and Meterpreter sessions, repeated runs, actual loot, and independent
SQL session/workspace origins. Stored secrets are not treated as authenticated
service logins, and filenames are not asserted to be account usernames.
