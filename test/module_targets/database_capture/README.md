# Genuine database clients of Framework capture servers

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb capture_mysql capture_mssql
```

These profiles run the unchanged MySQL and MSSQL capture modules as real
Framework jobs. The targets are genuine Oracle MySQL 8.0.36, MariaDB 11.2.2 and
FreeTDS 1.3.17 clients on an isolated Compose network. Each first authenticates
against the corresponding digest-pinned native database fixture. No test server
substitutes for a capture module, and no host port or Docker socket is exposed.
Client dependencies are pinned only in the disposable test image.

The MySQL profile has seventeen cases. Native controls authenticate both clients
to both real server implementations with explicitly configured
mysql_native_password accounts, exact spaced usernames/database names and
space/colon/quote/backslash passwords. Empty passwords succeed natively;
rejected fixture passwords fail. Actual PCAPs distinguish the native server's
initial plugin from its authentication switch. Independent hashlib calculations
verify the actual twenty-byte native-password responses. Fixed passwords make
the capture response end in NUL or space; both bytes must remain in SQL and the
John output. A genuine native seed containing zero is also supplied as the
custom CHALLENGE, with a custom advertised server version. Other cases cover
default client TLS negotiation, no database, no credentials, empty responses, malformed challenge input and
required TLS against the module's non-TLS greeting.

The MSSQL profile has twelve cases. SQL Server 2019 build 15.0.4500.2 and its
installed sqlcmd establish native identity and account policy. FreeTDS TDS 7.1
and 7.4 then authenticate with exact LOGIN7 user/password/database fields,
including genuinely accepted empty passwords. Rejected passwords fail
natively. The fixture explicitly disables encryption for these selected
protocol paths; this does not qualify encrypted LOGIN7 or TLS listeners.
DOMAIN\\user emits genuine FreeTDS NTLM bytes. SQL Server rejects this login
as an untrusted domain because the fixture has no domain backend. The capture
profile independently verifies NTLMv1/v2 challenge responses against the known
synthetic password with PyCryptodome MD4/DES and standard HMAC, including the
extended-session negotiation option. It does not claim a valid Windows/domain
login. PRELOGIN-only and malformed challenge controls must report nothing.

Every client case restarts the listener on the same port and executes twice.
Direct SQL checks exact client address, listener port, service/protocol,
module/service origin, workspace, private bytes/type, John format, UNTRIED status
and absent validation timestamp. Ordinary credentials deduplicate; fresh NTLMv2
nonce responses remain distinct. John files must contain exactly the independently
verified lines, including repeated append behavior. Changing the console workspace
must not move a listener's captures into it. All jobs must disappear and their
owned TCP listener must close before the next case; final project and volume
removal is audited separately.

Captures are not validated logins. The installed credential model has no
persisted login proof column and ignores the proof API option. Native/wire
proof, schema and focused module proof arguments are retained separately.
See the [runner guide](../README.md) for exact counts, current input hashes,
transcripts and teardown receipts. TCP fragmentation, packet coalescence,
oversized/multi-packet logins, other authentication plugins, AD/Kerberos,
Windows clients, IPv6 and TLS listeners remain unqualified. The test-only wire
decoders inspect complete captured streams and do not repair module transport
behavior. Existing human Scenarios are unchanged.
