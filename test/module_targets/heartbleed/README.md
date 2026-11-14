# OpenSSL Heartbleed module lab

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb heartbleed
```

The runner owns one fresh Compose project with three containers: the target,
Framework and its reporting database. Target ports publish on loopback with
dynamic host ports. Memory, swap, CPU and process limits apply to every service.
The runtime memory caps total 1,152 MiB, with 2.2 CPUs in service limits and no
additional swap allowance. The runner retains evidence under
`tmp/module-target-tests/` and removes its containers, network and disposable
database state after each run. The guarded
launcher refuses to start while another container or guarded invocation exists.

## Source and target identity

`releases.json` pins official OpenSSL repository commits and the SHA-256 of their
GitHub commit archives. These are release-tag source snapshots, rather than the
original vendor distribution tarballs. The recipe builds these variants serially:

| SDK | Purpose | Ordinary TLS port | Conditioned heap port |
| --- | --- | --- | --- |
| 1.0.1d | The affected release in the existing module guide | 10000 | 11000 |
| 1.0.1f | The final affected 1.0.1 release | 10100 | 11100 |
| 1.0.1g | The fixed release | 10200 | 11200 |
| 1.0.1f with `OPENSSL_NO_HEARTBEATS` | The published compile-time workaround | 10300 | 11300 |

The base image is pinned by digest. Builds use `no-shared`, `no-asm`, `no-ssl2`
and `-fcommon` to build the historical sources with the container's compiler.
`build.json`, package lists and separate SDK/application binary manifests record
the resulting artifacts. No OpenSSL heartbeat source is changed. Package lists
record the exact packages used; apt repository contents can change on a rebuild.

The [OpenSSL advisory](https://openssl-library.org/news/secadv/20140407.txt)
describes the affected 1.0.1 releases, 1.0.1g fix and compile-time workaround.
[RFC 6520 section 4](https://www.rfc-editor.org/rfc/rfc6520#section-4) defines
the heartbeat type, payload length and padding used by the independent clients.

## Genuine responses and key recovery

The ordinary providers run unchanged upstream `openssl s_server -www`. Independent
clients verify complete normal TLS handshakes, correctly formed heartbeat echoes
and malformed requests against affected, fixed and disabled providers. The clients
use Python's standard library and the pinned SDKs; they never call Framework.

`s_server` buffers output during its incomplete handshake. A native control sends
a small valid heartbeat followed by a larger one and verifies both exact echoes.
For a 65,535-byte malformed request it ordinarily flushes four 16,384-byte record
bodies, leaving 65,533 payload bytes after the three-byte heartbeat header. The
suite compares the module's partial loot with the bytes from that same connection.

Private key exposure in an ordinary server's heap is not deterministic. The
separate source-available `conditioned_server.c` application makes the exposure
condition explicit. Through OpenSSL's public `CRYPTO_set_mem_functions` API it
appends accessible slack to TLS-sized allocations and places a freshly generated,
disposable RSA factor in that process memory. All heartbeat parsing and response
generation remain inside the linked SDK. The application honors SSL retry results
and flushes the handshake BIO, including its last short response fragment.

The same application runs against all four SDK variants. Affected libraries must
leak the factor; fixed and disabled libraries must reject the malformed request
despite the same heap layout. The `KEYS` test reads the module's persisted key and
uses it to sign a challenge verified with the independently observed certificate.
A one-byte leak tests bounded unsuccessful recovery: it cannot contain a factor
of the disposable 2,048-bit RSA modulus. This fixture verifies module behavior
under controlled exposure; it does not measure production key exposure frequency.

## Transport and certificate matrix

An additional unchanged `s_server` on port 12000 uses a disposable ECDSA
certificate. Its native client verifies both a full TLS handshake and genuine
heartbeat exposure. The owning module must still dump memory, while RSA key
recovery must decline this unsupported certificate without a runtime exception.

The STARTTLS services are small transport adapters in `starttls.py`. They validate
the upgrade dialog and forward TLS bytes to a real ordinary SDK provider. They do
not generate heartbeat responses. These cover module transport negotiation, not
full production mail, XMPP, FTP or database applications.

| Dialog | Affected 1.0.1f port | Fixed 1.0.1g port |
| --- | --- | --- |
| SMTP | 10400 | 11400 |
| IMAP | 10500 | 11500 |
| XMPP (`JABBER`) | 10600 | 11600 |
| POP3 | 10700 | 11700 |
| FTP | 10800 | 11800 |
| PostgreSQL | 10900 | 11900 |

The ordinary and conditioned providers, adapters, ECDSA provider and unrelated
standard-library HTTP server share the single target container. Adapter ports are
internal to the lab network. The unrelated HTTP server on port 2525 independently
answers a normal HTTP request and supplies the non-TLS negative case.

## Functional assertions and evidence

The owning module is selected and executed through public console `check` and
`run` commands. Its methods, socket behavior, loot storage and reporting are not
replaced. Cases repeat to exercise fresh connections and per-run state.

The matrix covers `SCAN`, `DUMP` and `KEYS`; all four advertised SSL/TLS versions;
multiple leaks; complete and partial fragmented responses; matching and empty
filters; fixed/disabled targets; refused and unrelated services; separate reports
for two ports on one host; ECDSA; integer boundaries; and six STARTTLS dialogs.

The existing Framework `NET_RAW` capability observes only its own container's
traffic. Capture buffers include the Ethernet header for a maximum-sized IPv4
packet. Observers retain TCP sequence numbers and base64-encoded bytes, including
PostgreSQL's binary upgrade prefix. Reassembled heartbeat payloads are compared
byte-for-byte with the owning module's persisted loot. Native PostgreSQL queries
verify actual vulnerability and loot rows in isolated per-case workspaces.

The full native matrix runs before the module cases. Afterward, a shorter pass
rechecks all providers, fixed/disabled rejection, each STARTTLS dialog, ECDSA,
full normal TLS handshakes and binary identity. Repeating every TLS-version and
payload-boundary permutation afterward adds time without covering a new path.
Independent native controls therefore still bracket the module cases. Service
process identities and connections are checked between cases; final cgroup
counters detect memory or process-limit pressure. The runner records a fresh
console configuration, metadata provenance, selected input hashes, image IDs,
console output and cleanup results.

Coverage is representative. It does not establish every affected release,
compiler, architecture, cipher, certificate size/chain, TLS handshake fragmentation
pattern, proxy, real STARTTLS application configuration or XMPP domain discovery
path. The existing module guide's human-written `Scenarios` remain unchanged.
