# Native SIP targets

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb sip sip_enumeration sip_capture asterisk_login
```

The four bounded profiles contain 18 OPTIONS, 14 enumeration/deregistration,
seven capture, and three Manager authentication cases. Discovery, enumeration,
authentication and ordinary capture operations repeat. The collision case holds
one exclusive owner, releases it, then requires genuine authentication capture.
They use genuine Asterisk 18.10.0, sipsak 0.9.8.1 and SIPp 3.6.1 on a digest-pinned
Ubuntu 22.04 base. The Asterisk package version is explicit in the Dockerfile;
other package versions and image IDs are retained by the probes and runner.
The reporting database and unrelated BIND daemon reuse existing pinned targets.
No Framework dependency, session helper or runner change is required.

All identities and secrets are public artificial fixtures. There are no trunks,
external registrations, phones or media routes. The private project bridge contains
only owned targets; published ports bind randomly to loopback. Docker supplies
ordinary outbound routing so loopback publication can work. The fixtures use no
outside SIP destinations, trunks or registrations. An internal-only bridge does
not publish the requested ports on Docker Engine 29; that original setup failure
is retained separately. No host sockets,
mounts, networking or privileged mode are used. Both SYS_ADMIN and SYS_TIME are
dropped and checked. The daemons run as the package's `asterisk` user.

Two accounts exist: `1000` has no registration secret; `1001` uses
`module-target-sip-password`; `1002` is absent. The exposed server uses ordinary
unauthenticated OPTIONS and distinguishes an unknown REGISTER account. The
protected server enables `alwaysauthreject` and `auth_options_requests`, which
can return the same 401 to real and absent accounts. These are genuine
[upstream policy options](https://github.com/asterisk/asterisk/blob/18.10.0/configs/samples/sip.conf.sample).
A 401 enumeration result is a challenge candidate, not validated account
existence. Likewise, OPTIONS 200 does not prove password-free registration.
Native CLI account lists, actual accepted/rejected Digest authentication and
real SIP responses establish these distinctions before module assertions.

UDP, TCP and the TCP mixin's TLS path are exercised. The lab builds an artificial
self-signed certificate. Native OpenSSL/SSL API controls verify its chain and
name using that fixture certificate and reject it with ordinary system trust.
Framework positive TLS cases explicitly select `SSLVerifyMode=NONE`; another
case records an inherited Rex 0.1.71 limitation: its PEER callback returns true
for an untrusted certificate, so PEER is observational here and does not enforce
chain trust. The ordinary OpenSSL rejection, explicitly trusted control and actual
Rex reply use the same certificate. Even Rex's eventual `peer_verified=true` and
`verify_result=0` are not evidence of enforced trust. Installed source identity
and callback location are retained. No host trust store is changed.
sipsak's TLS receive/select failure is retained as an external client limitation;
TLS application responses are independently obtained from the real Asterisk
through the standard SSL/socket API. Successful UDP/TCP flows also use both
genuine SIP CLI implementations.

REGISTER enumeration changes real registration state on the open account.
Tests preserve the observed before/after state, then explicitly restore it with
an authorized native unregister before the next iteration. Deregistration cases
seed a real binding first on a separate permissive Asterisk service and distinguish
successful removal from authentication refusal. Only that service adds
`pedantic=no`; exposed/protected configurations retain their original bytes.
Native controls prove default pedantic mode drops the module's legacy untagged
REGISTER without a reply or state change. In permissive mode the identical
request removes account 1000 and challenges account 1001. These cases explicitly
bind the module's registered `CPORT=5060`, matching its bare Via default port;
native ephemeral-port controls show responses go to the separately advertised
5060 owner otherwise. No shared framing or NAT behavior is changed. The state oracle reads genuine SIPshowpeer, DBGet and CoreShowChannels
Manager actions, cross-checked against CLI controls. Raw frames, historical
Reg-Contact text and observation times remain visible. Inactive means no address
or port, no expiry timer, no registry key and no channel. Native Asterisk retains
historical contact text after unregister; it is not silently treated as a live
registration or erased. CLI Expire is a scheduler ID; Manager RegExpire is a
remaining-seconds observation, compared with its native timing resolution.

Capture uses genuine clients against the actual Framework UDP service, verifies
Digest inputs cryptographically, and checks direct database service/origin/hash
context, optional John bytes, repeat behavior, no-auth negatives, an exclusive
native UDP bind collision and physical bind availability after cleanup. The
exclusive socket has address reuse disabled; two Rex UDP owners can otherwise
share a port on Linux. A genuine client also verifies capture after its release.
Captures are UNTRIED
nonreplayable responses, not recovered plaintext passwords. Invalid or
unsupported Digest input is challenged without inventing credentials. The focused
corpus covers omitted MD5, absent qop, the supported qop=auth format and malformed
field controls. John file assertions
allow genuine SIP retransmissions while requiring every complete output line to
match the exact captured hash. The [optional pinned John control](JOHN.md) independently recovers the known
artificial password from the four actual captured records and checks the required
URI field layout. A qop=auth upstream known vector is checked separately. Other
Digest algorithms, live qop negotiation and Proxy-Authorization client behavior
remain unqualified.

The Manager login profile uses public `module_manager` /
`module-target-manager-password` credentials on TCP 5038 and verifies accepted,
wrong-password and absent-user paths with real service/credential reporting.
SIP discovery output and export notes are compared with native responses;
credential and note rows are read through the actual disposable database APIs.
The current credential-login schema does not store the supplied `proof` option;
authentication proof remains in the real Manager TCP exchanges and capture
files. Tests reuse the existing TCP reassembler and model note serializer.
Passive tcpdump observers retain the real owned signaling without changing it.

For quick UDP scans most cases select the module's registered
`ScannerRecvWindow=1`; one case retains its 15-second default. Existing runner,
console and protocol timeouts remain unchanged. IPv6, SIP proxies, media/calls,
Manager TLS and other server implementations remain outside this profile.

Firmware-specific Grandstream, old Android SIPdroid and legacy Windows endpoint
modules need their own genuine targets. The module audit records their individual
requirements; generic Asterisk responses do not qualify them. Invite spoofing
requires a real receiving user agent and ringing/caller-ID evidence. The AMI
credential-gatherer also needs its own compatible SIP/IAX target and full-secret
proof: this Asterisk's CLI reveals only a 15-character secret prefix, and native
authentication rejects that prefix. These paths are not represented as passed.
