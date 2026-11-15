# Erlang OTP SSH execution lab

These profiles use genuine digest-pinned Erlang OTP slim images and the vendor
`ssh:daemon` implementation. No SSH library code is patched. OTP 27.3.2 / SSH
5.2.9 and OTP 27.3.3 / SSH 5.2.10 straddle the
[vendor fix](https://github.com/erlang/otp/security/advisories/GHSA-37cp-fgq5-7wc2).
The target uses one strict disposable password account, rather than a callback
that accepts every password. Host keys, proof files and reporting data are
ephemeral. The non-root profile runs the same daemon as UID/GID 1000.

Run one profile at a time from the Framework root:

```sh
export DOCKER_CONTEXT=default BUILDX_BUILDER=default
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb erlang_ssh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb erlang_ssh_nonroot
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb erlang_ssh_fixed
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb erlang_ssh_versionless
```

The versionless profile uses the vendor's
[`id_string` option](https://github.com/erlang/otp/blob/OTP-27.3.2/lib/ssh/src/ssh_options.erl)
and requires an explicit ForceExploit because passive detection has no version.
All images run as linux/amd64 to match the module's Linux x64 default payload.
The apt-installed curl/CA packages support its HTTPS fetch transport; installed
versions are observable in build logs, but apt repositories are not snapshot
locked. Other OTP branches, architectures and operating systems remain outside
this fixture's runtime scope.

Each stack has three containers: target 0.5 CPU / 384 MiB / 128 PIDs, Framework
1 CPU / 768 MiB / 256 PIDs, and PostgreSQL 0.5 CPU / 256 MiB / 128 PIDs. Swap
cannot exceed those memory caps. Exposed ports bind random loopback ports.
The disposable target tmpfs explicitly permits execution for the native fetch
payload; a noexec mount is not a compatible target for that delivery family.
Framework mounts the checkout read-only and keeps isolated configuration and
artifacts. The guarded launcher serializes stacks and tears down project
containers, networks and volumes on success or failure.

Before any owning-module call, independent controls verify exact OTP/SSH
versions and the vendor `ssh_connection.beam` hash, reject a wrong password,
authenticate and execute normally, then send independent RFC 4253/4254-framed
preauthentication requests, including independent Unicode codepoint escapes.
Affected targets must create exact nonce files;
fixed targets must reject the same requests without files and still accept
ordinary authenticated execution. Captures retain raw packet bytes and decoded
message numbers. Receiving a KEXINIT is never execution proof. These controls
repeat after the module suite.

The real multi/handler first generates each default payload and the fixture
launches those already-generated command bytes natively inside the target.
Both the HTTPS fetch x64 Meterpreter and reverse Bash session must bootstrap,
write a nonce through their actual session API, expose the expected target
PID/UID, close their remote processes, and persist a closed SQL session record.
This calibration verifies delivery prerequisites independently of the exploit.

Functional cases then invoke the public module check/run paths. They cover
quoted commands, literal backslashes, UTF-8 (including non-BMP and decomposed
characters), both actual target/payload families,
AutoCheck enabled/disabled, repeated use of the selected module, configured
client identification, fixed rejection, a refused port and a real unrelated
PostgreSQL service. Successful execution requires independent target-side file
and process evidence. Session/job/fetch cleanup and OOM/PID counters are checked.
The passive run observer preserves effective command bytes as Base64 without
changing the executing datastore. The focused unit suite additionally verifies the configured identification bytes
sent on the wire. No owning method, network reply or session is substituted.

Recorded results, original defects, harness corrections and remaining limits
are maintained in the [verification record](../VERIFICATION-20261115-erlang-ssh.md).
A run requires all nine functional cases to pass. The existing human module
guide is preserved.
