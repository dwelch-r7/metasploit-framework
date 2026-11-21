# Sudo chroot default root callbacks

```sh
MODULE_TARGET_NAMESPACE=my-sudo-callback-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb sudo_chroot_sessions sudo_chroot_sessions_fixed
```

These serial profiles reuse the genuine affected/fixed builds and independent
compiler/NSS prerequisites in the [finite-command profiles](../sudo_chroot/README.md).
One target uses128MiB RAM/swap,0.5CPU,64PIDs, read-only root and bounded tmpfs.
Default Docker capabilities suffice; no privileged mode or published service
port is used. Every exit removes its namespaced stack.

Both real entry APIs are tested. Before any owner run, the actual default fetch
and staged Meterpreter producer/handler creates native UID1001 callbacks using
explicit /tmp and true default ./ destinations. Public
session APIs and independent physical UID/bytes/PID/cwd evidence must qualify it.
A cold original local-module selection must choose
`cmd/linux/http/x64/meterpreter/reverse_tcp` with `AllowNoCleanup=false`. The
payload is never explicitly selected for the owner. Two affected root callbacks
then use AutoCheck on/off on the same selection, with the second call retaining
the default relative fetch directory. Captured real wrapper bytes verify the
effective destination. Fixed controls retain AutoCheck
and refuse both owning bodies.

New sessions must provide actual UID0 proof, usable getwd/relative-directory
APIs, a physical existing cwd in the configured WritableDir and graceful shutdown
with exact PID disappearance. The independent /proc observer uses matching
process credentials, records the actual executable bytes/hash/UID, and needs no
extra ptrace capability.
The original entry must preserve identity/cwd, module staging cleanup must
complete, and the full final process/socket/config/tmp state must preserve.
Default `FETCH_DELETE=false` leaves a known absent-before ELF; its captured
explicit removal is lab reset, separate from module wrapper/NSS cleanup. Entry
fixture reset is also recorded separately after strict assertions.

Registration is not a passing verdict. Retain native, harness, module and
preservation failures separately. Wider payloads, paths, compiler denials,
distro/backport/release boundaries and reporting databases remain further work.
