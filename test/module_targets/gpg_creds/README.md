# GnuPG collection target

This opt-in profile requires native GnuPG 2.2.27 key generation, real Ed25519
sign/verify controls, protected/unprotected keys and a real account home
containing spaces. The controls follow the official [GnuPG key-management
interface](https://www.gnupg.org/documentation/manuals/gnupg/OpenPGP-Key-Management.html).
Wrong passphrases must fail after the actual agent cache is stopped. Native
prerequisites alone do not qualify the owner.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb gpg_creds
```

Ten functional cases use genuine Framework-generated shell/Meterpreter
callbacks. Each session type covers root collection and same-instance repeat,
a protected keyring in a space-containing home, ordinary-user collection,
a natively unreadable private key and genuinely absent keyrings. An explicit
empty boundary file is added after native key generation. Every collected
byte, loot metadata and PostgreSQL row is compared with the actual source
files; credential-core counts must remain zero. The permission case changes
only the private-key mode after successful native signing/verification.

The target uses digest-pinned Ubuntu 22.04 with GnuPG/gpg/gpg-agent/gpgconf
`2.2.27-3ubuntu2.5` and Python `3.10.6-1~22.04.1`. Package availability failures
are fixture failures. One serial stack uses target 512 MiB/0.5 CPU and reporting
384 MiB/0.25 CPU, equal memory/swap, PID128/init, loopback publication and a real
host Framework console. Selected account/home/package/helper/health-service
state must agree before/after. Exact keyring files/modes, session and launcher
processes, channels, payloads, markers, database rows and case selectors receive
per-case recovery checks; attached Docker objects must disappear on teardown.

Actual CLI generation supplies the key files; no opaque GPG key blobs are
checked in. Shared session controls have a separate six-case environment
regression. These tests collect raw GnuPG files and do not claim password
cracking or importing a collected key into another keyring. Other GnuPG/OS/
architecture versions, BSD/macOS, additional session transports, legacy 1.x/
2.0 layouts and transport loss remain separate qualification work. No human
module Scenarios are invented.
