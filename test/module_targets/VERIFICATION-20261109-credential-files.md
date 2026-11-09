# Linux credential-file qualification

The selected checkpoint covers **117 runtime modules, 52 families and 730
functional cases**. Every selected profile has exact counts, zero failures,
pending or outside errors, current recorded input hashes and owned teardown.
This adds three modules and twelve cases to the
[preceding checkpoint](VERIFICATION-20261109-jboss-sessions.md). The broader
goal remains active. No PR was created or full local RSpec suite run.

## Real collection and authentication

The [reusable lab](credential_files/README.md) provides two bounded six-case
profiles. SSH collection covers both declared shell and Meterpreter types;
Docker and RubyGems collection cover their declared shell type. Root/nonroot
collection, a real spaced home path, denied files, entirely missing/empty inputs,
repeated collection, exact loot and SQL values, and unchanged source files are
required. Twelve actual Linux x64 sessions complete 32 module executions.

Native OpenSSH generates/authenticates the RSA keys. Docker CLI 27.5.1 writes
the real login configuration for Distribution 2.8.3, whose authentication accepts
the full colon-containing password and rejects its truncated prefix. RubyGems
3.5.22 writes legacy/default-XDG credentials and uses Gemstash 2.8.2 for actual
private package push, exact-byte fetch and yank. These are disposable local
services, with no Docker socket or external account. Target gems remain isolated
from Framework dependencies.

Each profile passes 22 independent native commands and ten HTTP checks before
Framework runs. Recovered values subsequently pass **16 SSH, eight Registry and
eight RubyGems authentications**. All eight database SSH private keys match the
native originals byte for byte. The cases compare all 92 SSH loot files and
eight RubyGems key files with native bytes. Direct SQL checks usernames, complete
passwords/keys, realms, source paths, workspaces and actual session origins;
repetition must not duplicate records. RubyGems retains loot-only reporting.

## Captured failures and separate repairs

The original invocation `20261109T211148-a0e6eb` completes SSH **6/4** and
configuration **6/5**, with native controls and teardown passed. Three focused
owning repairs address independently confirmed failures:

- SSH's unquoted directory listing fails for the spaced home, and home basenames
  produce unusable reported account names. Reusing session escaping and Unix
  account metadata fixes both, retaining basename fallback for unlisted homes.
- Docker splits every colon, truncating a password that the real Registry
  rejects. Splitting once preserves it; read/empty guards handle unavailable
  files and the zero-byte configuration accepted by the actual Docker client.
- RubyGems' colon-based extraction includes YAML quoting/host fragments in the
  recovered key, and unreadable legacy data prevents reaching the default XDG
  file. Safe YAML parsing preserves exact default/named string values; both
  default paths are searched and unavailable files skipped.

The unchanged profiles in `20261109T212409-f8ff82` complete SSH **6/0** in
319.149899 seconds and configuration **6/0** in 272.528441 seconds, with no
pending/outside errors and teardown passed. Only their respective owning module
source bytes change; fixture/spec assertions remain frozen. Random order and
disposable native values differ between invocations and are retained explicitly.
No shared production library or project dependency changes.

Original focused runs reproduce SSH 15/3 and configuration 23/10, including
seven shared examples in each invocation. Combined repaired checks pass **31/0**,
including 24 owning examples and seven shared examples. The parent independently
reruns those 31 examples with zero failures/pending/outside errors. Changed Ruby
lint and all three module tidy checks pass.

## Retention and limits

The parent imports and byte-checks all 291 regular files from the combined final
invocation, including hidden snapshots, and verifies all 55 SSH and 53
configuration recorded hashes against integrated source. All **605** checksums
in `credential-file-validation-20261109-4c263bebb99` independently match. It
retains original/repaired runs, native setup mistakes, source snapshots, four
separate commits, focused checks and the actual SQL/loot/authentication captures.
Both final projects and all six recorded volumes independently audit absent.

Linux x64 and the captured client versions are qualified. Other platforms,
architectures, encrypted/other SSH key formats, credential helpers, custom XDG
paths and real external accounts remain unqualified. Modern prefixed RubyGems
keys and named-key fallback have parser coverage; real service authentication
here is Gemstash. Debian package sources remain build-time inputs. No human
module Scenarios were invented.

Aggregate selector: `tmp/module-target-checkpoint-credential-files-current.json`;
its sole warning is the unqualified WordPress admin reproducer. Hashes cover
declared inputs, not the entire dependency graph. Ansible deployment and Erlang
execution remain separate investigations. On the preceding public `a609a6423f6`
revision, Lint and seven acceptance workflows pass, Meterpreter is queued, and
Verify fails on the previously observed certificate/SID OpenSSL error. Its log
also retains a background RSpec mock-lifecycle exception; causality remains
unclassified. New publication CI must be inspected independently.
