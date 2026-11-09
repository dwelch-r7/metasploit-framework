# Linux credential file collection

From the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb credential_files_ssh credential_files
```

The six-case SSH profile covers `post/multi/gather/ssh_creds` through genuine
root and nonroot shell/Meterpreter sessions. The six-case configuration profile
covers `post/multi/gather/docker_creds` and `post/multi/gather/rubygems_api_key`
through their declared shell sessions. Each collection repeats, while missing
and empty collection states exercise the no-data paths. Both profiles use fresh
targets, databases and console configuration, with normal metadata-only reuse
within one invocation. Registration alone does not qualify a module.

Targets use digest-pinned Ruby 3.3.13 Bookworm, Docker CLI 27.5.1, Docker
Distribution 2.8.3 and the existing PostgreSQL 16 reporting fixture. The target
dependency Gemfile/lock pins Gemstash 2.8.2 and its dependencies; its published
gem checksum is verified during the build. These are target dependencies,
separate from Framework's bundle. The shared Linux session launcher and
acceptance context generate and run actual Framework ELF payloads; no session
or service response is simulated. No Docker socket is mounted.

Native account tools create root, `labuser` with real home `/home/lab user`,
and denied, empty and missing-data accounts. Native `ssh-keygen` generates
unencrypted RSA PEM keys; OpenSSH authenticates them against the owned sshd.
The native Docker client writes actual base64-backed `config.json` data after
local registry login, including valid colon-containing passwords. The registry
accepts full passwords and rejects truncated ones. Native logout produces an
empty authentication map; the client also accepts the test's zero-byte config.

RubyGems 3.5.22 writes credentials using `Gem::ConfigFile`, exercising both the
legacy path and the default XDG path, with a multi-key legacy file. Its native
client pushes, fetches exact package bytes and yanks an owned private gem from
real Gemstash. Protected fetching rejects an invalid key. File snapshots under
actual root/nonroot identities verify readable, denied, empty and missing
states before invoking Framework. No real registry, cloud account or API key
is used. Fixture passwords and generated keys are disposable test data.

The RubyGems paths and formats follow its installed client source and the
[official configuration guide](https://guides.rubygems.org/configuration/).
See [API key usage](https://guides.rubygems.org/api-key-scopes/),
[Gemstash private gems](https://github.com/rubygems/gemstash/blob/main/docs/gemstash-private-gems.7.md)
and [Docker login storage](https://docs.docker.com/reference/cli/docker/login/).
Native producer outputs retain exact client versions, source hashes, commands,
HTTP responses and raw fixture bytes.

The ordinary `db_connect` command migrates a separate empty Framework database.
Direct psql queries check actual credential cores, private/public values,
realms, imports and session origins; no ORM or completion banner is an oracle.
Recovered database keys/passwords are replayed against native local SSH/registry
authentication. Recovered RubyGems loot is replayed through the actual client,
with exact package fetching and yanking. Raw SSH loot bytes are compared to
native files, and repeated collection must not change those files or duplicate
credential records. Temporary no-data states are restored in an ensure block.

Only a random loopback health port is published; SSH, registry, Gemstash,
reporting DB and reverse-session listeners remain within isolated containers.
The [shared guide](../README.md) describes exact counts, input fingerprints,
console/native traces and owned resource teardown. Other operating systems,
CPU architectures, encrypted/other SSH key formats, credential stores/helpers,
custom XDG locations and real external account authentication remain outside
these profiles. Existing module scenarios are not fabricated or replaced.
