# Forgejo org-mode file reads

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb forgejo_15_0_5 forgejo_15_0_6 forgejo_16_0_1 forgejo_16_0_2 forgejo_unrelated
```

These serial profiles exercise genuine Forgejo releases, their real markup API,
and Framework's public module entry points. Their manifests/configs and release
commits are pinned in [profiles.json](profiles.json). The 15.x pair uses vendor
images. The 16.x registry indexes currently reference missing amd64 manifests;
[release.Dockerfile](release.Dockerfile) retains the vendor runtime and installs
the genuine release binary, checking both compressed and uncompressed SHA256.
It adds no replacement HTTP handler. Release source and the vendor build recipe
are available at the pinned commits linked from the profiles.

The normal vendor entrypoint, S6 wrapper and SQLite backend initialize through
supported environment variables. Native CLI/API operations create one ordinary
user and public/private repositories. No Docker socket, executor or CI runner is
used. The native probe verifies actual versions, binary hashes, authentication,
ordinary org-mode rendering, file bytes, permission failures and private context.
It uses Python's standard HTTP/HTML libraries independently of Framework's client
and Nokogiri parser. Existing Gitea controls hardcode other releases and migration
fixtures, so this product-specific probe is shared across all four profiles.

Org-mode returns rendered text. Real captures remove a final newline from text
files; a file without that newline remains unchanged. Tests preserve that genuine
behavior and compare full printed/loot text with independently decoded API bytes.
They do not claim binary or byte-exact original-file recovery. Empty, whitespace,
missing and unreadable files cannot be distinguished by their empty rendering;
the module must create neither success output nor loot/vulnerability records.

Native pre/post controls retain actual filesystem hashes, repository/account
state, configuration/binary hashes and process identity. They verify clean
memory/PID counters and a refused port from Framework's actual UID/namespace.
The shared Gopher reporting-database service provides real PostgreSQL records,
authentication and per-example workspaces for service/vulnerability checks.
The unrelated profile reuses the genuine, bounded Apache control.

Only one project runs at a time. Forgejo projects have three containers capped
at 1,408 MiB/1.45 CPUs: Forgejo 512 MiB/0.25 CPU/128 tasks, PostgreSQL
128 MiB/0.2 CPU/64 tasks, Framework 768 MiB/1 CPU/256 tasks. A 256 MiB Forgejo
pilot hit its memory limit; the larger cap has independent native controls.
Only target HTTP binds to host loopback. Disposable data volumes, networks and
containers are removed after each profile. Registration is not qualification;
passing current examples and independent native/cleanup evidence are required.

The vendor's security patches are [15.0.6](https://codeberg.org/forgejo/forgejo/pulls/13683)
and [16.0.2](https://codeberg.org/forgejo/forgejo/pulls/13682). The latter commit is
`d7471ea487788c5d6f711a61436a45bf47601948`. The published go-org renderer disables
its filesystem callback in those fixes.
