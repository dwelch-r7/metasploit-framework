# dizqueTV Linux command execution

```sh
MODULE_TARGET_NAMESPACE=my-dizquetv-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb dizquetv dizquetv_fixed
```

These opt-in profiles run the publisher's pinned **1.5.3** and **1.5.5** images,
one capped container at a time: **384 MiB**, **0.7 CPU**, equal memory/swap limits
and 96 PIDs. No application source is changed. The packaged application binary
is fingerprinted independently, and the real version API reports the application,
embedded Node runtime and FFmpeg versions. State lives only in the temporary
container. Every phase removes its container and ephemeral network.

The image bundles Node into the application executable. It has no standalone
Node, Python, PHP, curl or wget. The host's Python standard HTTP/JSON/CSV libraries
and stock Perl core provide independent observations without installing runtime
packages. A read-only Perl health probe requests the static root page; it avoids
the command-triggering version endpoint.

Native controls execute the exact command through the normal shell and then the
real ffmpeg-settings/version APIs. UID-0 file bytes and returned output must match.
Proofs are removed and absence checked before actual module delivery. The
vulnerable profile seeds a non-default thread count and compares the full API
settings and all nine root JSON database stores after every owning operation.
Original factory values restore afterward.

Seven vulnerable-profile cases cover native readiness, actual Appears/Unknown
checks, repeated COMMAND execution, quote/Unicode/CRLF preservation, COMMAND
precedence over the generic CMD payload, the payload fallback when COMMAND is
empty, and invalid polling options. Generic non-session runs explicitly set
`AllowNoCleanup=true`, disable the handler and use zero session wait. Command
proof files are deliberately removed by the fixture after their verification.

The fixed profile has three cases: native positive controls and specific
injection denial, the actual Safe result and repeated AutoCheck refusal on one
selection. A rejected write must leave all records untouched, including the
hidden path-lock timestamp. A normal successful update extends that timestamp
in the [publisher's service](https://github.com/vexorian/dizquetv/blob/196033844ac9abfa32819653d221b3fff2696677/src/services/ffmpeg-settings-service.js),
so the fixed control avoids redundant writes. No field is excluded from the
comparison. See the [official fixed-release notes](https://github.com/vexorian/dizquetv/releases/tag/1.5.5).

Passive traces retain original module calls, requests, command/output bytes and
failures. Native-control failures withhold the module verdict. Reverse sessions,
default fetch prerequisites, Windows and other releases remain unqualified.
Registration alone does not prove a profile passes; ordinary unit CI excludes
these Docker tests.
