# Mongobleed targets

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb mongobleed
```

The lab uses digest-pinned MongoDB 4.4.29 with zlib, the same release with only
snappy enabled, an authenticated 4.4.29 with zlib, fixed 4.4.30 with zlib,
and a real Apache service. MongoDB's
[advisory](https://jira.mongodb.org/browse/SERVER-115508) identifies the affected
release, fix and compression mitigation. Only random loopback ports are published.

A native Ruby client sends the independent published [Wiz one-packet probe](https://www.wiz.io/blog/mongobleed-cve-2025-14847-exploited-in-the-wild-mongodb).
It records raw/decompressed bytes losslessly. Native MongoDB commands verify
the actual compression configuration; HTTP proves the unrelated server's identity.
A fresh unauthenticated client must be denied database listing on the authenticated
target, while the independent unauthenticated wire probe still proves disclosure.

Module cases cover positive/fixed/mitigated/unrelated checks, safeguards against
leaking on protected targets, and bounded quick scans with connection reuse both
enabled and disabled on both open and authenticated targets. No credentials are
given to the module. Each scan mode runs twice. Binary loot must match the actual
Base64 fragments and metadata lengths in the JSON report. Scans use small buffers
and public disposable targets; no outside database or production data is used.

Memory contents are nondeterministic: the suite checks real nonempty disclosure
and structural integrity, not a promised secret string. Larger scans, other
release branches and forced exploitation remain
unqualified. The [campaign](../CAMPAIGN.md) records current results; target files
alone do not establish a passing result. See the [shared guide](../README.md) for
evidence and cleanup.
