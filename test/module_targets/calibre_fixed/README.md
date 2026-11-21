# Calibre genuine 7.16.0 fixed-release control

```sh
MODULE_TARGET_NAMESPACE=calibre-fixed-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb calibre_fixed
```

This target shares the [7.14.0 recipe](../calibre/README.md), system runtime,
normal startup and genuine seeded book. Build arguments select the official
7.16.0 archive and vendor SHA-512 instead. No vendor source is patched. Of four
installed function fingerprints, only the list implementation differs; bundled
Python 3.11.5, UID 1000 and book identity remain the same.

For every control the identical generated Python template must first execute
locally through genuine SafeFormat and create exact physical bytes. After
removal, the real HTTP endpoint returns the captured `Template not allowed`
result for that template and leaves its physical proof absent. HTTP 200 alone
does not establish command execution or a valid fixed target.

The actual module check must return reason-bearing Safe for 7.16.0. Normal
AutoCheck then withholds the actual exploit twice on the same selected object,
without calling `exec_calibre` or sending an RPC request. Exact-command local
positives and same-template HTTP denials precede both attempts.

Only one capped application container runs: 1 CPU, 768 MiB memory/equal swap,
128 PIDs and a loopback-only published port. Run serially with a unique namespace
through the guarded runner; ensure removes finished resources immediately.
This qualifies the stated fixed-release command/check control, not other
releases, payloads, Windows, empty libraries or disabled-AutoCheck behavior.
