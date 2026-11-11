# Forgejo markup response fixtures

`responses.json` contains selected unmodified response bodies and response headers
from the native control in run `20261111T210610-2a5d4c/forgejo_15_0_5`, captured
on 11 November 2026 against Forgejo `15.0.5+gitea-1.22.0`. The `provenance` object
records the original `native-before.json`, target executable and original module
SHA-256 digests. No network calls are made by the focused unit spec.

The UTF-8 markup response is an HTML fragment without a meta charset declaration.
Its HTTP Content-Type is `text/html; charset=utf-8`; the expected rendered text is
`Native café 日本語 Grüße` (30 UTF-8 bytes). Expected text comes from the native
control's independent HTML parser, rather than the module being tested. Forgejo's
renderer removes the file's final newline, so these expectations describe rendered
text rather than claiming byte-for-byte recovery of the original file.

Other real captures cover HTML entities, no final newline, empty/whitespace files,
a filename containing a space, a missing file, version discovery and a rejected
markup request. The files are deliberate lab fixtures, not private target data.

The spec uses actual Framework module loading and Rex HTTP responses, with network,
console, reporting and loot persistence doubled. Its accepted-authentication status
and malformed/absent-response guard cases are explicitly synthetic. Reporting
expectations cover module calls and preserve AutoCheck's passive vulnerability
report; they do not establish database persistence or deduplication. The serial
container suite provides that functional validation separately.

Run the focused spec with:

```sh
bundle exec rspec spec/modules/auxiliary/gather/forgejo_orgmode_fileread_spec.rb --seed 59774
```

For a before/after comparison, `FORGEJO_UNIT_MODULE_ROOT` can point to a directory
containing `auxiliary/gather/forgejo_orgmode_fileread_cve_2026_59774.rb` from the
original revision. Keep the spec, fixtures and seed identical between runs.
