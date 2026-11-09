# Elasticsearch enumeration HTTP captures

`responses.json` contains actual status, content type and unmodified HTTP body
bytes from vendor Elasticsearch 7.9.1 and the genuine Apache negative control.
The independent native REST preflight retained these in
`20261109T150045-2bb9a0/elasticsearch/native-elasticsearch-before.json` on
November 9, 2026, at Framework source `f938927d7b7`. Its full SHA-256 and each
body digest are recorded with the fixture. Unused response headers and request
credentials are omitted. Addresses and account names identify only disposable
public lab fixtures; unit target arguments use TEST-NET-1.

The native lab is `test/module_targets/elasticsearch/`. It seeds seven small
records and an empty index, then independently verifies stored content, row
samples, real Basic authentication, index/cluster monitor permission and
permission refusal before running Framework. The captured raw search bodies
include newline, quotes, commas, Unicode and empty text. No JSON body was
generated from the module's output matcher.

The `disabled_users` response was captured separately by a native HTTP GET to
the same pinned/configured open image in project
`msf-elasticsearch-csv-control`. The real disabled-security route returns
HTTP 405; its body/status are retained unchanged. The owned control project was
removed afterward.

Reproduce full live qualification from the repository root with:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb elasticsearch
```

Empty lists, malformed search shapes and missing source fields in the spec are
explicit derived boundaries. Reusing a captured HTTP refusal at another
collection phase tests the error contract and is not additional live endpoint
qualification. The CSV comparison parses output with the existing CSV library
and ignores record order; it still requires exact field values and public loot
metadata. A table's display sorting does not imply a search-result ordering
contract, and presentation whitespace normalization must not alter extracted
CSV data.

The index-note regression observes the argument emitted from the real captured
index Hash. It establishes the reported identifier, not persisted database
storage; no database is required by this fixture.
