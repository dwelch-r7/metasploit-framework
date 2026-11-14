# n8n execution reference-table fixtures

These are exact Flatted table values from genuine official n8n 1.120.0 member
controls, copied from `native/native-node.jsonl` lines 3 and 5 in the immutable
`ni8mare-console-text-diagnosis-20261114` archive. `native-oracle.json` records
source/fixture hashes, the archive manifest, and the installed `flatted.parse`
process exits and output hashes. No private fields required sanitization in
these two execution-data tables; no cookies, account data or config/database
contents are included.

The multipart table has 32 entries and file data at entry 29. The JSON confusion
table has 33 entries: entry 29 is the literal `txt`, while descriptor 25's `data`
reference points to entry 30. The independently parsed native object follows:

`resultData / runData / On form submission / 0 / data / main / 0 / 0 / binary / Native_file / data`

Both native parses return the same 41 bytes, expressed without an opaque blob:

`Module target n8n exact native bytes\n\x00\xff\xc3\xa9`

The source path was `/tmp/module target café 雪.txt`. The known byte content
includes a newline, NUL, 0xff and UTF-8 é. The short Base64 value in the JSON is
the actual captured file data, not an executable payload.

Parser specs derive reordered-reference, field-label, empty/numeric-literal and
malformed variants from these captures. Cleanup specs change only the data
literal at entry 30 and entry 32's size text to their controlled expected bytes;
the real 33-entry result structure remains intact. These variants are explicitly
local tests, not additional native target observations.
