# Native Docker version documents

`old.json` and `modern.json` are exact response bodies from genuine Docker Engine
26.1.4 and 28.0.4 daemons. `unrelated.html` and `missing.html` are exact real Apache
HTML/200 and HTML/404 bodies at `/version`. The isolated native probe uses Docker's
own Unix-socket client and independent HTTP; it does not invoke the module.
`provenance.json` records pinned images, actual response headers and file hashes.
The full run is `20261110T011231-14ea41` in the parent campaign's artifacts.

The focused spec additionally constructs malformed/missing/type boundaries from
these documents. Those derived cases are labeled explicitly and are not wire
captures. Host reporting keeps the native architecture spelling; the host model's
documented `Unknown`/`detected_arch` fallback is tested in the separate real-DB lab.
