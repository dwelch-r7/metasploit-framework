# Jenkins systemInfo capture provenance

`system_info_2_442.html` is a reduced real HTML capture from the open Jenkins
2.442 controller in the module-target lab. The native HTTP response was retained
in `tmp/module-target-tests/20261109T133503-ae346f/jenkins/native-jenkins-routes.json`.
Its original body is 245,801 bytes with SHA-256
`d73f314ae44dc273cf07a929f31d548ce9b927d4ca313b8c8c9e7c86cc73b1be`.
The controller uses the official Jenkins 2.442-jdk17 image pinned by the parent
lab and an intentionally open, job-free configuration.

The fixture retains the raw title and first stylesheet link plus seven actual
property rows. Nokogiri serializes those selected rows; only their SVG icons are
removed. The hidden/reveal controls, nested values and word-break elements remain.
No credentials, crumbs, host addresses or unrelated page content are retained.

`system_info_plain.html` is an explicitly derived compatibility variant: the
same property rows contain only their captured value text, without the modern
controls or page head. It is not a claim of a native older-version capture.
The inline missing-cell, value-column and empty-value examples are deterministic
structural variants of these captured property names and values.
