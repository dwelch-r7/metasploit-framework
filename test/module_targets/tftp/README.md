# TFTP target qualification

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb tftp
```

This lab is under qualification. A target definition or native preflight alone
does not establish a passing module result.

The digest-pinned Ubuntu 22.04 image installs pinned tftpd-hpa/tftp-hpa 5.2
packages. The genuine standalone daemon chroots into its image-local `/srv/tftp`
and serves files as `tftp`. Fixtures include ASCII, UTF-8, nested, empty and
1,536-byte binary data, plus a root-owned unreadable file. Binary data is generated
from source instructions in the Dockerfile. The container needs no additional
capabilities, host network, socket or host data mount.

Native tftp-hpa clients independently retrieve all readable files in octet and
netascii modes and compare their complete bytes with the server files. Controls
check the actual server UID's permissions, missing/unreadable error responses,
package versions and hashes. This client returns exit zero for some protocol
errors, so its status alone is not treated as success. The observed unreadable
response is `Error code 0: Permission denied`; it is not assumed to use code 2.

TFTP replies from a transfer-specific UDP port. Full native transfers and
Framework run inside the isolated lab network; no ephemeral host port range is
published. The runner explicitly discovers UDP loopback mappings. A genuine
unrelated BIND service verifies host-side UDP publication with a native DNS
request/answer and supplies the module's unrelated-service negative.

Six module cases cover readable/absent/denied names, explicit/default local
binding, repeat scans, empty dictionaries, whitespace/blank entries, UTF-8 names
and unrelated UDP. They test filename discovery, as advertised by this module;
the module itself does not complete a file download. Other implementations,
IPv6, proxies/pivots, packet loss/reordering and persistent reporting remain
unqualified. See the [shared guide](../README.md) for retained inputs and cleanup.
