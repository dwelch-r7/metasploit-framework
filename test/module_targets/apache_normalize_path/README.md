# Apache path normalization targets

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb apache_normalize_path
```

Official Apache 2.4.49, 2.4.50 and 2.4.62 images are pinned by digest. The first
two versions recreate CVE-2021-41773 and CVE-2021-42013 with an intentionally
permissive root directory and CGI enabled. A second 2.4.49 instance keeps the
root directory denied. The 2.4.62 instance uses the permissive configuration to
distinguish a fixed implementation from a configuration-based mitigation.
See [Apache's advisory](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773).

The suite verifies the exact server version, independently reads a known file
outside the document root and executes a harmless marker command before invoking
Framework. It tests both modules:

- `auxiliary/scanner/http/apache_normalize_path`: traversal detection, CGI RCE
  detection and real file retrieval/loot on both vulnerable releases; fixed,
  guarded and wrong-CVE negative controls.
- `exploit/multi/http/apache_normalize_path_rce`: in-memory commands and Linux
  x86/x64 executable delivery. Each executes twice and must create a fresh proof
  file inside the target; console output cannot substitute for execution proof.
  After removing that test-owned proof file, the target's temporary file list
  must match its original state.

The executable cases use `linux/x86/exec` and `linux/x64/exec`, and the command
case uses `cmd/unix/generic`. They do not open sessions. `AllowNoCleanup=true`
permits these payloads through FileDropper's normal session-cleanup gate; the
tests independently assert that this module's explicit removal worked. Reverse
shell/Meterpreter sessions, TLS and other payload families remain to be covered.
The targets explicitly use amd64 to exercise both declared executable architectures.

Only random host loopback ports are published. Containers have no host mounts
and are removed by the [shared runner](../README.md).
