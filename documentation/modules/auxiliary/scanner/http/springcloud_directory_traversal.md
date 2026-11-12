## Vulnerable Application

This module exploits CVE-2020-5410 in Spring Cloud Config Server 2.1.x before
2.1.9 and 2.2.x before 2.2.3, as well as older unsupported releases. The server
normally listens on port 8888. The requested file must be readable by the server
process, and its resource repository configuration must expose the encoded
absolute-path traversal.

Original server/client libraries 2.1.8 and 2.2.2 reproduced this primitive with
the native filesystem backend and a relative `file:./` search location. An
absolute search location did not reproduce that setup. Other backends and older
releases have not been verified by this regression lab. See the
[serial container lab](../../../../../test/module_targets/springcloud_config/README.md)
for pinned artifacts, preparation and independent native controls. Do not infer
the embedded Spring library version from the distribution image tag alone:
`hyness/spring-cloud-config-server:2.1.6.RELEASE` contains library 2.2.1.

References:

- [Spring advisory](https://tanzu.vmware.com/security/cve-2020-5410)
- [Vendor fix and encoded-slash regression](https://github.com/spring-cloud/spring-cloud-config/compare/v2.1.8.RELEASE...v2.1.9.RELEASE)

The module requests the resource endpoint with explicit application, profile and
label selectors. Using the explicit-label route avoids an overlapping environment
mapping that cannot read root-level files through the default-label shortcut. It requests
`application/octet-stream` to retain exact file bytes, including binary content,
placeholder expressions and empty files. Ordinary configuration JSON and HTTP
errors are not saved as file loot.

## Verification Steps

1. Start a vulnerable Config Server with a resource repository that exposes the
   traversal, using the linked lab instructions.
2. Start `./msfconsole`.
3. `use auxiliary/scanner/http/springcloud_directory_traversal`
4. `set RHOSTS <target>`
5. `set FILEPATH /absolute/path/to/read`
6. Set `TARGETURI` if the Config Server has a context prefix, then `run`.
7. Confirm the stored loot matches the requested file byte-for-byte. A missing
   file or a blocked traversal must not create loot.

## Options

### FILEPATH

Absolute path on the Config Server, default `/etc/passwd`. Spaces and UTF-8 path
bytes are URI-encoded. The path is not relative to the configuration repository.

### DEPTH

Retained as a deprecated compatibility option with its existing default. It has
no effect: this vulnerability uses a double-encoded leading slash, and adding
parent-directory prefixes prevents the verified primitive from resolving the
requested absolute file.

### APPLICATION, PROFILE and LABEL

Advanced repository selectors, defaulting to `foo`, `default` and `master`. Set
these to an application, profile and label supported by the target's repository
configuration. For Git repositories, `LABEL` selects a branch or tag. Each is a
single resource path segment. Spring can choose a profile-specific
variant of the requested file for a nondefault profile; `default` avoids that
substitution in the verified native-backend lab.

The following historical human-written transcript is retained unchanged; it
predates the corrected resource request and exact-byte regression checks.

## Scenarios

### Tested against Linux zero 4.15.0-48-generic #51-Ubuntu SMP x86_64 GNU/Linux

```
msf auxiliary(scanner/http/springcloud_directory_traversal) > run

[+] File saved in: /Users/Dhiraj/.msf4/loot/20200619234552_default_[REDACTED]_springcloud.trav_785232.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf auxiliary(scanner/http/springcloud_directory_traversal) > 
```
