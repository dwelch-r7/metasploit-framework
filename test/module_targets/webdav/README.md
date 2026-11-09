# Native Apache WebDAV targets

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb webdav
```

This profile uses the HTTP lab's digest-pinned Apache 2.4.62, enabling genuine
mod_dav/mod_dav_fs. Four directories provide open (`/dav/`), Basic-authenticated
(`/auth/`), read-only (`/readonly/`) and ordinary HTTP (`/plain/`) policies.
Lab credentials are `lab-dav-user` / `lab-dav-password`. The image gives the
configured Apache user ownership of the DAV data and lock directory. No PHP
runtime or command execution is enabled. The isolated service has a random
loopback port; see the [shared guide](../README.md).

Native Ruby HTTP/XML controls independently verify capabilities, exact static
content, authentication, depth-one listings, repeated writes/readback/deletion,
and denial of writes/deletion in both protected policies. They record actual
response headers and bodies. Default infinite-depth PROPFIND remains denied,
as in the ordinary Apache configuration; the lab does not enable it just to
satisfy a scanner. [Apache's DAV guide](https://httpd.apache.org/docs/2.4/mod/mod_dav.html)
describes the server configuration.

Twenty-two module cases cover capability detection, actual content listing,
depth-zero listing, explicit infinite-depth refusal, correct/incorrect Basic
credentials, repeated PUT/overwrite/DELETE, ordinary
regex characters as file contents, multiline `file:` input, an extensionless filename, missing files,
and denial of mutations, including overwrite of existing matching content.
Separate negatives distinguish server-header and
error-page matches from actual stored file contents. Native readback and module success
messages are both required; operator cleanup cannot satisfy those assertions.

This family is under module qualification. Consult the [campaign](../CAMPAIGN.md)
for actual passing results and defects; presence of the files is not a pass.
TLS/Digest, locks/MOVE/COPY, recursive or large directory scans, alternative
DAV servers, executable uploads and database reporting remain unqualified.
