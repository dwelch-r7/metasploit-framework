# CouchDB targets

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb couchdb
```

This is the original digest-pinned CouchDB 3.3.1 image, configured as a single
node using the [upstream setup guide](https://docs.couchdb.org/en/stable/setup/single-node.html).
Public fixture credentials are labadmin/labpassword and labreader/readerpassword.
Native HTTP controls seed real system/application databases, nested documents
and text/binary attachments, then independently validate actual bytes and access policy.
The reader authenticates successfully but receives HTTP 401 from admin-only
user/database listing; authentication and authorization are checked separately.

A real Apache service uses its ordinary `FallbackResource` directive, as in
SPA deployments, returning unrelated HTML with HTTP 200 for an unknown API path.
It is deliberately not a CouchDB response stub. Native HTTP verifies that
configuration before the login module's negative case. Both services publish
only random loopback ports and retain no data outside their owned project.

Tests cover login/admin/reader/incorrect credentials, unrelated HTTP, fixed-version
checking and exact database/document/attachment loot. Target definitions do not
imply a pass; see the [campaign](../CAMPAIGN.md) for actual results and limitations.
Native CouchDB 2.1.0 image lookups in both official namespaces returned not found;
authentic vulnerable source/image qualification remains separate pending work,
not a claim of infeasibility. CREATEUSER/CVE exploitation, other releases,
reverse-proxy paths, TLS and saved credentials are not yet qualified.
See the [shared guide](../README.md) for evidence and cleanup.
