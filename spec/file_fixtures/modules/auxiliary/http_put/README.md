# Native HTTP PUT verification captures

`responses.json` was captured on November 9, 2026 from the genuine Apache
HTTP Server 2.4.62 WebDAV lab using this pinned upstream image:

`httpd:2.4.62@sha256:4c7788695c832bf415a662dfb5160f1895e65fc65c025e85f436ee2c9e7d7f3e`

The independent Ruby HTTP client in `capture_responses.rb` writes two small
nonexecutable text resources, checks exact GET readback, deletes each resource,
and checks its absence. It also captures an unauthenticated GET and a denied
PUT against an existing read-only file, checking that its original bytes remain.
The fixture retains actual response statuses, headers, bodies and control
requests. These are target responses, not Framework-generated HTTP replies.

With the managed WebDAV target running, use its published loopback port:

```sh
ruby spec/file_fixtures/modules/auxiliary/http_put/capture_responses.rb 127.0.0.1 PORT responses.json
```

Only the script's two fixed `module-target-native-unit-capture-*` files are
eligible for its cleanup. Use it only against the owned lab. The target's
Dockerfile/configuration and independent policy checks are in
`test/module_targets/webdav/` on the module-validation campaign branch.

The focused spec also constructs explicit nil/empty responses, status410 and
small byte/encoding boundary examples. Those are unit variants, not additional
native captures. The live functional suite separately covers authentication,
repeated PUT/overwrite/DELETE, filename handling and exact file-input contents.
