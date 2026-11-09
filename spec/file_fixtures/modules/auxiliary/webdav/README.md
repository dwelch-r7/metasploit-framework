# Native Apache WebDAV responses

`apache_2_4_62_responses.json` contains unmodified HTTP response headers and XML
or HTML bodies captured on 2026-11-09 from Apache HTTP Server 2.4.62. The owned
DAV fixture uses:

`httpd:2.4.62@sha256:4c7788695c832bf415a662dfb5160f1895e65fc65c025e85f436ee2c9e7d7f3e`

The real mod_dav/mod_dav_fs service exposes `/dav/` containing `existing.txt`.
Its default `DavDepthInfinity Off` policy is retained. The independent stdlib
socket capture source is `capture_responses.rb`; it does not use Framework's
HTTP request generator or XML parser. With the owned fixture's loopback port:

```sh
ruby spec/file_fixtures/modules/auxiliary/webdav/capture_responses.rb 127.0.0.1 PORT
```

The three requests isolate these native outcomes:

- `Host: :PORT`, corresponding to the module's old explicit blank vhost plus
  Rex's nondefault-port formatting, receives HTTP400 even with `Depth: 1`.
- A valid Host with no Depth receives HTTP403 because the omitted header means
  infinity.
- A valid Host with `Depth: 1` receives HTTP207 and the actual collection/file
  hrefs in the DAV namespace, using the server's `D` prefix.

Request/response text, transient port, dates and resource metadata are retained
as captured. The exact loopback endpoint is not used as an expectation in the
focused module spec, which uses TEST-NET addresses. Alternate prefixes, a default
namespace, XML entities, duplicate/blank hrefs, malformed XML, foreign namespaces
and error-shaped variants in that spec are explicitly derived tests, not claims
of additional native server captures.

The generic target setup belongs under `test/module_targets/webdav/`; the
parent campaign owns that definition and the broader module acceptance suite.
