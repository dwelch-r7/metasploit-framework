# Apache HTTP module targets

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb http
```

The image builds from Apache HTTP Server 2.4.62, pinned by digest, with small
static documents, a directory listing, a redirect, robots.txt, TRACE enabled,
and a Basic-authenticated directory. These are real Apache features, not mocked
responses. The runner binds port 80 to a random host loopback port and validates
the version and page contents independently with Ruby's HTTP client.

The suite covers:

| Module | Cases |
|---|---|
| `auxiliary/scanner/http/http_version` | Apache version fingerprint |
| `auxiliary/scanner/http/title` | Entity decoding, requested redirect following, missing title |
| `auxiliary/scanner/http/robots_txt` | Present and missing file |
| `auxiliary/scanner/http/options` | Actual Allow header and enabled TRACE |
| `auxiliary/scanner/http/dir_listing` | Directory listing and ordinary index page |
| `auxiliary/scanner/http/http_header` | HEAD and GET |
| `auxiliary/scanner/http/trace` | Request reflected by Apache TRACE |
| `auxiliary/scanner/http/http_login` | One valid and one invalid Basic credential |

Lab credentials: `module-test-user` / `module-test-password`. There is no TLS,
Digest, WebDAV or Framework database in this initial fixture. Database-backed
service/note/credential persistence and other HTTP server implementations remain
untested. See [the shared runner guide](../README.md) for evidence and cleanup.
