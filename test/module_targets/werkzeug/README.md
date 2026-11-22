# Werkzeug debugger native validation

This shared recipe installs genuine **0.10, 0.11.5, 1.0.1 and 3.0.3** packages
without vendor patches. They represent the owner's four target families: no PIN,
legacy MD5 cookies, later MD5 cookies and SHA1 cookies. The Python 3.8.20 image
and [PyPI artifacts](packages.json) are checksum-pinned. Installed Python source
hashes and package versions are retained and independently checked at runtime.

The application is a small WSGI callable wrapped by the installed
`DebuggedApplication`. `/console` uses the genuine console. GET
`/trigger?file=raise` and POST `/trigger` with `file=raise` produce genuine
exception frames. `/health` is an ordinary application response. The service
uses UID/GID 1001 (`lab`), a synthetic `/etc/machine-id`, and its actual namespaced
MAC/cgroup values. No host identity is copied into the image.

The default profile uses 3.0.3. `werkzeug_md5`, `werkzeug_legacy` and
`werkzeug_noauth` share the same recipe for 1.0.1, 0.11.5 and 0.10. Their
authentication profiles cover native PIN/cookie acceptance, generated cookies,
known PIN and cookie modes where supported, exact command bytes, console and
GET/POST traceback entry points, repeated selected instances and ordinary-page
detection. Version 0.10 uses `AUTHMODE=none`.

Separate `*_sessions` profiles independently calibrate the actual cold-default
stock Python Meterpreter through a real handler, then exercise repeated owning
sessions. The selected exploit stays intact while the native handler runs.
The native control launches the unchanged stock program in a separate interpreter
using standard-library calls, independently of the Framework execution wrapper.
The original raw embedded program's unreaped-child failure remains recorded.
Session readiness requires the opened event and initialized APIs. Public file,
identity and shutdown APIs are paired with exact physical file bytes,
UID/PID/birth observations, process/socket closure and a responsive service.

`werkzeug_noeval`, `werkzeug_pinoff` and `werkzeug_custom_pin` use the genuine
3.0.3 configuration controls. They disable evaluation, disable PIN security, or
set a custom PIN. Native positive interpreter/authentication controls precede
owner denial or success assertions. Custom-PIN validation also distinguishes a
known PIN from a cookie derived from the environment's different default PIN.

Run the cleanup-guarded profiles serially from the repository root:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default \
  MODULE_TARGET_NAMESPACE=werkzeug-local \
  bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
  werkzeug werkzeug_md5 werkzeug_legacy werkzeug_noauth \
  werkzeug_sessions werkzeug_md5_sessions werkzeug_legacy_sessions \
  werkzeug_noauth_sessions werkzeug_noeval werkzeug_pinoff werkzeug_custom_pin
```

Each phase uses one Linux/amd64 container capped at 128 MiB RAM/swap, 0.5 CPU and
64 PIDs. Root is read-only; `/tmp` and `/run` use bounded tmpfs mounts. HTTP 8080
is published on a random loopback port. The Framework console runs on the host.
The guard records inputs and namespace labels, holds the shared lock and
removes the stack after success or failure. Use a unique namespace for a
separate investigation and remove its resources immediately afterward.

Native HTTP controls parse real debugger pages and authenticate against the
package's own PIN endpoint. Direct interpreter commands and stock generated
`python/exec` programs distinguish setup, payload and owner failures. Both
successful execution and idle process/socket preservation matter. Test proof
files are explicitly removed after their bytes/ownership are checked; that
reset is not credited as module cleanup. No test hides or manually reaps payload
zombies. Expected kernel TIME_WAIT records without an owner inode remain in raw
captures and are excluded only from live-socket comparison.

The [verification record](../VERIFICATION-20261122-werkzeug.md) distinguishes
confirmed source failures, harness races and unqualified paths. Initial failures
and corrections remain in the campaign evidence. Registration
does not establish a passing profile. These fixtures cover the recorded Linux,
Python and WSGI server configuration. Other Python/OS/web-server versions,
HTTP basic authentication, unusual application contexts, additional payload
families and release boundaries require separate native controls.
