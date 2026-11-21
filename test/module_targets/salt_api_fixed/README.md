# Salt REST API fix boundaries

These serial profiles reuse the [original HTTPS lab](../salt_api/README.md)
with unmodified official Salt **3000.4** and **3000.5** release archives. Each
profile runs only one container at **512 MiB / 0.7 CPU / 160 tasks**, using a
unique guarded Compose project and unconditional teardown. The base image,
CherryPy runtime, ordinary daemons, authentication and empty rosters are shared.
Builds install the version's locked release source; no target response or
application method is replaced.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb salt_api_3000_4 salt_api_3000_5
```

The release notes distinguish the
[3000.4 command-injection fix](https://docs.saltproject.io/en/3006/topics/releases/3000.4.html)
from the later
[3000.5 authentication fix](https://docs.saltproject.io/en/master/topics/releases/3000.5.html).
Native controls verify seven installed source files, actual TLS/configuration
state, valid and invalid login credentials, ordinary SSH key generation and an
authorized SSH API call. Invalid external-auth and token calls independently
establish each release's authentication behavior. A Salt eauth token from
`/token` is distinct from the web-session ID returned by `/login`; controls
exercise both credential types and a malformed non-hex token separately.
A normal root shell must write
the exact command's proof bytes. The original patched key generator must create
a literal filename instead of executing that command; the API is then tested
independently with no existing private key to short-circuit key generation.

Actual owning checks and AutoCheck calls run twice on the same selection.
The contract expects the module to refuse its command-injection exploit when
native controls establish that path is fixed. A profile that exposes a positive
auth-only check and an ineffective exploit must remain failing and recorded;
do not change its expectation merely to obtain green tests. Preserve the exact
CheckCode reason so the remaining auth flaw is not misreported as fixed.

Configuration, rosters, TLS material and `/dev/null` must be preserved. Literal
key-generation artifacts are recorded before separate fixture removal. Cgroup
counters and exact container/network cleanup are checked after failures too.
Registration does not establish qualification; consult the campaign verification
report for actual results and retained limitations. Default sessions, the Linux
dropper, alternate base paths and other release branches remain separate work.
