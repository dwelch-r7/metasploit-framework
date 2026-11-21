# Salt REST API native-gated command validation

The [Salt API profile](salt_api/README.md) passes **4 examples / 0 failures /
0 pending** in **88.40 seconds**. It invokes the original
`exploit/linux/http/saltstack_salt_api_cmd_exec` check and exploit methods against
unmodified Salt **3000.1**, CherryPy **18.6.0** and Python **3.7.17**. Two real
root-owned command proofs match the native controls byte for byte. Production
module source is unchanged, SHA256
`973a6c6476e3a9a5e9cfb5e237ff0c97860870d48768796060b93d8b5f24d1da`.

## Native prerequisites and actual owner behavior

The image pins its Python base, official Salt release archive and Python runtime
packages. Genuine OpenSSH binaries come from signed Debian snapshot packages.
Normal master/API daemons use HTTPS, disposable sharedsecret authentication and
empty rosters beside their actual configuration files. Seven installed Salt
source fingerprints match the release archive. The API's original
`CherryPy/18.6.0` Server header is preserved.

Before any owning method runs, native controls verify the HTTPS route, valid and
invalid login credentials, rejection of a request with no authentication field,
ordinary SSH key generation and an authorized SSH API request. Separate original
key-generator CLI and HTTP calls execute the exact plain and quoted
Unicode/CRLF commands. Actual root-owned file bytes prove execution; an empty
roster response alone is insufficient.

Six owning calls cover repeated checks on one module selection, plain and rich
`cmd/unix/generic` execution with AutoCheck enabled and disabled on one selection,
a natively confirmed refused port and AutoCheck refusal before the exploit body.
Passive observations retain original source locations, actual command bytes,
serialized requests and raw responses. All five returned CheckCodes have the
expected reasons. Every configuration file, both role-local rosters, TLS key and
certificate, common roster and `/dev/null` device metadata remain unchanged.

Salt's original vulnerable key generator creates literal-path directories under
`/dev/null < ` before invoking the shell. The test records these artifacts after
actual owning calls, then removes them as a separate fixture recovery step.
That explicit removal is not credited to the module. Proof files are removed
between native/owning executions, and the second command runs successfully.

## Setup corrections, resources and limits

Two initial builds fail before any module invocation: historical Salt metadata
requires `pycrypto` despite its supported pinned Cryptodome backend, and the
minimal base lacks OpenSSH. The final build accepts only the exact known package
metadata discrepancy, proves Salt loads Cryptodome and requires the real tools.
An initial 4/0 module run reveals missing role-local rosters in its target logs.
The fixture is corrected and replayed; the final 4/0 run has no missing-roster
error. Those preliminary results are not used for final qualification.

Only one container runs at a time, capped at **512 MiB / 0.7 CPU / 160 tasks**
with equal memory/swap limits and bounded runtime tmpfs. Four cgroup snapshots
are entirely zero. Each stack is removed before the next phase. All **9 new /
646 recorded Docker objects** are independently absent, and both Docker contexts
are empty, including stopped containers. No image/cache prune or daemon restart
is used. Ruby lint, Python syntax, module-document tidy and diff checks pass;
the module documentation's **7,997-byte human Scenarios tail** is unchanged.

The retained current set reaches **114 cases across 33 passing profiles**, with
**373 current declared source/harness inputs** and **47 retained used/closed
sessions**. This profile adds no sessions. Source inventory is **5,179 files /
333 registered owners / 44 individual reviews / 0 stale reviews**. Registration
is not proof of pass. There remain **193 pending container-hint candidates**,
including **164 exploits**, plus modules without documented container hints.
The broader goal remains active across all module types.

The default SSL Python session, Linux dropper, alternate base paths and fixed or
partially fixed Salt releases remain unqualified. The upstream
[security fixes](https://github.com/saltstack/salt/pull/58871) address separate
authentication and command-injection paths; no fixed-release verdict is inferred
from version labels or a 200 response. The existing ProjectSend cleanup and
normal PHP bootstrap investigations remain separate. No PR is created.
