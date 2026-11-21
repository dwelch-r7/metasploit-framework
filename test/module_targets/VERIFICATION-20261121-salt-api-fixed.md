# Salt REST API command/authentication fix boundaries

The [fixed-release profiles](salt_api_fixed/README.md) distinguish the two
prerequisites of `exploit/linux/http/saltstack_salt_api_cmd_exec` using genuine
Salt releases and native controls before actual owning calls.

| Salt release | Examples / failures / pending | Seconds | Verified behavior |
| --- | --- | --- | --- |
| 3000.1 | 4 / 0 / 0 | 82.96 | Vulnerable control retains two exact root-owned command proofs |
| 3000.4 | 3 / 2 / 0 | 87.59 | Native command injection blocked; auth-only positive check permits two ineffective exploit bodies |
| 3000.5 | 3 / 0 / 0 | 46.35 | Valid native authentication works; actual Safe checks and repeated AutoCheck refusal |

**3000.4 remains a failing profile**, with both readiness assertions enabled for
further investigation. Its check correctly identifies the remaining auth bypass,
but that result is insufficient to establish the module's command-injection
exploit prerequisite. The original check returns `Vulnerable` with reason
`Auth bypass successful.` on all four owning calls. AutoCheck enters the original
exploit and command methods twice, sends the exact natively calibrated command,
receives genuine HTTP 200 responses and produces no command proof. The module
source is unchanged, SHA256
`973a6c6476e3a9a5e9cfb5e237ff0c97860870d48768796060b93d8b5f24d1da`.

## Native controls

The pinned Python 3.7.17 / CherryPy 18.6.0 fixture installs official Salt release
archives and verifies seven installed source files for each version. Ordinary
master/API daemons use HTTPS, shared cache/PKI paths and empty, valid role-local
rosters. The upstream release notes separately identify the
[3000.4 command-injection fix](https://docs.saltproject.io/en/3006/topics/releases/3000.4.html)
and [3000.5 auth fix](https://docs.saltproject.io/en/master/topics/releases/3000.5.html).
Native observations establish their actual behavior here.

Valid and invalid login credentials, a real Salt eauth token from `/token`, a
web-session ID from `/login`, an unknown hex token, a malformed non-hex token and
missing credentials are tested separately. Valid SSH requests succeed on both
releases. In 3000.4, invalid eauth and well-formed unknown tokens still bypass
authentication. In 3000.5, these are rejected while valid eauth and Salt tokens
continue to work. The web-session ID is also rejected by 3000.5's `/run` route;
it is a different credential type from a Salt eauth token.

A normal shell writes the exact root-owned command proof. Calling each patched
release's original key generator with that injection instead creates a literal
key pair. The proof stays absent. The CLI-created key pair is explicitly removed
before the independent HTTP control so an existing key cannot skip generation.
On 3000.4 the API creates a new literal key pair, verified by real `ssh-keygen`,
without executing the command. On 3000.5 authentication denial creates no key.
All original source, HTTP headers, request/response bytes and method locations
are retained; no application or owning method is replaced.

Each check pair and each AutoCheck pair reuses one module selection.
The 3000.5 checks return `Safe` with reason `Auth bypass failed.`; neither owning
AutoCheck call enters the exploit body. Configuration, all roster files, TLS
material and `/dev/null` metadata preserve after every call. Literal key artifacts
are captured before separate fixture cleanup, which is not credited to the module.

## Setup corrections and scope

The first native attempt used a non-hex token and hit CherryPy's format check
before Salt's authentication path. A corrected unknown hex token and a separate
malformed-token control retain both cases. Two later 3000.5 native attempts
mistook the `/login` web-session ID for a Salt token; neither invokes the module.
The API/master cache and PKI were also normalized to their shared configuration.
That normalization alone does not explain or fix the credential-type error.
The final native controls use `/token`, read the actual loaded storage paths,
and pass before module execution. A native-only 3000.5 pilot passes independently.
The vulnerable 3000.1 profile is replayed after the shared fixture change.
Earlier native failures and 3000.4 reproductions remain separate evidence.

Only **one container** runs at a time, capped at **512 MiB / 0.7 CPU / 160 tasks**,
with equal memory/swap caps and bounded runtime tmpfs. All twelve final cgroup
captures are zero. All **18 new / 664 recorded Docker objects** are independently
absent; both Docker contexts are globally empty, including stopped containers.
No image/cache prune or daemon restart is used. Ruby lint, Python syntax and
module-document tidy pass. The human Scenarios tail is unchanged at 7,997 bytes.

The retained fully passing set reaches **117 cases across 34 profiles**, with
**383 current declared source/harness inputs** and **47 used/closed sessions**.
The failing 3000.4 profile is excluded from those passing totals. This work adds
no sessions. Default SSL Python sessions, the Linux dropper, alternate base paths
and other release branches remain unqualified. The source-bound review records
the 3000.4 limitation for follow-up. The broader all-module goal remains active;
registration is not proof of pass. No PR is created.
