# Superset cookie modules — 2026-11-11

The checkpoint is **186 runtime modules, 127 qualified lab profiles and 1,443
functional examples**. This adds one Superset 2.0.0 profile with fourteen passing
examples for the credential gatherer and generic Flask signer. It does not
qualify the Superset RCE module or other application releases.

Run the [dedicated cookie lab](superset_cookie/README.md). The shared
[native preparation](superset/README.md) also has a standalone native-only
launcher. Container definitions, initialization and native clients stay with
the tests; the two module documents link to this reproducible lab.

## Actual final run

`20261111T043329-268a9b`, source `53767fb3754`, naturally exited zero:

- Fourteen examples, zero failures, pending examples or outside-example errors;
  RSpec duration 149.485179 seconds. Whole run: 04:33:30–04:36:55 UTC.
- Native-before: nine installed-application commands and sixteen HTTP requests;
  native-after: eight commands and sixteen requests. Both passed, including
  exact selected logical state equality against the original seed.
- Real cookie login, Gamma datasource refusal, installed Flask serializer,
  authenticated and anonymous-cookie escalation to Admin, absent-user and
  invalid-signature refusal, unrelated HTTP, and exact datasource secrets.
- Three genuine nonempty SQL captures: repeat collection reuses the same core,
  login and origin/service rows; a separate workspace gets correctly attributed
  credentials after the native-proven anonymous-cookie path. Both report the
  independently resolved PostgreSQL address and `Untried` status, with no
  fabricated authentication attempt timestamp.
- All three Flask actions ran. Legacy String data decodes as literal text;
  explicit JSON mode decodes as the original object and an independent fresh
  HTTP request identifies `lab-admin`. Malformed JSON produces no signed cookie.

The official pinned application is Apache Superset 2.0.0 with Flask 2.0.3,
Flask-Login 0.4.1, Flask-AppBuilder 4.1.3, itsdangerous 2.1.1, SQLAlchemy 1.3.24
and Werkzeug 2.0.3. Actual installed source hashes, metadata ownership and
configuration are verified before owner calls. Its observed identity key is
`user_id`. The supported migration/admin/init commands and vendor Gunicorn
launcher remain intact. A separate native-only run also authenticated to the
configured PostgreSQL datasource and executed an ordinary SQL query.

Four containers are capped at 2,144 MiB and 2.15 CPUs. Only the real Apache
gateway publishes a random loopback port; backends and Framework remain on the
internal network. Native-only preparation uses three containers capped at
1,376 MiB and 1.15 CPUs. The gateway's small worker pool fits its unchanged
64-task limit. Live cgroups showed all four roles below their memory caps,
with no OOM events; these are live observations, not a final cgroup capture.
The canonical Framework dependency build reused all 23 cached operations.

Parent observation confirmed an actually returned first console prompt and
isolated BOOT, no first-profile metadata seed, and two fresh, parsed atomic
snapshots equal to the console's source files: 7,264 module entries and two cache
entries. Source and result receipts were not rebound during import.

Parent teardown audit passed twelve independent queries: exact absence of all
four container IDs, two network IDs and two owned volumes, absence of all
project labels, and an empty global container inventory. Images and unrelated
volumes remain. The shared lock is held through tests and teardown.

## Failure evidence and repairs

| Baseline | Actual result | Disposition |
| --- | --- | --- |
| `cc159a` | Rejected login redirected302; control expected200 | Corrected native control; no owner calls |
| `273ac4` | Gamma datasource refusal404; control expected403 | Corrected native control; no owner calls |
| `dbe4f5` | Native controls and exact3/2/2 cleanup passed | Initial native qualification |
| `c0075d` | Apache default worker pool exceeded64tasks | Reduced worker pool; no owner calls |
| `a3a7e2` | Healthy roles; shared selector rejected two networks | Dedicated internal-address selector; no owner calls |
| `a50488` | Twelve real examples, five failures; native controls restored | Four assertion assumptions and a signing-content boundary |
| `f5f216` | Fourteen real examples, two gather SQL failures; all eight Flask cases passed | Confirmed hostname reporting defect |

A rejected login still supplies an anonymous CSRF cookie. Independent native
controls prove that the default signing key can elevate it to Admin. Credential
collection after a rejected password is therefore an exercised vulnerability
path. Expected incorrect-key verbose output also uses an error marker; the
tests require the subsequent actual success instead of rejecting that marker
alone. Unrelated Apache `/login` returns404/Unknown without identification as
Superset. These assertion failures were not treated as module defects.

The Flask signer preserves its existing String default and adds explicit
`CookieContentFormat=JSON` for a standard session object. Missing, malformed and
non-object JSON fail `BadConfig` before signing. Fifteen isolated source-unit
examples pass, including exact legacy cookie bytes and nil compatibility.

The gatherer previously passed a datasource hostname to the credential API's
IP-only service address. Genuine disclosure succeeded while SQL contained no
credentials. It now derives a reporting IP using the existing Rex resolver,
preserves the displayed hostname and attribution, and handles unavailable
addresses without inventing a service. Thirteen isolated source-unit examples
pass; the final genuine SQL captures demonstrate the repair and repeat behavior.

Unit tests use explicit module/UI/transport boundaries and do not prove target
behavior by themselves. Parent reran all 28 focused unit examples after import.
Changed scripts/specs lint cleanly; the owners retain their independently
compared pre-existing diagnostics. No library or dependency changes are added.
Human Scenarios remain byte-identical. Module-document checks retain only their
existing universal-option/leading-blank warnings.

The final local seal contains 135 files; its manifest SHA-256 is
`29ade9f0b196808d4466c223566c5ebab11e489e6361c8103658efad7a772849`.
All 74 original run files imported byte-for-byte, and all 57 selected source
inputs match the primary worktree. Earlier failures, unit reproductions and
their exact teardown receipts remain separately sealed.

## Review and remaining work

**Summary:** Both selected owners pass their actual main functions and the
fourteen-case profile with native controls and independent cleanup.

**What looks good:** Real application identities, installed-source checks,
native serializer/HTTP identity, connected SQL graphs, repeat execution and
preserved failures establish more than startup or printed success.

**Concerns:** Use the dedicated launcher. The shared batch endpoint selector
still requires one network and cannot run this gateway's two-network layout.
Other versions, rotated/custom keys, HTTPS, alternative database backends,
unreachable private DNS, and SQL Lab/permalink RCE sessions remain separate
qualification work. A private hostname that the operator cannot resolve is
printed with a diagnostic but has no saved service/login. Selected logical
state comparisons exclude audit/login-history rows and SQLite file bytes.

**Suggestions:** Continue native-first version and RCE profiles independently.
The broader campaign remains active. No pull request is created.
