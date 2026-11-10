# Flowise open and Basic authentication qualification

The integrated checkpoint is **180 runtime modules, 120 qualified families and
1,412 functional cases**. Flowise 3.0.0 open and Basic profiles qualify selected
customMCP/JavaScript command and session behavior. The other four Flowise
profiles remain unqualified; all original outcomes are preserved.

```sh
nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb flowise_300 flowise_basic flowise_305 flowise_306 flowise_311 flowise_312
```

## Actual results

Invocation `20261110T231530-1a375c`, worker revision `4e51558b3baf`, naturally
exits one. All six families finish with zero pending/outside errors and passing
Compose teardown. Only complete passing families contribute to the checkpoint:

| Profile | Cases/failures | RSpec seconds | Outcome |
| --- | ---: | ---: | --- |
| 3.0.0 open | 3/0 | 134.698037 | Qualified |
| 3.0.0 Basic | 1/0 | 77.946938 | Qualified |
| 3.0.5 JWT/account recovery | 3/3 | 20.308332 | Native replay oracle |
| 3.0.6 fixed JS/reset | 2/2 | 26.242838 | Native replay oracle |
| 3.1.1 npx/reporting | 2/1 | 129.341371 | Host session registry observer |
| 3.1.2 fixed npx | 1/1 | 11.694735 | Native package-manifest lookup |

Image download/extraction and service setup are outside these RSpec durations.
The first 3.1.1/3.1.2 images required downloading; no concurrent target project
was started during those operations.

The open profile repeats quiet customMCP commands, used JS fetch/Meterpreter
sessions, and unrelated/missing-path refusals. Exact command/file bytes, actual
app UID, payload PID/ancestry, remote exit, process absence, fetch-file removal
and scoped restoration are required. Both owning sessions complete. Basic
repeats both owners' commands and wrong/missing-credential refusals. Its Ruby3
caller repair passes option hashes positionally without changing their values,
the helper, owner code or assertions.

The separate native fetch calibration reads the exact cached encoded command
from its executing handler, runs those bytes as the real app user, uses a real
session and verifies file bytes, PID/ancestry and shutdown. The native Python
calibration also completes on 3.1.1. Neither calibration is an exploit verdict.
Native CLI/HTTP counts are 44/6 for open and 44/7 for Basic.

## Retained unqualified paths

Both SMTP profiles now deliver real recovery mail, reset the password with its
actual token and accept a fresh login. Their native helper then expects HTTP400
for a consumed-token replay; both real releases return HTTP500 with the exact
transaction-not-started error. Pinned source checks the token before beginning
a transaction, then masks that refusal with an unconditional rollback error.
The current helper replays the same password, so post-replay state, denial and
distinct old/new-password behavior are not proved. Owning assertions never run;
the five RSpec failure labels are not five module defects.

Installed mailer bytes and resolved Nodemailer identity are retained. Only
3.0.5/3.0.6 enable literal `ALLOW_UNAUTHORIZED_CERTS=true` for unverified local
SMTP TLS. Exact delivered MIME proves authenticated TLS1.3 transport on both.
The earlier strict diagnostic rejects the disposable peer's 1970 expiry and
remains immutable. Trusted SMTP certificates are not qualified; shared Exim and
global Node TLS settings are unchanged.

The first 3.1.1 owning Python shell opens and is used. Target ancestry/PID absence
passes after remote exit, then the test times out expecting automatic host
session deregistration. The second positive iteration is not reached. The JWT
negative case passes, but the whole family remains unqualified. Supported host
shell closure after remote proof is being investigated separately; no production
session repair is claimed.

The 3.1.2 native identity helper cannot resolve the components package's private
`package.json` subpath because of its exports policy. The main package matches
3.1.2; components bytes and fixed-owner behavior remain unmeasured. Future lookup
correction must retain installed package/name/version and publisher-hash gates.

All three fixture investigations use a separate worktree. No failed result is
rewritten or counted as qualification. Windows, application HTTPS, other release
branches/roles/payloads, concurrent cleanup and the CSV/model-based owner remain
pending as described in the [shared guide](flowise/README.md).

## Parent verification and cleanup

All 102 selected inputs and six maps of 85/85/85/86/84/84 verify against the
integrated source. The parent imports and byte-verifies all 365 invocation files,
including eight files under hidden paths. All 483 immutable export entries verify:
`/Users/dwelch/.codex/reports/flowise-six-local-mixed-20261110-4e51558b3baf/`,
`SHA256SUMS` digest
`88b5445ea6ace1a8ef970fec1ed2ea340af84c8cd87ebb13378bae7511aeee94`.
The export retains all six results, inputs, TLS messages, replay/source and
session forensics, and parent cold/resource/terminal receipts. Earlier failures
and the strict 138-entry mail diagnostic remain separate.

Parent verification passes 47 focused examples (40 direct and seven ancillary),
seven-file Ruby lint, Python syntax and four module-document checks. Production
owners, shared libraries, runner and human Scenarios are unchanged.

One project runs at a time, with three or four containers and declared totals
of 1,888–2,144 MiB / 2–2.15 CPUs. The parent observes the genuine first prompt,
matching isolated BOOT and two fresh parsed atomic metadata snapshots without
manual seeding; later families use normal within-invocation reuse. After natural
aggregate termination, 61 fresh parent queries prove all 22 exact containers,
twelve networks and eight volumes absent, eighteen label inventories empty and
global container inventory empty. The broader campaign remains incomplete.
