# Capture protocols and integrated checkpoint, November 10

Current recorded inputs, exact passing counts and owned teardown establish
**142 runtime modules, 71 families and 976 functional cases**. This adds six
capture modules, two [Flink modules](VERIFICATION-20261110-flink.md) and
[ActiveMQ Jolokia](VERIFICATION-20261110-jolokia.md) to the preceding 133-module,
66-family, 902-case checkpoint. It is a selection of qualifying retained runs,
not a full RSpec run or completion of the repository-wide campaign.

The registered WordPress admin-session family remains excluded. WordPress and
Ansible failures are indexed in [deferred investigations](DEFERRED.md). NFS,
legacy ActiveMQ and additional database capture modules remain separate work.

## Capture results

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb capture_core capture_mail
bundle exec rspec spec/modules/auxiliary/server/capture
```

Final invocation `20261110T023017-6c7915` completed naturally:

| Profile | Cases | Failures | RSpec seconds | Current inputs |
| --- | ---: | ---: | ---: | ---: |
| `capture_core` | 16 | 0 | 191.847587 | 62 |
| `capture_mail` | 16 | 0 | 101.064872 | 56 |

Both have zero pending/outside-example errors and passed teardown. The parent
copied and byte-checked all 485 files in the complete invocation, preserving its
original revision, paths, commands and isolated atomic metadata snapshots. All
62/56 recorded input hashes match the integrated checkout. Exact parent resource
audits cover the earlier and final imported generations: four runner projects
and six recorded volumes are absent. The follow-up's independent audit covers
all seven native/runner projects and seven volumes, also absent.

Real libcurl, libpq and Python clients connect to the actual Framework capture
jobs. Independent genuine ProFTPD, Apache, PostgreSQL, Exim and Dovecot controls
establish that their protocol/authentication setup works first. Native gates in
the final invocation record 56 CLI commands and 23 actual packet captures;
Framework cases record 64 client programs and 64 packet captures. Listener jobs
restart on the same port and repeat each ordinary operation.

Direct SQL verifies 22 scoped credential rows and two SMTP notes: exact client
address, listener service/port, module/service origin, private bytes/type,
workspace graph, UNTRIED status and unset validation timestamp. No-auth and
unsupported-auth controls remain empty; repeated captures do not duplicate
credentials. Installed credential 6.0.26 has no persisted login `proof` column;
wire/client proof is retained externally, not claimed as database persistence.
Capture does not establish a validated login to a real target.

## Source repairs and failure attribution

The initial 30-case campaign retains genuine native controls and all failed
generations. Early failures included fixture service-name/HTTP-status assumptions
and an empty redirect setting that selected a different branch. Correcting those
assumptions before changing the six original modules leaves core 16/3 and mail
14/4. Separate owning repairs address these observed paths:

| Module | Corrected behavior |
| --- | --- |
| `auxiliary/server/capture/ftp` | Preserve password argument spaces. |
| `auxiliary/server/capture/http_basic` | Accept case-insensitive Basic with a token; ignore other authentication schemes. |
| `auxiliary/server/capture/postgresql` | Accept genuine direct Startup as well as the existing optional SSLRequest path. |
| `auxiliary/server/capture/smtp` | Handle LOGIN initial responses and preserve RSET text inside DATA until the actual terminator. |
| `auxiliary/server/capture/pop3` | Preserve password argument spaces. |
| `auxiliary/server/capture/imap` | Decode quoted LOGIN fields, preserve legal bare closing braces/brackets and complete captured commands. |

The first six repairs reproduce focused 42/16 to 42/0 and then pass all original
30 runtime cases. Independent parent review finds an extra closing-brace
exclusion in the quoted-field parser before publication. Genuine Dovecot/imaplib
controls establish that `}` and `]` are legal astring bytes. Dovecot's fixture
account whitelist explicitly adds only those two characters; this is not claimed
as its default account policy. Malformed opening-brace controls remain separate.

The frozen follow-up baseline `20261110T021839-ded9b4` passes core 16/0 but fails
mail 16/5: closing-brace credentials are missing, three correctly captured LOGIN
paths time out, and the unauthenticated command client fails. A first separate
commit removes only the extra `}` exclusion. A second returns after CAPABILITY
OK and sends one LOGIN NO after capture, reusing the existing refusal text.
The identical focused corpus reproduces **50/3, then 50/2, then 50/0**. Canonical
before/final key sets are identical; core changes no recorded input and mail
changes only its owning IMAP source. The 49-file source/unit/native freeze maps
also change only that source.

Final genuine IMAP clients have one matching tagged completion per command.
Eight credential clients finish with deliberate curl authentication refusal 67;
two unauthenticated clients finish zero. Measured curl transfers are
0.081729–0.176014 seconds, versus 2.001576–2.003216-second baseline timeouts.
Credentials remain UNTRIED. No shared parser, stream, runner, dependency or
timeout change was used.

Parent focused tests pass all 50 examples. Changed IMAP and acceptance Ruby lint
is clean. Module tidy retains its existing informational notice. IMAP module-doc
tidy retains the same legacy findings/status as the canonical original;
human-written Scenarios remain byte-identical. New source, regression and lab
changes remain separately committed.

## Durable evidence and limits

The unchanged initial export is
`/Users/dwelch/.codex/reports/capture-protocol-validation-20261110-814db68c7cd9`:
2,011 checksum entries independently verified by the parent, manifest SHA-256
`cad0b121453b4ec19e91bd7d39cf314d287613b51bcba45472e166416778be77`.
The additive follow-up is
`/Users/dwelch/.codex/reports/imap-capture-completion-20261110-b5543cae01e9`:
the parent independently verifies all 1,365 entries in `SHA256SUMS`, whose SHA-256
is `84ca295f80f0f3a2302378803831ce2a4408e96af80be863d162712d45cc57b1`.
Both retain frozen source/input maps, native controls, failures, actual wire,
SQL/schema data, unit comparisons, cleanup and separate patches. Raw evidence
stays outside Git; neither prior results nor historical seals are rewritten.

Parent verification outputs, the complete selected checkpoint and inventory are
sealed separately at
`/Users/dwelch/.codex/reports/module-target-parent-validation-20261110-fbc8976cd98`.
All 39 checksum entries were re-read; `SHA256SUMS.json` SHA-256 is
`b2560c317b2935a5e9956a585655d3ec4e5fa643bce8e72c527a7b20538f6137`.
This retains parent unit/lint/doc outputs, byte-import/source/export checks,
independent image comparisons and exact resource/volume absence receipts.

TCP listeners must close. HTTP pooled jobs instead require owned-route 404,
an unaffected 401 guard, no guard credentials and empty owned resources afterward;
their pooled listener is not assumed to close unconditionally. Full transport
framing/coalescence, long/malformed commands, TLS/STARTTLS, GSS/OAuth, IPv6, other
clients/platforms and complete protocol-server conformance remain unqualified.
Literal/Yahoo compatibility checks are derived unit controls, not native runtime
qualification. SMTP preserves raw dot-stuffed DATA bytes. The
[core](capture_core/README.md) and [mail](capture_mail/README.md) guides record
these boundaries and the actual clients/setup.
