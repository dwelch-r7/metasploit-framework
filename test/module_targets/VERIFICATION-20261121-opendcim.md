# openDCIM SQL command transport

The new [openDCIM profile](opendcim/README.md) passes **6 examples / 0 failures /
0 pending**, with six actual command executions. Native controls distinguish
four setup/harness faults from a confirmed SQL quoting defect. The minimal source
repair is prepared in isolated commit `fe09ea6f3a3` and integrated as
`22c84f8c3b5`. No PR is created; the broader inventory goal remains active.

## Native target and prerequisites

The official `opendcim/opendcim:24.01-beta` image is pinned by digest and actually
reports **24.01**, PHP **8.1.2-1ubuntu2.14**. The database is pinned MariaDB
**10.11.9**. Apache supplies `REMOTE_USER=dcim`, matching the SetEnv deployment
mode in the existing documentation. These results do not establish Basic Auth,
LDAP authentication or any other release. The original container installer
creates/upgrades the database; application source is unchanged.

[vendor.json](opendcim/vendor.json) pins seven installed source fingerprints and
the observed runtime versions and 145 configuration rows. The actual installer
is also fingerprinted and resolves to `container-install.php`. The vendor's
normal PDO connection sets session SQL mode to an empty string; the native
probe records that state. Thirteen LDAP values are seeded non-empty. All 145
full configuration records and the complete table-name registry must survive
each public module operation; original factory values restore afterward.

Native controls require real Graphviz SVG rendering, a stacked SQL request
that creates an independently read proof row, and a rich command run through
the real report endpoint using a parameterized configuration setter. Every
exact owning command then repeats that independent control, including its
alias route. The native proof is removed and absence verified before actual
module delivery, preventing a stale proof from satisfying the owning test.

The [original advisory](https://www.vulncheck.com/advisories/opendcim-sql-injection-in-config-updateparameter)
describes the unsafe configuration-update channel. Qualification here rests on
the actual pinned image and native behavior rather than its tag alone.

## Confirmed module fault

The valid original frame has **6/1/0**. Plain commands and the `/dcim/` alias
work twice each; the quoted command reaches `poison_dot` byte-for-byte but
creates no proof. The same command succeeds through its independent native
control. The installer still returns 302, and the report returns an ordinary
SVG instead of the redirected command's empty response. HTTP success alone
therefore does not establish successful SQL mutation or command execution.

Executing the captured generated SQL directly against native MariaDB produces
`SQLSTATE[42000]` / syntax error 1064 around the double-quoted argument. A second
control expresses the unchanged command bytes as a SQL hex string: the stored
`HEX(Value)` matches, and both direct SQL and the actual vulnerable form produce
the exact UID-33 file. Configuration and table state restore after both controls.

The source fix replaces manual backslash escaping with a SQL `X'...'` string
using the existing `Rex::Text.to_hex` helper. It preserves shell quotes,
backslashes and command bytes across the SQL parser. The string-literal choice
is documented by [MariaDB](https://mariadb.com/docs/server/reference/sql-structure/sql-language-structure/hexadecimal-literals).
Module options, targets, payload selection, check behavior and return shapes
stay unchanged. No owning method or vulnerable application component is stubbed.

## Maintained result

| Example | Result |
| --- | --- |
| Native SVG, stacked SQL and rich-command calibration | Pass |
| Original reason-bearing timed SQL check, with configuration preserved | Pass |
| Natively refused TCP connection returns Unknown | Pass |
| Plain generic command, twice on one selection | Pass |
| Quotes, backslashes, Unicode and physical CRLF, twice | Pass |
| Native-calibrated `/dcim/` base path, twice | Pass |

The final functional duration is **96.56 seconds**, excluding container startup.
Passive traces retain original requests/responses, commands, SQL and source
locations. Data reaches the public module through the real datastore; physical
CR/LF is preserved using the established direct-assignment pattern. Actual
command bytes, hex-decoded SQL values, UID-33 file bytes, distinct backup names,
full configuration and table restoration, and empty Framework jobs/sessions
are checked. All six temporary backup tables and proof files are absent afterward.

## Retained harness failures and checks

An initial image inspection assumes `classes/Config.class.php`; the installed
class actually lives in `config.inc.php`. That stopped inspection container is
removed. The first health predicate incorrectly expects an LDAP form after
installation; captured 302-to-index and index-200 responses identify the mistake.
The phase is deliberately interrupted and cleaned before correcting readiness.

The first maintained frame has **6/1/5** because a metadata query uses a reserved
SQL alias. No owning call occurs. The next has **4/1** and ends early because
physical newlines split a console command; the command never reaches the module.
Direct datastore assignment repairs that harness transport while retaining the
same command data and exact-byte assertions. Only the following **6/1/0** frame
is attributed to the confirmed module SQL defect. All inputs/results are retained
separately from the successful repaired frame.

Source and the three new Ruby files pass RuboCop. Standard module msftidy,
documentation tidy, Compose and Python parsing pass. The existing manual
Scenarios section remains byte-for-byte unchanged. The final native gate also
requires the observed exact PHP/database versions and 145 configuration rows;
earlier captures independently show those same values.

The current set reaches **78 cases across 23 profiles**, retaining **28 used/closed
OS sessions** with no new sessions counted here. All **261 declared inputs**
match current files; **140 current cgroup captures** are zero. Historical coverage
is **325 owners in stated runtime paths, 693 profiles and 4,853 cases**. Registration
and these path counts do not establish full module or inventory completion.

All **23 new / 531 recorded Docker objects** independently verify absent.
Global running/stopped containers and owned ephemeral networks/volumes are empty.
Stacks run serially with two capped services: 768 MiB/0.8 CPU for the application
and 384 MiB/0.4 CPU for MariaDB, equal memory/swap limits and 128 PIDs each.
No worker or Docker-backed connector is initialized in this tranche.

Reverse sessions, the dropper target and architectures, authentication variants,
other releases and patched behavior remain unqualified. These opt-in Docker
tests do not run in ordinary unit CI; exact published-head CI remains separate.

## Self-review

| Area | Assessment |
| --- | --- |
| Summary | One native-gated owner profile and a confirmed SQL transport repair. |
| What looks good | Exact per-command controls, before/after SQL diagnosis, repeated real execution and complete configuration preservation. |
| Concerns | Session, dropper, auth and release variants remain outside this profile. |
| Suggestions | Qualify those feasible execution paths next; continue the full module queue without treating registration as proof. |
