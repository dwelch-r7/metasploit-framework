# WP GDPR Compliance configuration and registration, 2026-11-17

Qualified one owner in four profiles with **22 passing public cases in one
aggregate with exit 0**, reaching **283 runtime owners in covered paths,
577 qualified profiles and 4,007 historical functional cases**. The wider
campaign remains active. No PR is created.

Owner: `auxiliary/admin/http/wp_gdpr_compliance_privesc`. Its source is unchanged
at SHA256 `533709a49710a6d6635a164e43b83538cedb85968791b03a3a288d7605d72b23`.
No owner defect or repair is claimed by this checkpoint.

## Reproduction and source scope

See the [target guide](gdpr_compliance/README.md) for preparation and serial
commands, and the
[module guide](../../documentation/modules/auxiliary/admin/http/wp_gdpr_compliance_privesc.md)
for options and retained-state recovery. The complete official 1.4.2/1.4.3
archives are pinned in [releases.json](gdpr_compliance/releases.json), with all
36 installed-file hashes per release. CRC/path/symlink and actual installed-file
checks pass. Vendor PHP, nonces, responses and mail generation are unchanged.

The [original Wordfence advisory](https://www.wordfence.com/blog/2018/11/privilege-escalation-flaw-in-wp-gdpr-compliance-plugin-exploited-in-the-wild/)
describes the guest settings issue. The actual source diff removes `save_setting`
from guest `process_action` in 1.4.3 and adds an authenticated settings action with
capability/option checks. The
[CVE-2018-19207 CNA](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2018/19xxx/CVE-2018-19207.json)
also describes broader SQL/RCE impact; those paths and whole-plugin security
are outside this settings/registration qualification. Authenticated settings
capability/allowlist code is source-verified, not independently runtime-qualified.

The selected runtime pins WordPress 6.8.3, PHP 8.3.28 and MariaDB 11.2.2, with
Linux/amd64 declared and observed in the prerequisite native runs. WordPress has
ordinary application grants. An ordinary PostgreSQL role starts with an empty
schema; Framework creates and uses its real reporting schema. Real version,
source, handler, URL/permalink, grant, account and selected configuration state
is observed before owning calls and again afterward.

## Preserved first failures

Independent native gates pass on both releases with 70 HTTP controls and six real
mail/reset/password flows before any owning call. Their first setup failures
are retained: WordPress caches a changed numeric option as an integer within the
writing request, and the actual reset redirect is root-relative. Corrections use
the core source contract, exact persistent values in a fresh process and the
actual reset form fields/action. No vendor or owner code is changed.

The first public aggregate has root 3 examples/2 failures/1 outside error and
fixed 3 examples/1 failure/1 pending. Native controls before the calls pass,
but complete controls afterward do not. A public account email contains the app's actual published
port, whereas native-created mail uses default 80. The harness initially rejects
that valid URL before password setup, then cleanup masks the original error and
leaves an account for the next attempt. Fixed closed registration is correctly
rejected, but unchanged numeric-option recovery hits a string/integer assertion.
Compose teardown removes those isolated failed stacks; individual account
recovery is not claimed for the first partial public account.

Three harness files are corrected among 114 initial declared inputs: accept only
default 80 or the exact declared app port on the same host/login path, distinguish
changed and unchanged option writes while verifying fresh persisted state, and
preserve original failures/contamination through all expectation errors. Account
password/permission proof precedes final outcome assertions so recovery remains
possible on a privilege mismatch. Owner/vendor bytes remain unchanged. This is
harness correction, not owner-only repair causality. The corrected initial
root/fixed cohort passes 6/0 with two administrators and one intended subscriber.
Neither these preliminary cases nor native controls are counted again below.

## Selected aggregate

| Profile | Release / condition | Cases | Admins | Subscribers | Native HTTP | RSpec seconds |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| gdpr_compliance | 1.4.2; root, options and negative edges | 13 | 5 | 0 | 92 | 190.7 |
| gdpr_compliance_fixed | 1.4.3; closed/open native registration | 3 | 0 | 1 | 54 | 63.0 |
| gdpr_compliance_subdirectory | 1.4.2; `/portal` | 3 | 2 | 0 | 72 | 76.4 |
| gdpr_compliance_plain | 1.4.2; verified plain permalinks | 3 | 2 | 0 | 72 | 78.9 |

Run `20261117T203623-4dcfc2` has zero failures, pending cases and outside errors,
and all teardowns pass. **Ten public accounts** comprise nine actual
administrators and one subscriber. Each consumes its own genuine WordPress
account email, follows the delivered reset link and real password form, then
passes native password, cookie, role/capability and actual user-management HTTP
checks. No password is assigned directly through SQL or a target API. Password
setup is an independent operator step: the owner neither supplies nor captures
that password. Repeats retain the same selected console module object and
recover state between executions. No Framework session qualification is claimed.

The root profile covers optional valid administration email, invalid optional
email ignored, valid 60/invalid 61-character usernames, username/email collisions,
invalid username/email, and genuine missing/login-page base inputs. Rejected
registrations really retain their earlier registration/default-role changes;
tests verify those changes before recovery. The missing base fails on a real 404.
The real 200 login-page base has no frontend nonce and is an invalid WordPress
base: the owner appends its AJAX/login paths. It eventually rejects registration
without changing options or adding an account. This is not presented as a
valid-AJAX missing-nonce owner path; native gates separately prove 403 rejection
of missing/incorrect nonces at the actual handler.

There is no AutoCheck in this owner. On 1.4.3, HTTP 200 from the former guest
settings action leaves all selected options unchanged. Closed registration fails;
when native registration is already open with the subscriber default, the owner
can register only a subscriber. Its password/login work and users-management
access is 403. Console warnings about setting options or a completed registration
are not privilege proof. Actual subdirectory and permalink state are verified.

Observed PostgreSQL workspaces contain **zero credential cores and zero loot**.
The original owner does not persist the new password. Three distinct scoped
vulnerability rows come from affected-version checks, not from administrator
authentication. Actual native authentication is separate from Framework
reporting. Sessions/jobs are empty after each profile.

## State, resources and limits

The owner retains its accounts and configuration. All **ten selected public
accounts** are deleted by separate native operator recovery after exact observed
ID/name/email/password and recent session-agent checks. Only named options with
the expected current values are restored; mail is deleted only after matching
captured basenames/SHA256. Baseline users/password hashes/roles/tokens/usermeta,
vendor options/tables, posts, selected configuration, source/config hashes,
complete upload trees and an empty spool match before/after. Real frontend/admin
and ordinary registration warm-up precedes the baseline; initial changes remain
recorded. Unrelated WordPress options, counters, logs, auto-increment state and
complete database restoration are outside that selected-state claim.

The aggregate records **290 native HTTP controls**,
40 actual cookie validations and
48 zero OOM/PID snapshots. One capped stack runs
at a time, with at most three containers totaling 1.75 CPUs/1,408 MiB. CPU,
memory/swap, PID/init and loopback settings are explicit and verified. All 20
attached volumes/networks are individually absent after teardown; unrelated
images and volumes are not pruned. PHP's local sendmail transport spools genuine
WordPress/PHPMailer messages inside the owned container. External mail delivery,
SMTP and deliverability are not qualified.

Changed Ruby syntax/RuboCop, PHP syntax, module-guide msftidy_docs and all four
Compose/input plans pass. No full RSpec suite runs. Historical human Scenarios
remain byte-identical. Private immutable native/public archives preserve first
failures, raw CLI/JSON/transcripts, source/state/resource observations and all
120 unique declared inputs. Publication CI is
separate and does not prove execution of these opt-in labs.

Other plugin/runtime releases, TLS, multisite, locales, arbitrary email formats,
external mail/activation configurations, transport-disconnect handling and the
broader advisory SQL/RCE paths remain unqualified.
