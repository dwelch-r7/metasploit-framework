# HTTP proxy and Linux collection qualification

The selected checkpoint covers **102 production runtime modules, 41 families
and 592 functional cases**. Every selected result has its exact expected count,
zero failures/pending/outside-example errors, matching current recorded input
hashes and successful owned teardown. Relative to the
[preceding checkpoint](VERIFICATION-20261109-multicall.md), Linux collection adds
two modules/eight cases and HTTP proxy detection adds one module/twelve cases.
The repository-wide campaign remains active. No pull request was created or
full local repository RSpec suite run.

## Reusable targets and controls

| Family | Independent controls and meaningful coverage | Cases |
|---|---|---:|
| [Linux history/hash collection](linux_history/README.md) | Digest-pinned Ubuntu 22.04, native account tools/libc password verification, exact file bytes and denied reads; genuine root/nonroot shell and Meterpreter sessions | 8 |
| [HTTP forward proxy](http_proxy/README.md) | Digest-pinned Apache 2.4.62, genuine forwarding and HTTPS tunnels, native Net::HTTP/Socket clients, denied/unrelated/unavailable endpoints | 12 |

Linux retains all 22 actual system accounts. Native Python 3.10.12 checks
readability and SHA-512 shadow credentials before modules run. Cases assert exact
passwd, shadow, password-history and user-history loot, locked-account exclusion,
empty/missing histories and a home directory containing a space. Root enumerates
all accounts once per session API; bounded current-user history and every
hash/refusal path repeat. Each example establishes a fresh proven session.
Seeded history files test collection; they do not qualify the corresponding
database clients, shells or editor. Empty native login databases do not qualify
real login-event parsing. Fifty-three recorded native commands exit zero.

Proxy controls establish actual GET forwarding and HTTPS through CONNECT on
443 and 8443, including destination bytes and certificate identity. They verify
403 access refusal, unrelated HTTP 200 content/CONNECT 405, and a permitted but
unavailable destination returning 503. Nine native operations precede module
assertions; additional independent raw wire captures establish response framing.
Module traces retain exact CONNECT authorities. The detector itself reports
potential openness from status; native HTTPS controls prove the fixture tunnels.
Only random loopback ports are published; handlers remain inside owned networks.

## Failure classification and repairs

Early proxy attempts failed preflight checks before invoking modules. Those
were native-client exception/configuration expectation errors, not module
defects. After correcting preflight, genuine module results were **12/4 ->
12/3 -> 12/0** failures:

- CONNECT URL processing removed hostname characters and folded explicit ports
  into the hostname. Actual requests used `deinaion8443:443` instead of
  `destination:8443`, producing Apache DNS failures. A scoped authority helper
  preserves explicit ports, retains the historical absent-port default of 443,
  formats IPv6 through the existing helper and refuses invalid configuration.
  GET behavior is unchanged. Focused regressions: **30/21 -> 30/0**, comprising
  23 owning examples and seven shared support examples.
- Correct authorities exposed header-only CONNECT 200 replies waiting for a
  nonexistent HTTP body. No suitable existing header-only API was available;
  partial-response mode merely deferred the problem until timeout. The response
  parser now completes successful CONNECT at its header boundary, and the client
  preserves following tunnel bytes in `bufq`. The response-owned Boolean
  predicate remains false on initial/reset/error paths. This follows
  [RFC 9110 section 9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6).
  New focused regressions: **31/15 -> 31/0**, comprising 24 owning examples and
  seven shared examples, with zero pending/outside errors. The combined relevant
  four-file HTTP suite has **99 total: 91 passed, eight pre-existing pending,
  zero failures/outside errors**. Native wire captures are distinguished from
  derived framing, 2xx, reset and malformed-response boundaries.

Authority and shared-library repairs are separate commits. The final proxy
manifest explicitly adds packet/response/client dependencies; earlier native
results retain their original smaller input set. Raw result metadata was not
rewritten to imply identical dependency keys across that expansion.

Linux's first two eight-case runs each had four harness failures: a final
newline removed by the session command API, then an attempted session-sharing
optimization conflicting with deliberate common cleanup. Fresh sessions and
the documented command-output boundary resolve those issues; exact file-byte
assertions remain. Production Linux module source is unchanged.

## Integrated regression and evidence

After integrating the shared HTTP change, one invocation passes **all 75
HTTP/WebDAV/WordPress functional cases**, with exact counts, no pending/outside
errors, current hashes and teardown. This refreshes WebDAV's changed recorded
response dependency and checks ordinary HTTP methods, authentication, XML-RPC,
HTML, redirects, listing and mutation behavior. Other families were not all
rerun for this guarded CONNECT change; their selected recorded inputs remain
current. Recorded hashes are a declared input set, not a complete dependency graph.

- Linux final: `tmp/module-target-tests/20261109T180700-73c916/linux_history`,
  eight cases, 247.782745 seconds including bootstrap/native controls.
- Proxy original: `tmp/module-target-tests/20261109T180440-31adbe/http_proxy`;
  authority-only: worker invocation `20261109T180929-899142/http_proxy`.
- Proxy final: `tmp/module-target-tests/20261109T182351-a0640e/http_proxy`,
  twelve cases, 60.653817 seconds including bootstrap/native controls.
- Integrated regression: `tmp/module-target-tests/20261109T182533-78dc73/`;
  HTTP 14/40.997034 seconds, WebDAV 22/114.138965, WordPress 39/95.340144.
- Aggregate selector: `tmp/module-target-checkpoint-proxy-history.json`.
  Its sole warning names unqualified WordPress admin upload.

All 130 imported Linux and 48 imported proxy regular files were verified
byte-for-byte, with 42 and 39 final input hashes matching the parent. Original
worker revision, paths, commands and project identity remain intact. Durable
exports preserve diagnostic and unit evidence; all 214 proxy export checksums
were independently verified. Resource audits find three Linux and five proxy
projects empty. The three integrated regression projects are empty, with all
five recorded anonymous volumes absent. No unrelated resources were changed.

New specs/probes have no lint offenses. Existing source diagnostics remain
without additions; syntax, diff, module tidy and documentation comparisons pass.
Existing human Scenarios remain intact. Other OS/hash profiles, missing optional
`opasswd`, proxy authentication/chains, live IPv6, multiport discovery and
Framework database credential persistence remain unqualified. Existing WordPress
native JSON 2 encoding warnings remain an explicit limit; JSON 3 is unqualified.

## Retained investigation and remaining work

The [WordPress admin reproducer](wordpress_admin/README.md) is now retained in
the repository with a prominent unqualified status and observed seed 7721.
Its narrow upload-permission check repair is independent: matched ordered
diagnostics pass **20/5 -> 20/0**, focused examples **21/9 -> 21/0**, and the
integrated-source focused rerun passes 21. It does not add passing module coverage.

Full-suite staged-session attempts reproduce a reconnect burst and retain null
counts after controlled interruption. A bounded observer case completes with
one failure and successful teardown. Native controls, explicit remote exit,
prior-handler teardown and fresh stage/configuration observations narrow the
investigation toward Meterpreter bootstrap/`core_loadlib` and packet transport.
TLV logs include successful negotiation replies but lack session/socket labels;
missing decoded replies do not establish wire silence or a server exception.
No upload-module cause or session repair is claimed. All 338 session-export and
95 permission-export checksums were independently verified and preserved.

Eight source-hashed reviews now identify concrete separate kernel/OS/device/host
requirements, including two cgroup container escapes requiring disposable VM
hosts. They are not blanket infeasibility decisions. Ansible native controls
have passed and its original-source gather baseline is underway separately;
it is not included in these totals. Hundreds of documented container hints and
other unreviewed modules remain in the campaign queue.

At preceding published revision `c54794e65bf`, Lint, LDAP and PostgreSQL CI passed,
six workflows remained queued and
[Verify failed](https://github.com/dwelch-r7/metasploit-framework/actions/runs/42668769457)
in Ruby 3.2 on the existing certificate/SID example: OpenSSL rejects
`ms-ntds-sec-ext` with `first num too large`. Owning source/spec are unchanged;
the cause remains unclassified. Inspect new pushes separately; there is no
overall green-CI claim.
