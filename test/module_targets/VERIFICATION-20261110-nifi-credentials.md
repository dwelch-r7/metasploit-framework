# NiFi credentials and integrated checkpoint, November 10

Current input hashes and complete passing records establish **169 runtime
modules, 99 families and 1,276 functional cases**. One module adds 11 cases to the
[SMB directory checkpoint](VERIFICATION-20261110-smb-directory.md). The full
campaign remains incomplete.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb nifi_credentials
```

The four-container lab uses genuine Apache NiFi 1.21.0, Apache, PostgreSQL and
Framework. NiFi retains the vendor startup and runs as service UID1000. Public
fixture accounts and independently inspected PKCS12 stores provide real stored
configuration; GetHTTP authenticates to the actual Apache endpoint. Disabled
database/Azure configuration supplies stored-secret controls, without claiming
external database or cloud authentication.

Current invocation `20261110T121923-913a1d` passes **11/0** in **430.831474 RSpec
seconds including console bootstrap**, with zero pending/outside errors and
successful teardown. Runtime source revision is `c5f5fbc846f`; parent source/lab
commits are `b8c2f77c91a` and `d74097f6dd9`. Parent imports and byte-checks the whole
156-file invocation and verifies all 73 selected input hashes.

All 22 module calls complete. Eleven actual shell/Meterpreter sessions open,
execute target identity/proof commands and close; native launch PID receipts and
container lifecycle events remain recorded. Positive collection repeats through
both declared session types as the NiFi user, plus a root shell. Other cases cover
genuinely unreadable files, explicit paths containing spaces, missing files,
identity-only data, a missing key, unsupported encryption and a corrupt GCM tag.
Boundary copies are explicitly derived from real vendor files; they are not
claimed to be accepted live NiFi configurations.

Native preflight, snapshots and final canary comprise 24 successful actions,
217 CLI records and 109 HTTP records; 115 separate harness/SQL commands remain
distinct. Vendor runtime bytes, application version, auth, native files and real
component graph are checked independently. Node's built-in crypto decrypts seven
actual stored fields for comparison. All eight decrypted-loot JSON trees equal
those independently derived native values. Fourteen properties and twelve original
flow loot files retain the expected bytes.

SQL has 28 cores: 20 Password and eight NonreplayableHash. Each complete positive
workspace has six repeat-stable cores, including five Password records and the
native identity hash. Four password records have actual null public identities;
keystore filenames and Azure managed-identity labels are not invented usernames.
Every record retains the actual session/workspace origin. Stored configuration
does not create a successful service login or authentication claim.

Separate source fixes preserve plaintext as JSON string values, including quote,
backslash, Unicode and literal substitution escapes; associate the private-key
password with its keystore; persist recovered secrets; preserve identity collection
at partial-file/expected crypto boundaries; and reset discovery/crypto state on
repeated use. Matched capture-backed focused tests reproduce **26/19 → 26/0** with
only the owning source changed. Parent independently passes the same 26 examples.

The original mixed run `20261110T110556-ef8125` retains 11/7, including a fixture's
VERBOSE fallback-file messages. Using the actual public default VERBOSE=false
with unchanged assertions gives corrected-original `20261110T113803-8848a1`,
also 11/7. Its independently valid setup establishes wrong key-password association,
invalid quoted-secret JSON, missing plaintext credential cores, identity-only and
missing-key exceptions, and an unhandled corrupt authentication tag. These failures
remain preserved rather than being reclassified as passing. An earlier startup
deadline and native API persistence race are separate setup records.

Actual corrected-original and repaired image inspection proves identical RootFS
layer arrays, architecture and creation timestamps. Framework/NiFi/Apache image
IDs differ only through the Compose project label; PostgreSQL retains its image
ID. That measured comparison does not retroactively establish identical images
for the earlier failed startup. Cached-build output and full image inspection
remain evidence.

Parent four-file RuboCop, actual module/docs tidy, selected dry11/excluded dry7,
two Python syntax checks and two Node syntax checks pass. All original 20,772
human-written documentation bytes remain unchanged. No full local RSpec suite is
claimed. Other NiFi versions, operating systems, nested flow groups, Azure
authentication and Azure authorizer branches remain unqualified.

Parent independently verifies all 13 exact owned resources absent: four container
IDs, one network and eight volumes. Three project-label queries are empty. At the
user's subsequent explicit request, 31 unrelated containers (14 running and 17
nonrunning) are removed while their images/volumes are preserved. Docker is empty
before the next Druid run. Only this campaign's containers may run; each project
retains the [five-container serial limit](CAMPAIGN.md#local-execution-limit) until
natural completion and teardown.

Parent independently verifies the original 203-entry and corrected-original
207-entry seals, respectively SHA-256
`703dfc8655f1c0be93966afc0f8dee5779cc5453ec695d2d655a4a761b6a8416` and
`d0d2f5a9574fc87327f963f371fb8a3a6bba9b77036968e27e3061160213fa78`.
The 19-entry parent receipt seal is
`/Users/dwelch/.codex/reports/module-target-parent-validation-20261110-d74097f6dd9`,
manifest SHA-256
`ca9646c9b6f0a7148595a104e130f339cc8869dceb9c12fabd52a82b427b7550`.
