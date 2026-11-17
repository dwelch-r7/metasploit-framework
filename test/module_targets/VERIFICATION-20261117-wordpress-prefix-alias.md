# WordPress SQLi prefix alias qualification — 2026-11-17

The shared custom-prefix lookup generates an alphabetic SQL table alias.
That generator can return reserved words such as `AS` or `IN`. The original
query then fails to parse, so otherwise valid WordPress custom-prefix targets
can fail intermittently. Commit `5e223f7e811ac479ac26bbb2948c59b665699d5e`
quotes that generated identifier at its declaration and three references.
The alias remains random; the default-prefix probe and return contract remain
unchanged. No owner module or human module guide changes.

The same 27 local examples produce two failures on the original helper and
zero on the candidate, followed by another zero-failure candidate run, seed
51827. These include seven existing support examples. SQL transport, feasible
forced randomness and UI are doubled; these unit results alone do not prove
native SQL grammar or extraction.

The parent executes the real helper's captured SQL bytes unchanged in genuine
MariaDB 11.2.2, as ordinary `module_target@%` on `wp_root`. WordPress 6.8.3,
WooCommerce 9.3.3 and TI Wishlist 2.8.2 use the actual `wp_native_` prefix.
No default `wp_users` table is visible in that database; the unchanged default
probe returns no row. Original `AS` and `IN` queries return MariaDB error 1064.
Original `A` and `AbCdE`, and all four quoted candidates, return `wp_native_`.
Vendor source, users, product state and independent public HTTP/timing controls
pass before and after. This confirms the parser/data defect separately from
unit doubles. It adds no Framework functional cases or campaign counts.

The native target uses two capped containers: app 1 CPU/512 MiB and database
0.5 CPU/512 MiB, both with equal memory/swap limits, 128 PIDs and init enabled.
Eighteen native HTTP requests and eight zero OOM/PID-limit snapshots pass.
Both containers and all four attached volumes/networks are removed, individually
verified absent. The global container inventory is empty. No images are pruned.

Parent verification after importing the exact commit passes 161 examples with
no failures, pending or outside errors, seed 51827, on Ruby 3.3.13. This combines
SQLi libraries, WordPress prefix contracts, the existing owner alias contracts
and LiteLLM consumer contracts. Lint passes for both changed helper/spec files
and four new TI/WooCommerce test support files. Existing module qualifications
retain their recorded tested revisions; this unit/native proof does not rerun
every consumer module. The broader campaign remains active; no PR is created.

The final worker seal is
`/Users/dwelch/.codex/reports/wordpress-prefix-alias-final-20261117T054524Z-seal`,
manifest SHA256 `efa268ee46f3ac6e5e0c7ef0696f5e9bb954fdaf727163b4a9b303dd2ce2f9a0`.
The parent independently rehashes its exact 81-entry payload set. The native
80-entry seal is
`/Users/dwelch/.codex/reports/ti-wishlist-native-2.8.2-20261117T054226-seal`,
manifest SHA256 `698567895fbb3d0314e06c97c62803b00073fe15d5a667853606bf257a1e6ab0`.
It retains all eight unchanged SQL executions, native inputs/outputs, resource
counters and cleanup evidence. An earlier controller attempt fails before
startup because a query-input copy was skipped after the parent's manifest
sidecar check failed; it creates zero containers and performs zero module calls.
That harness failure is preserved separately from the successful native proof.
