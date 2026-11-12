# 4gaBoards user information disclosure lab

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb 4gaboards_3_3_8 4gaboards_3_3_9 4gaboards_registration_disabled 4gaboards_unrelated
```

These serial profiles use the genuine vendor 3.3.8 and 3.3.9 images, with their
normal Node startup and PostgreSQL schema. Images and relevant controller sources
are pinned in [profiles.json](profiles.json). Upstream
[3.3.8](https://github.com/RARgames/4gaBoards/tree/v3.3.8) returns full profiles;
[3.3.9](https://github.com/RARgames/4gaBoards/tree/v3.3.9) sanitizes other users'
fields for non-administrators. The fixed profile must not report this CVE merely
because the public user list can still be collected.

Native controls establish ordinary pages, source/process identity, real schema,
accepted/rejected database and administrator authentication, unauthenticated and
invalid-token rejection, registration, duplicate email rejection and affected or
fixed API behavior. The seeded administrator's phone, organization and SSO email
are public fixture values written to the real application database before tests.
No endpoint or module method is replaced. Registration-disabled and unrelated
Apache controls supplement version coverage.

Functional cases use the public module entry point, inspect complete JSON loot
and real Framework service/vulnerability/loot SQL, and verify account state in
the separate application database. Administrator username/email, missing and
partial credentials, bad password, normalized email, duplicates, invalid email,
missing paths, refused ports and repeats are covered. Native cleanup removes any
active per-example account after its observed state has been asserted. The vendor
uses soft deletion; historical user/action rows are expected until lab teardown.
No external mail or SSO provider is contacted or authenticated.

Only one profile runs at a time. Application profiles have three containers
including Framework, capped at 1,344 MiB and 1.55 CPUs total. PostgreSQL and
application upload directories use bounded tmpfs; only target HTTP is published,
on a random loopback port. Apache control has three containers capped at
960 MiB/1.3 CPUs. Teardown removes the project before the next profile starts.

Registration and fixture checks are not qualification. Consult the campaign
verification report for actual results and any unresolved failures.
