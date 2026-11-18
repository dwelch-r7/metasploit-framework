# Fetchmail credential collection target

This opt-in profile exercises `post/multi/gather/fetchmailrc_creds` using pinned
real Fetchmail and Dovecot in one target container,
a separate ordinary PostgreSQL reporting database and a genuine host Framework
console. The owner declares only shell sessions.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb fetchmailrc_creds
```

Native Fetchmail check-only controls authenticate without retrieving mail, trust
the explicit lab certificate, correlate successful Dovecot logins, reject wrong
passwords and unsafe/missing files, and verify message-content recovery. Each
selected home file must authenticate immediately before collection. Actual CSV
loot and session file bytes are checked independently; this owner does not
report credential cores. Native success does not by itself qualify collection.

Ten cases cover plain/repeated collection, quoted passwords with spaces, IMAP,
comments, blank/multiline/default configurations, multiple users, an unreadable
root file and an ordinary user's own file. Earlier invalid native option ordering
and artifact-mount preflight refusal are preserved separately from owner results.
Single quotes, quoted usernames and ESMTP have source-backed unit contracts with
no native authentication claim. Escape decoding and other syntax/platforms remain
unqualified; legacy escape bytes are preserved.
One serial stack has two capped containers: target 512 MiB/0.5 CPU and reporting
384 MiB/0.25 CPU, with equal memory/swap, PID128 and init. Published ports bind
only to loopback. Generated payloads/session markers and home files must be
recovered; all Docker resources must be removed before any result is counted.
