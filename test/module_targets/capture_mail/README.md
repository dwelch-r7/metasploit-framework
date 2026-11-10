# Mail credential and message capture

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb capture_mail
```

This fourteen-case profile starts the actual SMTP, POP3 and IMAP capture modules
through Framework jobs and connects genuine Python/libcurl clients. Existing
Dovecot 2.3.16 and Exim 4.95 fixtures independently authenticate those clients
first. Dovecot's real password-file update is reloaded; a genuine Exim plaintext
and CRAM configuration validates the exact fixture password, including spaces,
colon, quotes and backslash. No real mail account or remote recipient is used.
The family override gives Exim's appendfile transport an existing working
directory and a fixed local sink, avoiding an absent account home and a tainted
recipient-derived filename. Native messages remain inside that owned fixture.

SMTP covers LOGIN challenge and initial response, PLAIN challenge/initial,
CRAM-MD5, EHLO without credentials and DATA with a normal message or a legal
RSET body line. The actual CRAM challenge/response is independently verified
with HMAC-MD5 and must be stored as a nonreplayable hash. Captured SMTP message
bytes are checked against the actual client DATA payload through direct SQL
and the existing model codec. Focused owning regressions also replay actual
Exim-accepted dot-stuffed DATA and a split dot terminator. The capture retains
raw transmitted body bytes, including dot stuffing, rather than producing a
decoded mailbox message. POP3 covers password edge fields, a rejected
fixture password and USER without PASS. IMAP covers ordinary/escaped quoted
passwords and commands without LOGIN. Every case repeats with a restarted job.

Exact credential/service/origin/workspace/UNTRIED checks, actual packet evidence,
reporting-schema limitations and cleanup follow the [core guide](../capture_core/README.md).
All listeners and client traffic stay inside owned container namespaces. The
mail services publish no ports. TLS/STARTTLS, OAuth, Yahoo cookie modes, literal
LOGIN transfers and other clients/platforms remain unqualified. The existing
IMAP server also emits an extra CAPABILITY response and leaves LOGIN without
a tagged completion, so a client can time out after credentials are captured.
This profile qualifies the capture/reporting path and records the actual client
status; it does not claim a completed IMAP login conversation. Existing human
Scenarios are not generated or replaced.
