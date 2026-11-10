# Mail credential and message capture

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb capture_mail
```

This sixteen-case profile starts the actual SMTP, POP3 and IMAP capture modules
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
passwords, legal closing-brace/bracket credentials and commands without LOGIN.
Dovecot's fixture username policy explicitly adds only `}` and `]` to its default
whitelist; genuine curl and imaplib authentication prove the exact fields.
Every case repeats with a restarted job.

Exact credential/service/origin/workspace/UNTRIED checks, actual packet evidence,
reporting-schema limitations and cleanup follow the [core guide](../capture_core/README.md).
All listeners and client traffic stay inside owned container namespaces. The
mail services publish no ports. TLS/STARTTLS, OAuth, Yahoo cookie modes, literal
LOGIN transfers and other clients/platforms remain unqualified. IMAP completion
gates require one tagged CAPABILITY OK, one tagged LOGIN NO after capture, and
prompt non-timeout client completion (curl67 for the deliberate refusal; the
unauthenticated stdlib client exits0). The capture never validates a supplied
password against a real backend, and reporting stays UNTRIED. NOOP retains its
existing tagged NO response; complete IMAP-server conformance is unqualified.
Curl's actual transfer time and every case's result/wire are retained separately.
Framing/coalescence limits in the core guide still apply. Existing human Scenarios
are not generated or replaced.
