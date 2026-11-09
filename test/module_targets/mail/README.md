# POP3 and IMAP targets

Run from the repository root with Python 3 available for independent clients:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb mail
```

Five genuine Dovecot instances share a digest-pinned Ubuntu 22.04 image, pinned
2.3.16 Ubuntu packages and a single-message Maildir. Separate random loopback
ports expose POP3, implicit TLS POP3, IMAP, implicit TLS IMAP and a POP3 listener
requiring TLS. The public credential is `module_target` / `module-target-password`.
There is no SMTP service, external delivery, host mailbox or database dependency.
The generated image-local key/certificate belongs only to this public lab.
Its ten-year certificate validity is checked by the native clients; rebuild the
image when it expires. Transitive OS packages can drift on rebuild, so installed
package versions and image IDs are retained.

Configuration uses Dovecot's real
[passwd-file authentication](https://doc.dovecot.org/2.3/configuration_manual/authentication/passwd_file/)
and [static user database](https://doc.dovecot.org/2.3/configuration_manual/authentication/static_user_database/).
Python's standard-library POP3/IMAP clients independently authenticate, read the
actual message, reject wrong/unknown/blank credentials and validate TLS against
the explicit lab certificate. Host-side clients also check the TLS-required
listener from outside its loopback trust exception. Native STARTTLS reads prove
that listener can serve the mailbox after upgrading; no module STARTTLS support
is claimed. Periodic health checks authenticate without changing mailbox data.
Native authentication reads allow twenty seconds for Dovecot's retained
[per-IP authentication penalty](https://doc.dovecot.org/2.3/configuration_manual/authentication/auth_penalty/),
whose maximum is fifteen seconds. Ordinary connects/readback stay bounded at
five seconds; the module keeps its existing sixteen-second PASS response wait.

Thirteen functional cases cover both banner modules over cleartext/implicit TLS,
repeated successful POP3 logins, rejected passwords/users/blank/anonymous
credentials, refusal of cleartext login under TLS policy, and an actual IMAP
negative for the POP3 login scanner. Banner expectations come from the native
server responses. Mailbox counts and actual contents are checked again after
the module cases. Framework uses `SSLVerifyMode NONE` solely for the lab's
self-signed certificate; module certificate validation remains unqualified.

Other server implementations/versions, SASL/APOP, IPv6, proxies, remote mail
delivery, large responses and database credential/service persistence remain
unqualified. The banner modules report the server's greeting; a greeting need
not disclose a software version. See the [shared guide](../README.md) for
recorded evidence, reproduction and owned cleanup.
