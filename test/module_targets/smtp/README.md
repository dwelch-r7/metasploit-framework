# SMTP targets

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb smtp
```

Four real Exim instances share a digest-pinned Ubuntu base and a seeded local
`module_target` account. Profiles enable VRFY, force RCPT fallback, accept all
local recipients, or accept remote relay transactions. Native SMTP probes
independently verify each policy and both known/missing users before Framework.
Exim's disabled-VRFY response is 252; its enabled verification routes against
the real local account database. See Exim's [ACL documentation](https://www.exim.org/exim-html-current/doc/html/spec_html/ch-access_control_lists.html).

The suite tests the banner, VRFY/RCPT enumeration, missing users and unreliable
catch-all detection. Standard and sixteen-form extended relay checks run twice
against closed and open policies. A positive module result must also produce a
fresh recipient-specific native delivery-log record.

All accepted remote messages terminate in Exim's local `:blackhole:` router.
No SMTP forwarding transport is configured, so test mail is never delivered to
an external recipient. This qualifies acceptance/queueing detection, not actual
forwarding across mail systems. Only random loopback SMTP ports are published;
Framework runs in the target network. TLS, authentication, EXPN enumeration and
other SMTP implementations remain unqualified. OS packages may drift on rebuild;
native versions and image IDs are retained.

See [the shared guide](../README.md) for evidence and cleanup and the
[campaign](../CAMPAIGN.md) for current qualification status. A lab definition
does not establish that its tests passed.
