# ProjectSend command delivery and cleanup

```sh
MODULE_TARGET_NAMESPACE=my-projectsend-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb projectsend_rce
```

This profile extends the pinned, unchanged r1605-ls199 image and capped database
from `../projectsend`. Two services run at a time; only a random localhost HTTP
port is published. Ordinary mail settings point SMTP to the target's verified
closed loopback port 9, containing registration mail. These settings join the
complete preservation baseline. No PHP extension or application patch is added.

The real installer, twelve source fingerprints and native check controls run
first. Each exact command passes stock `php/exec` CLI execution and an independent
client registration, denied PHP upload, approved upload, UID 1000 proof,
self-unlink and portal deletion. Native fixture state is recovered explicitly.

The original exploit then runs plain and quoted Unicode/CRLF commands with
AutoCheck enabled and disabled on the same selection. Passive observations retain
the generated PHP, raw upload, candidate URLs, original execution and cleanup.
Exact proof and portal cleanup are checked separately from full option
preservation. Actual post-run state is saved before explicit fixture recovery;
restoration cannot turn a failed module assertion into a pass. Created accounts
are recorded. Session delivery and other releases remain separate work.

Registration of this profile does not assert that its tests pass. Consult the
dated verification report and retained raw results for qualification status.
