# .netrc credential collection target

This profile exercises `post/multi/gather/netrc_creds` using real Linux shell sessions and
native curl authentication against the existing Apache Basic-authentication
fixture. PostgreSQL records actual loot metadata; the saved CSV file must contain
the expected client-verified account and server. Console completion alone is
insufficient. The original owner stores CSV loot rather than credential cores.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb netrc_creds
```

The pinned Ubuntu 22.04 client installs curl `7.81.0-1ubuntu1.30`. Its captured
native controls independently exercise multiline, inline, tab-separated,
commented and multiple-machine files, correct/wrong/no credentials and both
server aliases. The apparent machine inside a comment does not authenticate.
The real module runs against target-only mode-0600 home files. Cases recover only
files whose bytes match the installed fixture, terminate their actual shell
processes, remove generated ELFs/markers and verify database session closure.

One capped stack runs at a time: client, Apache and reporting database total
1 CPU/768 MiB, equal memory/swap, PID limits and init. All exposed ports bind to
loopback. Generated shell delivery is a prerequisite; the existing owner declares
shell only. Shared callbacks, shell proofs and cleanup reuse the rsync target
helper through owner/resource/observation hooks. The existing rsync profile needs
a regression run when those shared defaults change.

Eight functional cases make nine module calls: multiline and a same-instance
repeat, tabs, comments, an unreadable root file, inline fields, multiple machines,
multiple ASCII spaces and an ordinary user's own home file. Each installed file
is tested by native curl before its module call. Eight expected CSV loot files
must match exact data and reporting metadata, including the two-machine case.
The repeat creates a new loot file with the same CSV bytes. Loot represents
collected data; it does not independently prove that any password authenticates.
No credential cores or Successful login records are claimed.

The separate focused contracts retain exact captured files and an original
CSV capture. Transport, Framework/session access, persistence and output are
doubled there; the real owner/table/CSV code runs. A nil-read continuation case
is a defensive boundary test; the file-disappearance race was not reproduced
natively. See the [verification report](../VERIFICATION-20261117-netrc-creds.md)
for original failures and the unchanged owner-only replay.

Native acceptance is specific to the pinned curl release. Quoted strings added
to newer curl, other operating systems, architectures, `.netrc` consumers and
additional grammar remain outside the current profile. Native/harness failures
must be distinguished from an owner defect before changing module code.
