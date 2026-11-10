# Samba directory, policy, and named-pipe targets

These profiles exercise genuine Samba 4.15.13 from Ubuntu 22.04 packages,
native Samba CLI/Python clients, and a disposable PostgreSQL reporting database.
They extend the existing module-target runner without modifying the qualified
core SMB fixture. All six accounts and passwords are public artificial data in
`credentials.json`. The private Docker bridge and randomly published loopback
ports serve only this owned project. No host shares, socket, network namespace,
privileged container, Windows installation, or domain account is required.

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb \
  smb_directory_users smb_directory_pipes smb_directory_gpp
```

The three bounded profiles select 11 + 9 + 12 examples. Each operation runs twice;
the tests check the actual console result, native state, caller-session usability,
target file bytes/ownership/permissions, and reporting or loot where implemented.
The runner retains isolated configuration, exact input digests, native commands,
stdout/stderr, console transcripts, target logs, and owned teardown results.

## Bind framing and existing sessions

The auditor keeps multi-context binding enabled. Its default write minimum is
1024 bytes, matching the existing maximum. The unchanged default generator
prepends 10–15 contexts and appends none, so its largest BIND is
`28 + 16 * 44 = 732` bytes. Each default BIND therefore fits one pipe write.
An unset minimum follows the selected maximum, so a smaller explicit maximum
remains valid. An explicit minimum takes precedence. When selecting both bounds,
choose a minimum no greater than the maximum. The inherited writer raises its
effective maximum to an explicitly selected minimum if those bounds are reversed.

Native evidence replays the exact same 688-byte BIND using the genuine RubySMB
client. One write receives a valid rejection in 0.034 seconds; the captured
256/189/243-byte writes reach the existing 60-second read timeout. Two full
215-interface audits with whole writes complete on one authenticated connection.
These are Samba interoperability controls; no shared RPC implementation or
timeout was changed. Smaller explicit write bounds can reproduce the retained
unqualified fragmented-write result.

GPP credential reporting uses the existing SMB session's actual peer port when
`SESSION` is selected, including nondefault ports. Direct connections keep their
selected `RPORT`. The session observer interacts with the real SMB console,
enumerates actual shares, and backgrounds the session before module execution;
Meterpreter-only console command flags are not used for SMB sessions.

## Native controls and scope

* `smb_enumusers_domain` invokes NetWkstaUserEnum, which lists logged-on users.
  Its name does not make it a SAMR inventory of all domain accounts. The genuine
  Samba implementation requires membership in BUILTIN Administrators for this
  API. `rpc_admin` has an explicit SID S-1-5-32-544 group mapping; the ordinary
  reader is denied. Two actual local interactive `smbclient` processes connect
  over NetBIOS139, are independently observed through native RPC, and close
  gracefully after the test. Samba's source includes local SMB users only when
  the remote machine name matches its NetBIOS name. The identical client over
  direct445 has an IP machine name and produces an empty list. No utmp or RPC
  response is manufactured. Forced SMB1/SMB2, default SMB3, direct445 and NetBIOS139 module transports are
  exercised separately from that native logged-on-user policy.
* `pipe_dcerpc_auditor` probes its complete unchanged list of 215 UUID/version
  pairs. Native Samba `base.ClientConnection` binds the same list independently.
  On this release `samr` exposes SAMR 1.0 and the management interface 1.0;
  default `BROWSER` and `module_missing` are absent. The tests preserve those
  genuine negatives and exact UUID notes. They do not shorten the list or
  claim Windows-specific pipe coverage. `rpcclient` commands choose their own
  interface/pipe and therefore cannot independently prove an arbitrary pipe.
* `smb_enum_gpp` reads nine real XML files through an actual SYSVOL SMB share.
  These are deterministic legacy GPP-format fixtures with Microsoft-defined
  CLSIDs and cpassword encryption. An independent OpenSSL AES-256-CBC/UTF-16LE
  control retrieves each file over SMB, decrypts it, and authenticates the
  recovered account/password. ASCII and non-ASCII passwords, all nine searched
  locations, STORE true/false, existing SMB sessions, NetBIOS139, missing shares,
  unreadable files, and empty folders are covered. XML files are not applied as
  Windows GPOs; this is a file-discovery/crypto/reporting qualification on Samba,
  not an Active Directory or Windows OS qualification.

All credentials persisted by GPP are expected to remain `Untried`: the module
recovers passwords but does not authenticate them itself. The independent native
proof is retained separately. `smb_enumusers_domain` currently has no credential
or note reporting call; its exact output and absence of invented reporting are
tested. Existing-session cases authenticate using the ordinary `smb_login`
module, verify genuine share enumeration before and after the operation, and
close the owned session at the end of each example.

Native negative controls include a wrong password, nonexistent account,
administrator/reader RPC policy, missing pipe, unreadable policy share, and real
empty share states. A failed test requires checking these native prerequisites;
zero raw RSpec failures alone do not establish qualification.

## Provenance

The Ubuntu base is digest pinned in `Dockerfile`. Native evidence records exact
installed package versions and the rendered configuration. Samba's relevant
implementation is [`srv_wkssvc_nt.c` at samba-4.15.13](https://github.com/samba-team/samba/blob/samba-4.15.13/source3/rpc_server/wkssvc/srv_wkssvc_nt.c).
The public GPP AES key and serialization are defined by
[MS-GPPREF password encryption](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be),
and [MS-GPPREF preference CLSIDs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/12512ed6-0632-4e90-a112-d3d2cd41df6c).
`pipe_uuids.json` is the complete original module table, explicitly frozen as a
native input; its order and length are asserted against every module run.
