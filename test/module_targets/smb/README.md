# Samba protocol suite target

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb smb
```

This reuses `test/smb/Dockerfile`, its share configuration and tracked seed files,
with a pinned Ubuntu 22.04 base. Native `smbclient` authenticates and reads an
existing file from the read-only share before Framework runs. The writable share
supports the existing session tests. Only a random host loopback port is published.

Credentials: `acceptance_tests_user` / `acceptance_tests_password`.

The existing `spec/acceptance/smb_spec.rb` covers login/session creation, SID/user/
pipe/share enumeration and version detection. It exercises the default protocol
set and an explicit SMB 2/3 selection, through supported direct-host and session
paths, plus `post/test/smb`. This is a Samba target; it does not prove Windows
server vulnerabilities or Windows-specific operations. The built image ID and
actual server banner are retained; OS package updates can change the Samba build.

The Framework console runs on the same isolated Compose network. This is required
for the direct share-enumeration path, which deliberately scans ports 139 and 445
and does not accept RPORT. Mapping only a random host port cannot test that path.
The managed lab bounds SID enumeration to RIDs 500–514, retaining the expected
user/group results without hundreds of unnecessary requests. Other invocations
of the existing suite retain their previous range.

See [the shared guide](../README.md) for evidence capture and cleanup.
