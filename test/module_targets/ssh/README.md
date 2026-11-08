# OpenSSH protocol suite target

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb ssh
```

This reuses `test/ssh/Dockerfile` with a pinned Ubuntu 22.04 base. The native
OpenSSH client authenticates and executes `id -un` as a health check. A read-only
askpass script supplies the public fixture password without adding a client gem
or host dependency. Only a random host loopback port is published.
The Framework console joins the same isolated Compose network, reusing the
shared dependency image and source-metadata cache between container families.

Credentials: `acceptance_tests_user` / `acceptance_tests_password`.

The existing `spec/acceptance/ssh_spec.rb` opens a real SSH shell session,
exercises Unix user enumeration through `post/test/unix`, and scans the server
version. Key authentication, incorrect credentials and additional SSH modules
remain to be added. The built image ID and actual server banner are retained in
the run evidence; package updates can change the OpenSSH build on the pinned OS.

See [the shared guide](../README.md) for evidence capture and cleanup.
