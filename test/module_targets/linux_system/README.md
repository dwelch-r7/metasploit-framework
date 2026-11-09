# Linux system collection targets

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb linux_system
```

This profile extends the digest-pinned Ubuntu22.04 session target with genuine
cron, network tools and OpenSSH configuration. Package versions are explicit in
Compose. Native controls read the actual installed packages, crontabs, interfaces,
listening ports, configuration files, SSH keys and kernel settings. The named
service user has actual UID1000; a session-created file's native owner proves
that payloads execute as the requested user.

The twelve cases run system, network and protection collection with both declared
session types (command shell and Meterpreter), as root and an unprivileged user.
Every case starts a fresh real payload session. Loot must match native file bytes
and package/account data; root cron collection must include both users, while
nonroot collection must omit the root job. Interface addresses, a real listener,
SSH key contents and permitted/denied firewall collection have independent controls.
The suite checks only errors backed by native missing files or permission denial.
Each console command has a bounded three-minute wait because collection performs
many session round trips; the overall family retains the runner's ten-minute cap.

The target receives NET_ADMIN to seed/read a harmless rule in its own network
namespace. Native root collection must see it; the unprivileged user must be
denied. There is no host network, privileged mode, Docker socket or host sysctl
change. Neither cron nor sshd runs: this profile tests collection. HTTP supplies
readiness. The kernel belongs to Docker's Linux VM, so its observed protections
do not qualify arbitrary host kernels or distributions. Other distributions,
security products, SSH directory combinations and database note/loot persistence
remain unqualified. See the [shared guide](../README.md) and
[campaign](../CAMPAIGN.md) for actual results and findings.
