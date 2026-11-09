# Ansible controller collection

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb ansible
```

This profile tests `post/linux/gather/ansible` on digest-pinned Ubuntu 22.04
with native `ansible-core=2.12.0-1ubuntu0.1` and OpenSSH
`1:8.9p1-3ubuntu0.18`. The controller and SSH node reuse the
[Linux target image](../linux_post/README.md). Only controller readiness is
published on a random loopback port; SSH stays on the project network.
There is no host Docker socket, container connection plugin, host network or
external inventory. A disposable volume carries a newly generated SSH key.
The ordinary controller user owns its private copy with mode 0600; a root-only
copy supplies a real denied-read control. No key is committed.

Native Ansible and SSH clients establish inventory, successful and rejected
authentication, actual config/key bytes, compact INI syntax and two genuine
copy/execute/remove playbooks per controller identity. The protected config
points to the root-only key; selecting `ANSIBLECFG` controls the file collected
by Framework, while native commands retain their ordinary Ansible config search.
The [Ansible configuration documentation](https://docs.ansible.com/projects/ansible/latest/reference_appendices/config.html)
describes that search order. No responses, sessions or deployments are simulated.

Fourteen cases use real root/nonroot shell and Meterpreter sessions, explicit
`/usr/bin/ansible` and `/usr/bin/ansible-inventory` options, default config
discovery, all/selected hosts, exact inventory/config/key loot, valid compact
INI, denied key reads and an actual empty inventory. Every case starts a fresh
session. The empty inventory is restored before the next case. Native setup
is validated before module assertions; registration is not qualification.

Ansible node deployment is separate qualification work; native playbook success
alone does not qualify that Framework exploit. Other Ansible versions, Unix
platforms, privilege escalation, encrypted keys/vault, dynamic inventories,
alternative connection plugins and Framework database persistence remain
unqualified. The external lab in the existing human Scenarios is retained as
historical evidence; this managed profile avoids its fixed ports and host engine
access. See the [shared runner guide](../README.md) for retained evidence/cleanup.
