# Container host requirements — 2026-11-14

Four additional source and module-document reviews identify targets that need
an isolated operating system or container host. Their current source SHA-256
values and dispositions are recorded in [reviews.yml](reviews.yml). These are
target requirements, not claims that the modules fail or cannot be tested.
The functional checkpoint remains **239 modules qualified in covered paths,
288 profiles and 2,745 examples**.

| Module | Required target and positive-path evidence |
| --- | --- |
| `exploit/linux/local/docker_privileged_container_kernel_escape` | A disposable guest with matching kernel headers and a nested container granting SYS_MODULE. Exercise the actual `insmod`/`call_usermodehelper` path, prove host identity from shell and Meterpreter entry sessions, and verify session closure and kernel-module removal. |
| `exploit/linux/local/docker_runc_escape` | A disposable host running an affected runtime. A real host `docker exec` triggers replacement of its `runc` binary. Prove host execution for the payload targets and verify restoration of the original runtime checksum, container shell and filesystem. |
| `exploit/linux/local/runc_cwd_priv_esc` | An isolated guest with its own affected and fixed Docker/runc packages. Exercise the actual leaked-descriptor `docker build`, host ownership/SUID change and elevated payload. A copied runtime executable or invented version banner does not exercise the daemon's runtime. |
| `exploit/windows/local/docker_credential_wincred` | A disposable Windows desktop with the affected Docker Desktop installation and real UAC state. Cover the privileged `docker login` credential-helper trigger and the separate no-prompt `ShellExecute` branch, with actual elevated sessions and restored artifacts. |

Ordinary service images share the engine's kernel and runtime. They do not
supply the private kernel, affected host runtime or Windows desktop behavior
needed for these positive paths. A dedicated VM or another genuinely isolated
host remains follow-up work. No shared Docker socket, host runtime binary,
kernel module, desktop setting or credential is changed by this review.

Validation loads all 22 review records, checks their hashes against the current
Ruby sources and regenerates the complete module inventory with zero stale
reviews. No exploit or functional test is run for these four modules. Module
sources, public options and historical Scenarios are unchanged. The broader
campaign remains incomplete; no PR is created.
