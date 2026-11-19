# Native Craft FTP template execution targets

These profiles run genuine Craft CMS, nginx, PHP-FPM and PostgreSQL. The Framework
listener shares their isolated network so PHP's real FTP wrapper can reach both
control and passive data connections.

| Profile | Craft CMS | PHP `register_argc_argv` | Expected behavior |
| --- | --- | --- | --- |
| `craftcms_ftp` | 4.13.0 | On | Native and module command execution |
| `craftcms_ftp_argv_off` | 4.13.0 | Off | FTP reads work; template injection is refused |
| `craftcms_ftp_fixed` | 4.13.2 | On | FTP reads work; fixed web bootstrap ignores injected paths |

The [advisory](https://github.com/craftcms/cms/security/advisories/GHSA-2p6p-9rc9-62j9)
and [research](https://www.assetnote.io/resources/research/how-an-obscure-php-footgun-led-to-rce-in-craft-cms)
describe the release boundaries, PHP prerequisite and FTP/Twig primitive.
[releases.json](releases.json) pins source references, critical hashes and locks.
All 99 non-CMS Composer package records match between vulnerable/fixed locks.
The shared [Dockerfile](../craftcms/Dockerfile) installs genuine application code.

With the existing Framework bundle, Docker Compose and NASM:

```sh
MODULE_TARGET_NAMESPACE=craft-ftp-dev \
  bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
    craftcms_ftp craftcms_ftp_argv_off craftcms_ftp_fixed
```

Select one profile for a shorter run. Run the guarded runner directly; it owns the
shared worktree lock. Profiles run serially with three capped services:

| Service | CPU | Memory and swap cap | PID cap |
| --- | --- | --- | --- |
| Craft | 0.75 | 768 MiB | 128 |
| PostgreSQL | 0.25 | 384 MiB | 128 |
| Framework | 1 | 640 MiB | 128 |

Database roles/databases are separate. Published ports bind to random loopback
ports; listeners use the internal network. Completed stacks and volumes are
removed immediately. Confine cleanup to the chosen namespace's recorded objects.

Seventeen native application controls run before and after each profile. They
exercise ordinary/database-backed Twig, real administrator login, password
rejection, preserved files and source hashes. The shared control's `vulnerable`
flag describes the older condition-handler CVE; `ftp_vulnerable` describes this
module's separate primitive.

Independent controls use actual `auxiliary/server/ftp` and PHP wrapper reads.
They check exact FTP replies/bytes, Twig arithmetic and a command-created file
under the web UID. Protected profiles retain FTP reads and refuse execution.
Native controls must pass before interpreting owner results.

The owner uses an exact generic command. On the vulnerable profile, native
curl/wget downloads first run known x86/x64 ELF files. Session cases cover x86
HTTP fetch with inline Meterpreter and x64 wget fetch with staged Meterpreter.
Filesystem writes, channel closure, native PID/UID/executable hashes, live TCP
connections and persisted database records prove use. Shutdown must close the
connection, process and database record. Both families repeat with the same
selected console module and AutoCheck disabled. A raw socket refusal calibrates
the closed-port check. Resource counters and the native baseline are checked
throughout; prerequisite, pending and cleanup failures withhold qualification.

Other Craft branches, Unix platforms, HTTPS deployments and payload families
remain outside this fixture's qualification. The original 4.13.1 pilot hit the
[upstream CLI bootstrap regression](https://github.com/craftcms/cms/issues/16142).
The older 4.4.14 image refused the remote template root in its bootstrap. Those
setups remain investigations; application handlers are unchanged. Host passive
FTP transfer controls failed, requiring the listener inside the Docker network.
