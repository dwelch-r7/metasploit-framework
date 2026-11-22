# LinuxKI native-gated Bash sessions

Run `linuxki_sessions` with the namespaced guarded runner from the Framework
root. The target reuses the pinned [genuine package](../linuxki/README.md);
the only extra mount is the existing PHP procfs observer, read-only.

Four examples gate execution with package/CLI/interpreter and UID33 command
controls, a real callback/ack exchange, then actual stock-handler Bash sessions
from the CLI and genuine vulnerable page. Only then are two owning target2
sessions permitted. This profile explicitly selects `cmd/unix/reverse_bash`;
the second run reuses the selected owner with a fresh callback port and AutoCheck
disabled. The console's actual automatic Unix selection is qualified separately
in [the Unix default profile](../linuxki_unix_default_sessions/README.md).

Each session must pass public file-write/identity/shutdown APIs, physical UID33,
PID/birth, exact file bytes, connection and process disappearance checks. Apache
may retain an extra legitimate prefork worker under its original parent; other
UID33 processes must return to baseline. There is no reporting database and no
claim about database persistence. Proof/log files are removed in `ensure`;
the runner removes both capped containers and its network on every exit.

PHP and Linux droppers require their own independent controls. All observations
and raw console/HTTP evidence are retained in the normal runner artifacts.
