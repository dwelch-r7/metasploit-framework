# WordPress administrator unrelated profile

See the [component profile table](../wordpress_admin/README.md) for scope, native
controls, resource limits and the unqualified staged-session reproductions.

The profile allows 128 PIDs for Apache event MPM. Its normal startup worker
threads exceed a 64-PID limit; the original resource-counter failure is retained
separately and occurred before native controls or module calls. CPU and memory
limits remain 0.25 CPU and 128 MiB.
