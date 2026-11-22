# LinuxKI check error contracts

Run `linuxki_errors` with the guarded runner after the
[native package controls](../linuxki/README.md). Four examples prove genuine
positive command readiness, then independently establish a missing page, denied
directory traversal and a refused target socket before calling the real check.
Each check must return a reason-bearing Unknown instead of raising an exploit
failure. No HTTP response or Framework transport is mocked. The temporary denied
directory is restored and removed in `ensure`; the runner removes both containers
and the project network on every exit.
