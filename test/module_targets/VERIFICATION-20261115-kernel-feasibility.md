# Additional kernel-target feasibility reviews

Three individual source reviews require disposable kernel guests for positive
functional qualification. They add zero passing modules, profiles or cases.
No io_uring or BPF exploit was invoked and no host settings were changed.
The source digests and concrete target requirements are in [reviews.yml](reviews.yml).

| Module | Positive target requirement |
| --- | --- |
| `exploit/linux/local/cve_2022_1043_io_uring_priv_esc` | Affected private kernel and multiple CPUs; bundled native code retains damaged kernel credentials and can panic the kernel when they are released |
| `exploit/linux/local/cve_2021_3490_ebpf_alu32_bounds_check_lpe` | Supported distribution/kernel build, BPF configuration and policy; native BPF exploitation overwrites kernel credentials |
| `exploit/linux/local/bpf_sign_extension_priv_esc` | Affected kernel and BPF/hardening configuration; native BPF exploitation obtains kernel read/write and changes credentials |

An ordinary service image does not provide a separate kernel for those paths.
These are specific target requirements, not a blanket exclusion of Linux local
exploits or proof that every container deployment is immune. Future guest
qualification must cover each declared shell and Meterpreter entry session,
actual privilege changes, repeat behavior and cleanup or complete guest disposal.

The reviewed implementations are the three corresponding files under
`modules/exploits/linux/local/`. Their bundled native sources are
`external/source/exploits/CVE-2022-1043/cve-2022-1043.c`,
`external/source/exploits/CVE-2021-3490/Linux_LPE_eBPF_CVE-2021-3490/` and
`data/exploits/cve-2017-16995/exploit.c`. These files were read, never compiled
or executed.

Two check concerns remain source observations for later reproduction. The
io_uring check constructs a one-CPU `Safe` result without returning it, then
constructs `Vulnerable`. The BPF sign-extension check indexes `kernel_release`
with `:upstream`, although `Msf::Post::Linux::Kernel#kernel_release` returns the
uname String and `kernel_rex_release` supplies the hash. No functional failure,
regression result or repair is claimed for either observation. Reproduce each
contract separately before changing its owner; passing a mocked version check
would still not qualify kernel exploitation.
