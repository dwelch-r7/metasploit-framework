# User-space NFS and RPC targets

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb nfs
```

This profile builds authentic [UNFS3 0.11.0](https://github.com/unfs3/unfs3/releases/tag/unfs3-0.11.0)
from the official release archive (SHA256
`42ef63cd949b65a4ead30bee269703059a8c4269bef6aa1533215ad1c2a26d6f`)
on a digest-pinned Ubuntu 22.04 base. The target packages include rpcbind and
libnfs command-line clients. No host mounts, kernel NFS mounts, Docker socket,
privileged mode or host network are used. `SYS_ADMIN` and `SYS_TIME` are dropped
and verified absent. All published TCP/UDP ports use random loopback bindings.
A separate digest-pinned PostgreSQL 16 container stores Framework results with
public artificial lab credentials; it starts with an empty schema and is removed
with its data volume by the runner.

The three targets serve five exports, no exports, or rpcbind alone. Native
`rpcinfo`, `showmount`, `nfs-ls`, `nfs-cat` and `nfs-cp` verify genuine discovery,
NFSv3 file read/write permissions, denied access, read-only refusal and exact file
restoration. Two ordinary wire probes per service decode actual RPC replies
independently over TCP and UDP. Each scan runs twice, compares all advertised
programs or export paths/groups, checks exact database services/notes and stable
row IDs, and verifies the exported files remain unchanged.

The NFS scanner reports a location heuristic; it does not attempt a mount or
prove write permission. `Mountable=false` labels every returned export as
mountable, including the deliberately denied export. The profile also supplies
a real nonblank client hostname and an outside `LHOST` address to exercise the
heuristic independently of successful native access. CIDR and dotted netmask
exports use the actual container subnet determined at startup.

UNFS3 represents an unrestricted client as literal `<anon clnt>` in the EXPORT
reply. Its official `Config/exports.y` initializes unnamed clients with this
label and prefix zero, then exposes that label in `gr_name`. Native reads and
writes establish the access semantics. Empty strings and empty export lists are
separate cases; no empty-string meaning is inferred from this implementation.
[RFC 1813 section 5.2.5](https://www.rfc-editor.org/rfc/rfc1813.html#section-5.2.5)
permits implementation-specific group names.

This profile covers MOUNT v1 EXPORT and portmapper v2 DUMP over IPv4 TCP/UDP.
File I/O uses ordinary libnfs transport; UDP file I/O is not separately qualified.
It does not qualify kernel NFS servers, NFSv4, IPv6, Kerberos, client host-name
ACL resolution, Unix UID permission combinations, or request fragmentation. An
optional exploratory split-record request ended at peer EOF and remains
unqualified; ordinary record requests and genuine libnfs operations are the
controls used here. No payload or target session is involved.
