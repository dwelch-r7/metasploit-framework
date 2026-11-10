## Description

The `pipe_dcerpc_auditor` scanner will return the DCERPC services that can be accessed via a SMB pipe.

## Verification Steps

1. Do: ```use auxiliary/scanner/smb/pipe_dcerpc_auditor```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set THREADS [number of threads]```
4. Do: ```run```

The repository [Samba directory target guide](../../../../../test/module_targets/smb_directory/README.md)
documents genuine native controls, automated cases, and platform limitations.

## Options

### SMB::pipe_write_min_size

The normal default is 1024 bytes so ordinary multi-context BINDs fit one pipe
write. When no minimum is explicitly selected, it follows the selected maximum,
including a smaller operator maximum. An explicit minimum takes precedence.
Fragmented BIND writes can stall Samba reads.

### SMB::pipe_write_max_size

The inherited maximum remains 1024 bytes. An unset minimum follows this value.
When supplying both bounds, keep the minimum no greater than the maximum; the
existing RPC writer clamps a smaller maximum upward.

## Scenarios

```
msf > use auxiliary/scanner/smb/pipe_dcerpc_auditor
msf auxiliary(pipe_dcerpc_auditor) > set RHOSTS 192.168.1.150-160
RHOSTS => 192.168.1.150-160
msf auxiliary(pipe_dcerpc_auditor) > set THREADS 11
THREADS => 11
msf auxiliary(pipe_dcerpc_auditor) > run

The connection was refused by the remote host (192.168.1.153:139).
The connection was refused by the remote host (192.168.1.153:445).
192.168.1.160 - UUID 00000131-0000-0000-c000-000000000046 0.0 OPEN VIA BROWSER
192.168.1.150 - UUID 00000131-0000-0000-c000-000000000046 0.0 OPEN VIA BROWSER
192.168.1.160 - UUID 00000134-0000-0000-c000-000000000046 0.0 OPEN VIA BROWSER
192.168.1.150 - UUID 00000134-0000-0000-c000-000000000046 0.0 OPEN VIA BROWSER
192.168.1.150 - UUID 00000143-0000-0000-c000-000000000046 0.0 OPEN VIA BROWSER
192.168.1.160 - UUID 00000143-0000-0000-c000-000000000046 0.0 OPEN VIA BROWSER
...snip...
```
