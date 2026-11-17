# Publication follow-up, 2026-11-17

## Ultimate Member exact-fork Ruby 3.3 evidence

Four completed Ruby 3.3 jobs explicitly check out fork `d33d61df000fa58c6ac9116f5adc16e6ba19989b`.
Both non-content logs visibly execute all 45 new owner examples: 29 nonce cases
and 16 alias cases. Content jobs validate module metadata separately.

| Job | Examples | Failures | Pending | Seed |
| --- | ---: | ---: | ---: | ---: |
| [normal](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43990752463/job/133730393903) | 20038 | 0 | 33 | 50533 |
| [remote](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43990752463/job/133730393865) | 19851 | 0 | 664 | 14017 |
| [content](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43990752463/job/133730393823) | 6781 | 0 | 0 | 63626 |
| [contentremote](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43990752463/job/133730393918) | 6781 | 0 | 0 | 42556 |

The six-entry exact-checkout seal is `/Users/dwelch/.codex/reports/ultimate-member-publication-unit33-20261117`,
manifest SHA256 `f3f034f7ebd6af4255cca9abd1b4b8ceced260ee5c523a531492df3bc4e9bd98`. These unit doubles are distinct
from the fifteen accepted genuine public cases. No extra local case is added.
All ten workflows are now terminal; no agent retry or cancellation was performed.

## Ultimate Member terminal acceptance follow-up

Nine workflows passed. [Meterpreter acceptance](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43990752804) failed with 22 successful jobs, one failed Linux Mettle job and one skipped optional build.
The [failed job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43990752804/job/133730395291) reports 51 examples, one failure and one error outside examples, seed 23950.
The reverse HTTP session using `base64_transforms.profile` timed out while deleting a symbolic link in `post/test/file`; subsequent file operations and console cleanup also timed out.

Although the workflow came from fork `d33d61df000fa58c6ac9116f5adc16e6ba19989b`, its `git log -1` confirms actual Framework checkout `aa9ce416588a2d6fb97423d23591089aff2c8c3e`.
This does not validate the fork changes or establish a regression in them. The native cause and a base-versus-fork comparison remain unverified. No extra case or coverage is counted.

The six-entry terminal seal is `/Users/dwelch/.codex/reports/ultimate-member-publication-terminal-20261117`, manifest SHA256 `290e13a5eae920b1f03b497e9e269872bb2fbb0718f3774f67cb6b0a375129d4`; its complete file set and every byte were independently rehashed.

## WordPress core SQLi publication

All ten workflows for fork `2ddcc7f81b47c026f6db795d388543f544db25ab`
finished successfully, without an agent retry or cancellation.
[Verify](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44003241977)
passed all fourteen jobs. Four Ruby 3.3 logs explicitly confirm the actual fork
checkout; both non-content logs visibly execute all fifteen new alias examples.

| Job | Examples | Failures | Pending | Seed |
| --- | ---: | ---: | ---: | ---: |
| [normal](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44003241977/job/133772224065) | 20053 | 0 | 33 | 47515 |
| [remote](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44003241977/job/133772223986) | 19866 | 0 | 664 | 3797 |
| [content](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44003241977/job/133772224001) | 6781 | 0 | 0 | 45069 |
| [contentremote](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44003241977/job/133772224038) | 6781 | 0 | 0 | 46012 |

[Meterpreter acceptance](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44003242377)
finished with 23 successful jobs and one optional skipped build. Its actual
Framework checkout was not inspected here; workflow metadata alone does not
establish candidate execution. These published jobs exclude the later monotonic
clock repair and the new RCE fixtures. No local functional cases are added.

The six-entry exact-unit seal is
`/Users/dwelch/.codex/reports/wordpress-core-sqli-publication-unit33-20261117`,
manifest SHA256 `d24963614a617eb6010223e7bff295f6f61c8a76fc29e603310dabd6a720e015`.
The three-entry terminal metadata seal is
`/Users/dwelch/.codex/reports/wordpress-core-sqli-publication-terminal-20261117`,
manifest SHA256 `51a15cba1e39be37b0e9142dbb3d085762fdbd50018fa34b2a64ef4449b2cb5c`.
Both complete file sets and all bytes were independently rehashed.
