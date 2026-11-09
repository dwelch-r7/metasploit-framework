# Rsync targets

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb rsync
```

The lab builds pinned rsync packages on digest-pinned Ubuntu 22.04
(`3.2.7-0ubuntu0.22.04.7`, protocol 31.0) and Debian 12
(`3.2.7-1+deb12u6`, protocol 32.0) bases. Both report rsync 3.2.7 but have
different actual wire greetings; the version string alone is insufficient.
Native version output, actual wire greeting, package versions and image
IDs are retained. Mixed-policy daemons export public, password-protected and
uncommented shares, plus a genuinely usable hidden share excluded from listing.
A separate daemon exports nothing; a real Apache service is the unrelated target.

Native CLI controls list shares, fetch exact proof contents from open/locked/
hidden shares, and reject the wrong password. Module tests compare share names,
comments, authentication requirements, optional MOTD/version output and empty/
unrelated responses. No protocol response stub is used. Configuration follows
the [upstream daemon manual](https://download.samba.org/pub/rsync/rsyncd.conf.5).

Only random loopback ports are published. The scanner enumerates authentication
requirements; it does not validate passwords or transfer files itself. Native
client transfers establish fixture policy independently. No SSH transport,
other daemon versions, restricted host ACLs or persistent report database is
qualified. Older bare-number greetings without a subprotocol/digest list are
also outside these two profiles. See the [campaign](../CAMPAIGN.md) for results and [shared guide](../README.md)
for evidence and owned-project cleanup.
