# Fixed sudo default-callback control

This uses the [same default-callback controls](../sudo_chroot_sessions/README.md)
against genuine sudo1.9.17p1. Native UID1001 staged callbacks stay positive;
native NSS escalation and both original AutoCheck owning bodies must be denied.
The one-container caps, namespace and cleanup policy are unchanged.
