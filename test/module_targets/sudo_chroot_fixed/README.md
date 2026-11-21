# Fixed sudo chroot control

This serial profile builds official sudo1.9.17p1 and uses the same independent
compiler/NSS and real shell/Meterpreter controls as the
[affected profile](../sudo_chroot/README.md). Native escalation and original
AutoCheck execution must both be denied; compiler/direct-library controls remain
positive. See the shared README for the guarded command, resources and limits.
