# ProFTPD CopyEngine-off control

Shares the [native target and test procedure](../proftpd_modcopy/README.md) and
the fixed 1.3.5a build. Its configuration disables `mod_copy` with `CopyEngine
off`. Ordinary authenticated FTP upload/download/delete and the PHP health
endpoint must still work. Original check and explicit exploit refusal must
leave no active FTP socket or target artifact. One capped container runs at a
time and is removed after each phase.
