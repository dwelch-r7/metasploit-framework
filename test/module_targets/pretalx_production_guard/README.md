# Companion production check only

This profile verifies two public checks of
`exploit/linux/http/pretalx_rce_cve_2023_28458` against a genuine production-mode
2.3.1 application and an actual site administrator. Native HTTP first confirms
that `/orga/admin/` is accessible and that development mode is disabled.

The companion must return Safe before attempting version discovery. Hidden
production versions must not bypass that prerequisite through a Detected result.
The source-helper change is covered by focused before/after consumer regressions.

This is deliberately a **check-only** profile. Its manifest has no qualified
module owners: successful execution does not qualify the companion's file write,
Python startup hook, command execution, session or cleanup. The file-collection
profiles remain separate. All four capped services and teardown follow the
[shared native lab](../pretalx/README.md).
