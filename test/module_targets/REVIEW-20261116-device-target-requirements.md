# Device target requirements — 2026-11-16

Three individual source reviews add firmware requirements to
[reviews.yml](reviews.yml), with exact current source SHA256 values. They add
zero functional cases and make no claim about firmware-image availability.
Owned devices or runnable matching vendor guests remain possible follow-up
targets. Existing module sources and human guides/Scenarios stay unchanged.

| Module | Positive-path evidence the target must supply |
| --- | --- |
| [2Wire password reset](../../modules/auxiliary/admin/2wire/xslt_password_reset.rb) | Version5 XSLT administration, an actual persistent password change, independent old/new login checks, repeat execution and restoration of the original configuration. HTTP page/header/cookie captures can support parser checks; native authentication state still needs qualification. |
| [Cisco Smart Install](../../modules/auxiliary/scanner/misc/cisco_smart_install.rb) | Both SCAN and DOWNLOAD against Smart Install firmware. The latter must execute the embedded IOS copy command, initiate a real TFTP transfer and return known configuration bytes for reporting. Verify callback routing and listener cleanup before a second run. |
| [HP Jetdirect traversal](../../modules/exploits/linux/misc/hp_jetdirect_path_traversal.rb) | Real PJL filesystem traversal into the firmware startup directory, command-file verification, an SNMP power cycle and an actual used shell. Verify removal of the script and closure of the session/telnetd listener; the existing human guide records intermittent cleanup. |

The Brother default-password module stays in the pending queue. Its supported
`TargetSerial` plus `ValidatePassword=false` branch performs local derivation
and Untried credential reporting, so that bounded path can be tested without a
printer. Discovery and successful administrator login need a separate genuine
device/firmware target. A blanket device exclusion would hide the feasible
offline branch. No generation, discovery, login or device operation is run as
part of this review.

Validation parses the review registry and checks the source digests, with no
runtime qualification or coverage-count increase. The broader campaign remains
incomplete; no PR is created.
