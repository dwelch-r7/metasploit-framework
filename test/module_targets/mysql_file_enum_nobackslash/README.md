# MySQL without backslash escapes

This profile runs the [same genuine file-enumeration matrix](../mysql_file_enum/README.md)
on MySQL 8.0.36 with `NO_BACKSLASH_ESCAPES` added to its normal SQL modes. The
native client independently loads the quoted filename before module evaluation.
Actual collector and native-control checks pass.

This profile passes 11 cases; see the [verification report](../VERIFICATION-20261118-mysql-file-enum.md).
