#!/bin/bash
set -eu
mode="$1"
client="${NATIVE_MYSQL_CLIENT:-mysql}"
base=/var/lib/mysql-files/module-write
outside=/tmp/module-write-outside
query() {
 local user="${2:-root}" password=Module-schema-password42!
 if [[ "$user" == root ]]; then password=password; fi
 "$client" --protocol=TCP --host=127.0.0.1 --default-character-set=utf8mb4 --user="$user" --password="$password" --batch --skip-column-names --execute="$1"
}
expect_error() {
 local number="$1" sql="$2" user="${3:-file_operator}"
 if query "$sql" "$user" >/tmp/module-write-native-error 2>&1; then cat /tmp/module-write-native-error; exit 2; fi
 cat /tmp/module-write-native-error
 grep -Eq "^ERROR $number " /tmp/module-write-native-error
}
literal() {
 local value="$1"
 # Independent vendor-client statements use SQL quote doubling; the filesystem
 # gate verifies the resulting exact pathname and bytes for each server mode.
 if [[ "$sql_mode" != *NO_BACKSLASH_ESCAPES* ]]; then value="${value//\\/\\\\}"; fi
 value="${value//\'/\'\'}"
 printf "'%s'" "$value"
}
if [[ "$mode" == seed ]]; then
 bash /opt/module-target/file-enum-native.sh seed
 mkdir -p "$base/ordinary" "$base/space dir" "$base/quote'dir" "$base/back\slash-dir" "$base/denied" "$outside"
 printf 'Not a directory\n' > "$base/file-not-directory"
 chown -R mysql:mysql "$base" "$outside"
 chmod 755 "$base"
 chmod 700 "$base/ordinary" "$base/space dir" "$base/quote'dir" "$base/back\slash-dir" "$outside"
 chown root:root "$base/denied"
 chmod 500 "$base/denied"
elif [[ "$mode" == probe ]]; then
 bash /opt/module-target/file-enum-native.sh probe
 sql_mode="$(query 'SELECT @@SESSION.sql_mode;')"
 query "SELECT VERSION(),CURRENT_USER(),@@secure_file_priv,@@SESSION.sql_mode,'NATIVE_WRITE_ROOT';"
 for path in "$base/ordinary/native-probe.txt" "$base/quote'dir/native-probe.txt" "$base/back\slash-dir/native-probe.txt" "$base/ordinary/module-write\back'quote.txt"; do
  encoded="$(literal "$path")"
  query "SELECT _utf8'test' INTO DUMPFILE $encoded;" file_operator
  [[ "$(od -An -v -tx1 "$path" | tr -d ' \n')" == 74657374 ]]
  [[ "$(stat -c '%U' "$path")" == mysql ]]
  stat -c 'NATIVE_WRITE_BYTES %U %a %s' "$path"
  expect_error 1086 "SELECT _utf8'test' INTO DUMPFILE $encoded;"
  rm -- "$path"
 done
 expect_error 1 "SELECT _utf8'test' INTO DUMPFILE '$base/denied/native-probe.txt';"
 # A failed realpath/secure-file check may precede the OS create operation.
 # These fixed, valid SQL statements must fail and leave no destination file;
 # retain the actual vendor code instead of assuming one OS-error mapping.
 expect_error '[0-9]+' "SELECT _utf8'test' INTO DUMPFILE '$base/absent/native-probe.txt';"
 expect_error '[0-9]+' "SELECT _utf8'test' INTO DUMPFILE '$base/file-not-directory/native-probe.txt';"
 [[ ! -e "$base/absent/native-probe.txt" && -f "$base/file-not-directory" ]]
 expect_error 1290 "SELECT _utf8'test' INTO DUMPFILE '$outside/native-probe.txt';"
 query "SELECT CURRENT_USER(),'NATIVE_WRITE_NO_FILE';" no_file
 denial=1227
 if [[ "$client" == mariadb ]]; then denial=1045; fi
 expect_error "$denial" "SELECT _utf8'test' INTO DUMPFILE '$base/ordinary/native-probe.txt';" no_file
elif [[ "$mode" == files ]]; then
 find "$base" "$outside" -type f -name 'module-write*' -print0 | while IFS= read -r -d '' path; do
  path_hex="$(printf '%s' "$path" | od -An -v -tx1 | tr -d ' \n')"
  bytes_hex="$(od -An -v -tx1 "$path" | tr -d ' \n')"
  printf '%s\t%s\t%s\t%s\n' "$path_hex" "$bytes_hex" "$(stat -c '%U' "$path")" "$(stat -c '%a' "$path")"
 done | LC_ALL=C sort
elif [[ "$mode" == reset ]]; then
 # This prefix exists only in the new task-owned lab directories. It also finds
 # a wrong escaped filename, which is recorded before any test cleanup occurs.
 find "$base" "$outside" -type f -name 'module-write*' -delete
elif [[ "$mode" == state ]]; then
 bash /opt/module-target/file-enum-native.sh state
 find "$base" "$outside" -printf '%m %u %g %p\n' | LC_ALL=C sort
 find "$base" "$outside" -type f -exec sha256sum '{}' \; | LC_ALL=C sort
else
 exec bash /opt/module-target/file-enum-native.sh "$@"
fi
