#!/bin/bash
set -eu
peer="$1"
mode="$2"
profile="${NATIVE_MYSQL_MODE:-vulnerable}"
client="${NATIVE_MYSQL_CLIENT:-/usr/local/mysql/bin/mysql}"
admin_peer="${NATIVE_MYSQL_ADMIN_HOST:-$peer}"
admin() { "$client" --protocol=TCP --host="$admin_peer" --user=root --password=123456 --batch --skip-column-names --execute="$1"; }
if [[ "$mode" == seed ]]; then
 if [[ "$profile" == open ]]; then admin "SELECT COUNT(*) FROM mysql.user WHERE User='module_reader';"; exit; fi
 "$client" --protocol=TCP --host="$admin_peer" --user=root --password=123456 < /opt/module-target/seed.sql
 if [[ "$profile" == policy ]]; then admin "DELETE FROM mysql.user WHERE Host NOT IN ('localhost','127.0.0.1','::1'); FLUSH PRIVILEGES;"; fi
 exit
fi
if [[ "$mode" == state ]]; then admin "SELECT HEX(User),HEX(Host),HEX(Password) FROM mysql.user ORDER BY User,Host;"; exit; fi
if [[ "$mode" == idle ]]; then admin "SELECT COUNT(*) FROM information_schema.processlist WHERE ID<>CONNECTION_ID() AND USER<>'system user';"; exit; fi
if [[ "$mode" == expected ]]; then admin "SELECT HEX(User),HEX(Password) FROM mysql.user WHERE LENGTH(User)+LENGTH(Password)>0 ORDER BY User,Host;"; exit; fi
if [[ "$mode" != probe ]]; then exit 2; fi
query="SELECT VERSION(),CURRENT_USER(),'MODULE_TARGET_NATIVE_LOGIN';"
admin "$query SELECT COUNT(*) FROM mysql.user WHERE User='root' AND Password=PASSWORD('module-target-known-wrong');"
"$client" --version
sha256sum "${NATIVE_MYSQL_SERVER:-/usr/local/mysql/bin/mysqld}" "$(command -v "$client")"
ldd --version | head -1
if [[ "$profile" == policy ]]; then
 if "$client" --protocol=TCP --connect-timeout=2 --host="$peer" --user=root --password=123456 --execute='SELECT 1' 2>/tmp/module-target-native-policy-error; then exit 3; fi
 grep 'ERROR 1130' /tmp/module-target-native-policy-error
 printf 'NATIVE_HOST_POLICY_DENIED\n'
 exit
fi
if [[ "$profile" == open ]]; then
 for wrong in module-target-known-wrong another-wrong-password; do
  "$client" --protocol=TCP --host="$peer" --user=does_not_exist --password="$wrong" --batch --skip-column-names --execute="$query SELECT COUNT(*) FROM mysql.user;"
 done
 tr '\0' ' ' < /proc/1/cmdline
 printf '\nNATIVE_GRANTS_DISABLED\n'
 exit
fi
wrong=module-target-known-wrong
denials=0
successes=0
limit=4096
if [[ "$profile" == fixed ]]; then limit=64; fi
for ((attempt=1; attempt<=limit; attempt++)); do
 if output=$("$client" --protocol=TCP --connect-timeout=2 --host="$peer" --user=root --password="$wrong" --batch --skip-column-names --execute="$query" 2>/tmp/module-target-native-auth-error); then
  successes=$((successes+1))
  printf 'NATIVE_WRONG_PASSWORD_ACCEPTED\tattempt=%s\tdenials=%s\tidentity=%s\n' "$attempt" "$denials" "$output"
  if [[ "$profile" == fixed ]]; then exit 3; fi
  if ((denials>0)); then break; fi
 else
  if ! grep -q 'ERROR 1045' /tmp/module-target-native-auth-error; then cat /tmp/module-target-native-auth-error >&2; exit 2; fi
  denials=$((denials+1))
  if ((successes>0)); then break; fi
 fi
done
printf 'NATIVE_AUTH_RESULT\tattempts=%s\tdenials=%s\tsuccesses=%s\n' "$attempt" "$denials" "$successes"
if [[ "$profile" == fixed ]]; then
 if ((successes!=0 || denials!=64)); then exit 3; fi
 printf 'NATIVE_PATCHED_PASSWORD_DENIAL\n'
elif ((successes==0 || denials==0)); then exit 3; fi
"$client" --protocol=TCP --host="$peer" --user=module_reader --password='Module-target-read42!' --batch --skip-column-names --execute="SELECT COUNT(*) FROM mysql.user;"
"$client" --protocol=TCP --host="$peer" --user=module_denied --password='Module-target-denied42!' --batch --skip-column-names --execute="SELECT 1;"
if "$client" --protocol=TCP --host="$peer" --user=module_denied --password='Module-target-denied42!' --execute="SELECT User,Password FROM mysql.user" 2>/tmp/module-target-native-select-error; then exit 4; fi
grep 'ERROR 1142' /tmp/module-target-native-select-error
