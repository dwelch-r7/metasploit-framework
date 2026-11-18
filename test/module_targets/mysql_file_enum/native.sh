#!/bin/bash
set -eu
mode="$1"
client="${NATIVE_MYSQL_CLIENT:-mysql}"
base=/var/lib/mysql-files/module-target
query() {
 local user="${2:-root}" password=Module-schema-password42!
 if [[ "$user" == root ]]; then password=password; fi
 "$client" --protocol=TCP --host=127.0.0.1 --default-character-set=utf8mb4 --user="$user" --password="$password" --batch --skip-column-names --execute="$1"
}
expect_error() {
 local number="$1" sql="$2" user="${3:-file_operator}"
 if query "$sql" "$user" >/tmp/module-file-native-error 2>&1; then cat /tmp/module-file-native-error; exit 2; fi
 grep "^ERROR $number " /tmp/module-file-native-error
}
if [[ "$mode" == seed ]]; then
 mkdir -p "$base/read-dir"
 printf '7\n8\n' > "$base/numbers.txt"
 printf 'not-an-int\n' > "$base/text.txt"
 printf '9999999999999999999999999999999999999\n' > "$base/range.txt"
 : > "$base/empty.txt"
 printf 'private\n' > "$base/private.txt"
 printf '7\n' > "$base/quote'file.txt"
 printf 'outside\n' > /tmp/module-target-outside.txt
 chown -R mysql:mysql "$base"
 chmod 755 "$base" "$base/read-dir"
 chmod 644 "$base/numbers.txt" "$base/text.txt" "$base/range.txt" "$base/empty.txt" "$base/quote'file.txt"
 chown root:root "$base/private.txt"
 chmod 600 "$base/private.txt"
 "$client" --protocol=TCP --host=127.0.0.1 --user=root --password=password < /opt/module-target/seed.sql
elif [[ "$mode" == probe ]]; then
 query "SELECT VERSION(),@@secure_file_priv,@@sql_mode,'NATIVE_FILE_ROOT';"
 query "SELECT CURRENT_USER(),'NATIVE_FILE_OPERATOR'; LOAD DATA INFILE '$base/numbers.txt' INTO TABLE module_files.native_load; SELECT COUNT(*),SUM(brute) FROM module_files.native_load;" file_operator
 expect_error 1366 "LOAD DATA INFILE '$base/text.txt' INTO TABLE module_files.native_load;"
 expect_error 1264 "LOAD DATA INFILE '$base/range.txt' INTO TABLE module_files.native_load;"
 query "LOAD DATA INFILE '$base/empty.txt' INTO TABLE module_files.native_load; LOAD DATA INFILE '$base/quote''file.txt' INTO TABLE module_files.native_load; LOAD DATA INFILE '$base/numbers.txt' INTO TABLE \`module files\`.\`native table\`;" file_operator
 query "CREATE TABLE \`module files\`.\`module enum table\` (brute INT); LOAD DATA INFILE '$base/numbers.txt' INTO TABLE \`module files\`.\`module enum table\`; SELECT COUNT(*),SUM(brute) FROM \`module files\`.\`module enum table\`; DROP TABLE \`module files\`.\`module enum table\`;" file_operator
 expect_error 1085 "LOAD DATA INFILE '$base/read-dir' INTO TABLE module_files.native_load;"
 expect_error 29 "LOAD DATA INFILE '$base/private.txt' INTO TABLE module_files.native_load;"
 expect_error 13 "LOAD DATA INFILE '$base/absent.txt' INTO TABLE module_files.native_load;"
 expect_error 1290 "LOAD DATA INFILE '/tmp/module-target-outside.txt' INTO TABLE module_files.native_load;"
 query "SELECT CURRENT_USER(),'NATIVE_NO_FILE'; SELECT COUNT(*) FROM module_files.native_load;" no_file
 expect_error 1045 "LOAD DATA INFILE '$base/numbers.txt' INTO TABLE module_files.native_load;" no_file
 query 'TRUNCATE module_files.native_load; TRUNCATE `module files`.`native table`;'
elif [[ "$mode" == state ]]; then
 query "SELECT HEX(TABLE_SCHEMA),HEX(TABLE_NAME) FROM information_schema.TABLES WHERE TABLE_SCHEMA IN ('module_files','module files') ORDER BY TABLE_SCHEMA,TABLE_NAME; SELECT brute FROM module_files.existing_rows ORDER BY brute; SELECT COUNT(*) FROM module_files.native_load; SELECT COUNT(*) FROM \`module files\`.\`native table\`; SELECT HEX(User),HEX(Host),HEX(plugin) FROM mysql.user ORDER BY User,Host;"
 find "$base" -printf '%m %u %g %p\n' | sort
 find "$base" -type f -exec sha256sum '{}' \; | sort
elif [[ "$mode" == existing ]]; then
 query 'SELECT brute FROM module_files.existing_rows ORDER BY brute;'
elif [[ "$mode" == reset_existing ]]; then
 query 'TRUNCATE module_files.existing_rows; INSERT INTO module_files.existing_rows VALUES (777);'
elif [[ "$mode" == flush ]]; then
 query 'FLUSH PRIVILEGES;'
elif [[ "$mode" == processes ]]; then
 query 'SELECT ID,USER,HOST,COMMAND,STATE FROM information_schema.PROCESSLIST ORDER BY ID;'
elif [[ "$mode" == clients ]]; then
 query "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE ID<>CONNECTION_ID() AND USER<>'system user' AND COMMAND<>'Daemon';"
else exit 2
fi
