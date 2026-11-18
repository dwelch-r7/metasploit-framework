#!/bin/bash
set -eu
mode="$1"
user="${2:-root}"
client="${NATIVE_MYSQL_CLIENT:-mysql}"
password=Module-schema-password42!
if [[ "$user" == root ]]; then password=password; fi
query() { "$client" --protocol=TCP --host=127.0.0.1 --default-character-set=utf8mb4 --user="$user" --password="$password" --batch --skip-column-names --execute="$1"; }
if [[ "$mode" == seed ]]; then
 "$client" --protocol=TCP --host=127.0.0.1 --default-character-set=utf8mb4 --user=root --password=password < /opt/module-target/seed.sql
elif [[ "$mode" == databases ]]; then
 query "SELECT HEX(SCHEMA_NAME) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('information_schema','mysql','performance_schema','test') ORDER BY SCHEMA_NAME;"
elif [[ "$mode" == tables ]]; then
 query "SELECT HEX(TABLE_SCHEMA),HEX(TABLE_NAME) FROM information_schema.TABLES WHERE TABLE_SCHEMA NOT IN ('information_schema','mysql','performance_schema','test') ORDER BY TABLE_SCHEMA,TABLE_NAME;"
elif [[ "$mode" == columns ]]; then
 query "SELECT HEX(TABLE_SCHEMA),HEX(TABLE_NAME),HEX(COLUMN_NAME),HEX(COLUMN_TYPE),ORDINAL_POSITION FROM information_schema.COLUMNS WHERE TABLE_SCHEMA NOT IN ('information_schema','mysql','performance_schema','test') ORDER BY TABLE_SCHEMA,TABLE_NAME,ORDINAL_POSITION;"
elif [[ "$mode" == state ]]; then
 query "SELECT HEX(SCHEMA_NAME) FROM information_schema.SCHEMATA ORDER BY SCHEMA_NAME; SELECT HEX(User),HEX(Host),HEX(plugin) FROM mysql.user ORDER BY User,Host; SELECT HEX(entry),amount,HEX(binary_value),HEX(notes) FROM module_basic.normal_rows ORDER BY id;"
elif [[ "$mode" == flush ]]; then
 query "FLUSH PRIVILEGES;"
elif [[ "$mode" == processes ]]; then
 query "SELECT ID,USER,HOST,COMMAND,STATE FROM information_schema.PROCESSLIST ORDER BY ID;"
elif [[ "$mode" == clients ]]; then
 # MySQL 8's event_scheduler is a server Daemon, not an authenticated client.
 query "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE ID<>CONNECTION_ID() AND USER<>'system user' AND COMMAND<>'Daemon';"
elif [[ "$mode" == probe ]]; then
 query "SELECT VERSION(),CURRENT_USER(),'NATIVE_SCHEMA_ROOT';"
 user=schema_basic;password=Module-schema-password42!
 query "SELECT CURRENT_USER(),'NATIVE_SCHEMA_BASIC',COUNT(*) FROM module_basic.normal_rows; SHOW DATABASES; SHOW FULL COLUMNS FROM module_basic.normal_rows;"
 if query "SHOW FULL TABLES FROM \`module odd-db\`" 2>/tmp/module-target-schema-denial; then exit 2; fi
 grep 'ERROR 1044' /tmp/module-target-schema-denial
 user=schema_catalog
 query 'SELECT CURRENT_USER(),"NATIVE_SCHEMA_CATALOG"; SHOW FULL TABLES FROM `module odd-db`; SHOW FULL COLUMNS FROM `module odd-db`.`order details`; SHOW FULL TABLES FROM `module``quoted`; SHOW FULL COLUMNS FROM `module``quoted`.`table``quoted`;'
 user=schema_none
 query "SELECT CURRENT_USER(),'NATIVE_SCHEMA_NONE'; SHOW DATABASES;"
else exit 2
fi
