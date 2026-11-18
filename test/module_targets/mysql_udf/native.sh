#!/bin/bash
set -eu
query() { mysql --protocol=TCP --host=127.0.0.1 --user=root --password=password --database=mysql --batch --skip-column-names --execute="$1"; }
case "$1" in
 seed)
  mysql --protocol=TCP --host=127.0.0.1 --user=root --password=password < /opt/module-target/seed.sql
  chown mysql:mysql /usr/lib64/mysql/plugin
  install -d -m 0700 -o mysql -g mysql /tmp/module-target-udf
  ;;
 sql) query "$2" ;;
 clients) query "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE ID<>CONNECTION_ID() AND USER<>'system user' AND COMMAND<>'Daemon';" ;;
 flush) query 'FLUSH PRIVILEGES;' ;;
 processes) query 'SELECT ID,USER,HOST,COMMAND,STATE FROM information_schema.PROCESSLIST ORDER BY ID;' ;;
 inventory) find /usr/lib64/mysql/plugin /tmp /tmp/module-target-udf -maxdepth 1 -type f -exec sha256sum {} + ;;
 reset) query 'DROP FUNCTION IF EXISTS sys_exec;' ;;
 probe)
  query "SELECT VERSION(),@@version_compile_os,@@version_compile_machine,@@plugin_dir,@@secure_file_priv,CURRENT_USER(); SELECT name,dl FROM mysql.func;"
  rpm -q wget
  stat -c '%U %G %a %n' /usr/lib64/mysql/plugin /tmp/module-target-udf
  ;;
 *) exit 2 ;;
esac
