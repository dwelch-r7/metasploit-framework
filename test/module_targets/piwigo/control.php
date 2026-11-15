<?php
$conf = [];
require getcwd() . '/local/config/database.inc.php';
if (!preg_match('/^[a-zA-Z][a-zA-Z0-9_]*$/', $prefixeTable)) { throw new RuntimeException('Unexpected table prefix'); }
$database = new mysqli($conf['db_host'], $conf['db_user'], $conf['db_password'], $conf['db_base']);
if ($database->connect_error || !$database->set_charset('utf8mb4')) { throw new RuntimeException('Native database connection failed'); }
$users = $database->query('SELECT u.id,u.username,u.password,i.status FROM ' . $prefixeTable . 'users u LEFT JOIN ' . $prefixeTable . 'user_infos i ON i.user_id=u.id ORDER BY u.id')->fetch_all(MYSQLI_ASSOC);
if (!preg_match("/define\(\s*'PHPWG_VERSION'\s*,\s*'([^']+)'\s*\)/", file_get_contents('include/constants.php'), $version)) { throw new RuntimeException('Version constant missing'); }
$hashes = [];
foreach (['admin/history.php', 'include/constants.php', 'admin/themes/default/template/history.tpl'] as $name) { $hashes[$name] = hash_file('sha256', $name); }
$limits = $database->query('SELECT @@session.group_concat_max_len AS group_concat_max_len, LENGTH(GROUP_CONCAT(CONCAT_WS(0x3b, username, IFNULL(password, REPEAT(0x31,0))))) AS truncated_length, SUM(LENGTH(CONCAT_WS(0x3b, username, IFNULL(password, REPEAT(0x31,0))))) + COUNT(*) - 1 AS full_length FROM ' . $prefixeTable . 'users')->fetch_assoc();
echo json_encode(['version'=>$version[1], 'php'=>PHP_VERSION, 'uid'=>posix_geteuid(), 'sapi'=>PHP_SAPI, 'database'=>$conf['db_base'], 'table_prefix'=>$prefixeTable, 'server_version'=>$database->server_info, 'source_sha256'=>$hashes, 'users'=>$users, 'limits'=>$limits], JSON_PRETTY_PRINT), "\n";
