<?php
chdir('/var/www/html');
define('sugarEntry', true);
require_once 'include/entryPoint.php';
require 'suitecrm_version.php';
$result = $GLOBALS['db']->query('SELECT id,user_name,user_hash,is_admin,status,deleted FROM users ORDER BY user_name');
$users = array();
while ($row = $GLOBALS['db']->fetchByAssoc($result, false)) {
    $users[] = $row;
}
$result = $GLOBALS['db']->query('SELECT id,name,deleted FROM accounts ORDER BY id');
$accounts = array();
while ($row = $GLOBALS['db']->fetchByAssoc($result, false)) {
    $accounts[] = $row;
}
echo json_encode(array('version' => $suitecrm_version, 'php' => PHP_VERSION,
    'export_sha256' => hash_file('sha256', 'include/export_utils.php'),
    'users' => $users, 'accounts' => $accounts)), "\n";
