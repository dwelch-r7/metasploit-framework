<?php
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ? getenv('LAB_PREFIX') : '') . '/';
require_once getcwd() . '/wp-load.php';
global $wp_version;
$accounts = json_decode(file_get_contents('/opt/module-target/accounts.json'), true);
$users = array();
foreach ($accounts as $name => $account) {
    $user = get_user_by('login', $name);
    if (!$user) {
        $id = wp_create_user($name, $account['password'], str_replace('_', '-', $name) . '@example.test');
        if (is_wp_error($id)) {
            throw new RuntimeException($id->get_error_message());
        }
        $changed = wp_update_user(array('ID' => $id, 'role' => $account['role']));
        if (is_wp_error($changed)) {
            throw new RuntimeException($changed->get_error_message());
        }
    }
    $valid = wp_authenticate($name, $account['password']);
    $wrong = wp_authenticate($name, 'module-target-wrong-password');
    if (is_wp_error($valid) || !is_wp_error($wrong)) {
        throw new RuntimeException('Native account authentication differs: ' . $name);
    }
    $users[$name] = array('id' => $valid->ID, 'roles' => $valid->roles, 'wrong_error' => $wrong->get_error_code());
}
$xmlrpc_source = file_get_contents(ABSPATH . 'wp-includes/class-wp-xmlrpc-server.php');
$json = json_encode(array(
    'version' => $wp_version, 'php' => PHP_VERSION, 'accounts' => $users,
    'xmlrpc_source_sha256' => hash('sha256', $xmlrpc_source),
    'has_auth_failed_latch' => strpos($xmlrpc_source, '$auth_failed') !== false,
    'active_plugins' => get_option('active_plugins'), 'mail_command' => ini_get('sendmail_path')
), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
if ($json === false) {
    throw new RuntimeException('Native profile cannot be encoded as JSON');
}
echo $json . "\n";
