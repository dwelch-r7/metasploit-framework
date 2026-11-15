<?php
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/';
$_SERVER['PHP_SELF'] = (getenv('LAB_PREFIX') ?: '') . '/index.php';
$_SERVER['REQUEST_METHOD'] = 'GET';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$operation = $argv[1] ?? 'inspect';
if ($operation === 'restore') {
    $snapshot = json_decode(file_get_contents('/tmp/module-target-post-smtp-baseline.json'), true, 512, JSON_THROW_ON_ERROR);
    $user = $snapshot['user'];
    $updated = $wpdb->update($wpdb->users, ['user_pass' => $user['user_pass'], 'user_activation_key' => $user['user_activation_key']], ['ID' => $user['ID']]);
    if ($updated === false) { throw new RuntimeException('Owned user state restoration failed'); }
    clean_user_cache($user['ID']);
    update_option('post_smtp_mobile_app_connection', $snapshot['devices']);
    update_option('post_smtp_server_url', $snapshot['server_url']);
    delete_transient('post_smtp_auth_nonce');
    if ($snapshot['nonce'] !== false) { set_transient('post_smtp_auth_nonce', $snapshot['nonce'], 1800); }
    echo json_encode(['operator_restore' => true, 'mail_audit_logs_retained' => true], JSON_THROW_ON_ERROR), "\n";
    return;
}
if ($operation === 'key') {
    $input = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
    $parsed = parse_url($input['url']);
    parse_str($parsed['query'] ?? '', $query);
    $checked = check_password_reset_key($query['key'] ?? '', $query['login'] ?? '');
    echo json_encode(['valid' => !is_wp_error($checked), 'login' => is_wp_error($checked) ? null : $checked->user_login], JSON_THROW_ON_ERROR), "\n";
    return;
}
if ($operation !== 'inspect') { throw new InvalidArgumentException('Unknown fixture operation'); }
$user = get_user_by('login', 'module_admin');
$plugin = 'post-smtp/postman-smtp.php';
$active = is_plugin_active($plugin);
$metadata = $active ? get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false) : null;
$logs = [];
if ($active) {
    $logs = $wpdb->get_results("SELECT id, success, original_to, original_subject, original_message, time FROM {$wpdb->prefix}post_smtp_logs ORDER BY id", ARRAY_A);
    if ($wpdb->last_error) { throw new RuntimeException($wpdb->last_error); }
}
echo json_encode([
    'core' => get_bloginfo('version'), 'php' => PHP_VERSION, 'sapi' => PHP_SAPI, 'uid' => posix_geteuid(),
    'active' => $active, 'active_plugins' => get_option('active_plugins'),
    'plugin_version' => $metadata['Version'] ?? null, 'prefix' => getenv('LAB_PREFIX') ?: '',
    'archive_sha256' => $active ? hash_file('sha256', '/opt/module-target/plugin.zip') : null,
    'rest_source_sha256' => $active ? hash_file('sha256', WP_PLUGIN_DIR . '/post-smtp/Postman/Mobile/includes/rest-api/v1/rest-api.php') : null,
    'options' => get_option('postman_options'), 'logging_enabled' => $active ? PostmanOptions::getInstance()->isMailLoggingEnabled() : null,
    'devices' => get_option('post_smtp_mobile_app_connection'), 'server_url' => get_option('post_smtp_server_url'),
    'auth_nonce' => get_transient('post_smtp_auth_nonce'),
    'user' => ['login' => $user->user_login, 'email' => $user->user_email, 'password_sha256' => hash('sha256', $user->user_pass), 'activation_key_sha256' => hash('sha256', $user->user_activation_key)],
    'logs' => $logs
], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), "\n";
