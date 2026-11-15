<?php
require '/opt/module-target/seed-base.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
$mode = getenv('POST_SMTP_MODE') ?: 'vulnerable';
if ($mode === 'absent') {
    file_put_contents('/tmp/module-target-post-smtp-ready', "ready\n");
    return;
}
$version = getenv('POST_SMTP_RELEASE') ?: '2.8.6';
$releases = json_decode(file_get_contents('/opt/module-target/post-smtp-releases.json'), true, 512, JSON_THROW_ON_ERROR);
$release = $releases[$version] ?? null;
if (!$release || !hash_equals($release['sha256'], hash_file('sha256', '/opt/module-target/plugin.zip'))) {
    throw new RuntimeException('Pinned POST SMTP archive differs');
}
$changed = wp_update_user(['ID' => get_user_by('login', 'module_admin')->ID, 'user_email' => 'module_target@example.com']);
if (is_wp_error($changed)) { throw new RuntimeException($changed->get_error_message()); }
update_option('admin_email', 'module_target@example.com');
update_option('postman_options', [
    'transport_type' => 'smtp', 'hostname' => 'smtp', 'port' => 25,
    'auth_type' => 'none', 'enc_type' => 'none', 'smtp_mailers' => 'postsmtp',
    'sender_email' => 'native@example.com', 'sender_name' => 'Owned module target',
    'envelope_sender' => 'native@example.com', 'run_mode' => 'production',
    'mail_log_enabled' => $mode === 'no_logs' ? 'false' : 'true', 'mail_log_max_entries' => 250,
    'connection_timeout' => 3, 'read_timeout' => 5
]);
update_option('post_smtp_mobile_app_connection', [
    'module-target-existing-device' => ['auth_key' => 'module-target-existing-key', 'fcm_token' => 'module-target-existing-device', 'device' => 'Owned existing device', 'enable_notification' => 0]
]);
update_option('post_smtp_server_url', 'http://smtp.module-target.test');
delete_transient('post_smtp_auth_nonce');
if (!WP_Filesystem()) { throw new RuntimeException('WordPress direct filesystem unavailable'); }
$extracted = unzip_file('/opt/module-target/plugin.zip', WP_PLUGIN_DIR . '/');
if (is_wp_error($extracted)) { throw new RuntimeException($extracted->get_error_message()); }
$plugin = 'post-smtp/postman-smtp.php';
$metadata = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin, false, false);
if ($metadata['Version'] !== $version) { throw new RuntimeException('Installed POST SMTP version differs'); }
$activated = activate_plugin($plugin);
if (is_wp_error($activated)) { throw new RuntimeException($activated->get_error_message()); }
$user = get_user_by('login', 'module_admin');
$snapshot = [
    'user' => ['ID' => $user->ID, 'user_pass' => $user->user_pass, 'user_activation_key' => $user->user_activation_key],
    'devices' => get_option('post_smtp_mobile_app_connection'), 'server_url' => get_option('post_smtp_server_url'),
    'nonce' => get_transient('post_smtp_auth_nonce')
];
file_put_contents('/tmp/module-target-post-smtp-baseline.json', json_encode($snapshot, JSON_THROW_ON_ERROR));
chown('/tmp/module-target-post-smtp-baseline.json', 33);
chmod('/tmp/module-target-post-smtp-baseline.json', 0600);
file_put_contents('/tmp/module-target-post-smtp-ready', "ready\n");
