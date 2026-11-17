<?php
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = '/';
ob_start();
require getcwd().'/wp-load.php';
require_once ABSPATH.'wp-admin/includes/plugin.php';
require_once ABSPATH.'wp-admin/includes/user.php';
$bootstrap = ob_get_clean();
$operation = $argv[1] ?? '';
$result = null;
$mailDirectory = '/tmp/module-target-gdpr-mail';
if ($operation === 'options') {
    $changes = json_decode(base64_decode($argv[2], true), true, 512, JSON_THROW_ON_ERROR);
    foreach ($changes as $name => $change) {
        if (!in_array($name, ['users_can_register', 'default_role', 'admin_email'], true) || get_option($name) !== $change['expected']) { throw new RuntimeException('Option ownership differs: '.$name); }
    }
    $writes = [];
    foreach ($changes as $name => $change) {
        $written = update_option($name, $change['value']);
        $actual = get_option($name);
        // Changed numeric options are cached as integers; unchanged DB reads
        // retain strings. Require an exact requested or native-sanitized value.
        if ($actual !== $change['value'] && $actual !== sanitize_option($name, $change['value'])) { throw new RuntimeException('Native option update failed: '.$name); }
        $writes[$name] = ['changed' => $written, 'actual' => $actual, 'type' => get_debug_type($actual)];
    }
    $result = ['options_checked' => array_keys($changes), 'writes' => $writes];
}
if ($operation === 'clear-sessions') {
    $agent = $argv[2] ?? '';
    $user = get_user_by('login', 'module_admin');
    if (!$user || $user->ID !== 1 || $agent !== 'module-target-gdpr-native-control') { throw new RuntimeException('Unknown native administrator session'); }
    $manager = WP_Session_Tokens::get_instance($user->ID);
    $tokens = $manager->get_all();
    if (!$tokens || count($tokens) > 2) { throw new RuntimeException('Unexpected native administrator token count'); }
    foreach ($tokens as $token) {
        if (($token['ua'] ?? '') !== $agent || $token['login'] < time()-300 || $token['login'] > time()+5) { throw new RuntimeException('Unowned native administrator session'); }
    }
    $manager->destroy_all();
    $result = ['tokens_removed' => count($tokens), 'user_id' => $user->ID];
}
if ($operation === 'cookie') {
    $cookie = base64_decode($argv[2], true);
    if ($cookie === false) { throw new RuntimeException('Invalid cookie encoding'); }
    $result = ['validated_user_id' => wp_validate_auth_cookie($cookie, 'logged_in')];
}
$publicAccount = in_array($operation, ['password-public', 'delete-public'], true);
if ($operation === 'password' || $operation === 'delete-user' || $publicAccount) {
    $owned = json_decode(base64_decode($argv[2], true), true, 512, JSON_THROW_ON_ERROR);
    $user = get_user_by('login', $owned['name']);
    if (!$user || $user->ID <= 4 || $user->ID !== $owned['id'] || (!$publicAccount && !preg_match('/^native_gdpr_[a-z]+$/D', $owned['name'])) || $user->user_email !== $owned['email'] || !wp_check_password($owned['password'], $user->user_pass, $user->ID)) { throw new RuntimeException('Owned account identity differs'); }
    $result = ['user_id' => $user->ID, 'valid_password' => true];
    if ($operation === 'delete-user' || $operation === 'delete-public') {
        $agent = $owned['agent'];
        if (!preg_match($publicAccount ? '/^module-target-gdpr-public-[0-9]+-[a-z]+$/D' : '/^module-target-gdpr-native-[a-z]+$/D', $agent)) { throw new RuntimeException('Unknown native session owner'); }
        $tokens = WP_Session_Tokens::get_instance($user->ID)->get_all();
        if (count($tokens) > 4) { throw new RuntimeException('Unexpected native token count'); }
        foreach ($tokens as $token) {
            if (($token['ua'] ?? '') !== $agent || $token['login'] < time()-300 || $token['login'] > time()+5) { throw new RuntimeException('Unowned native session token'); }
        }
        $identifier = $user->ID;
        if (!wp_delete_user($identifier) || get_userdata($identifier) || get_user_meta($identifier)) { throw new RuntimeException('Owned deletion failed'); }
        $result = ['deleted_user_id' => $identifier, 'tokens_removed' => count($tokens)];
    }
}
$mail = [];
foreach (new DirectoryIterator($mailDirectory) as $entry) {
    if ($entry->isDot()) { continue; }
    if ($entry->isLink() || !$entry->isFile() || !preg_match('/^message\.[A-Za-z0-9]+\.eml$/D', $entry->getFilename()) || $entry->getSize() > 1048576) { throw new RuntimeException('Unknown spool entry'); }
    $raw = file_get_contents($entry->getPathname());
    $mail[$entry->getFilename()] = ['sha256' => hash('sha256', $raw), 'bytes' => strlen($raw), 'base64' => base64_encode($raw)];
}
ksort($mail);
if ($operation === 'clear-mail') {
    $expected = json_decode(base64_decode($argv[2], true), true, 512, JSON_THROW_ON_ERROR);
    if (array_map(fn($entry) => $entry['sha256'], $mail) !== $expected) { throw new RuntimeException('Mail ownership differs'); }
    foreach ($mail as $name => $entry) { if (!unlink($mailDirectory.'/'.$name)) { throw new RuntimeException('Owned mail deletion failed'); } }
    $result = ['mail_removed' => count($mail)];
    $mail = [];
}
$release = json_decode(file_get_contents('/opt/module-target/releases.json'), true, 512, JSON_THROW_ON_ERROR)[getenv('GDPR_RELEASE')];
$hashes = [];
foreach ($release['installed_sha256'] as $path => $digest) { $hashes[$path] = hash_file('sha256', WP_PLUGIN_DIR.'/wp-gdpr-compliance/'.$path); }
$users = [];
foreach (get_users(['orderby' => 'ID', 'order' => 'ASC']) as $user) {
    $users[] = ['ID' => $user->ID, 'user_login' => $user->user_login, 'user_pass' => $user->user_pass, 'user_email' => $user->user_email, 'roles' => $user->roles, 'install_plugins' => user_can($user, 'install_plugins'), 'promote_users' => user_can($user, 'promote_users'), 'sessions' => WP_Session_Tokens::get_instance($user->ID)->get_all()];
}
$tables = [];
$tableErrors = [];
foreach ($wpdb->get_col("SHOW TABLES LIKE '{$wpdb->prefix}wpgdprc_%'") as $table) {
    if (!preg_match('/^[A-Za-z0-9_]+$/D', $table) || !str_starts_with($table, $wpdb->prefix.'wpgdprc_')) { throw new RuntimeException('Unknown vendor table'); }
    $rows = $wpdb->get_results('SELECT * FROM `'.$table.'`', ARRAY_A);
    if ($wpdb->last_error) { $tableErrors[$table] = $wpdb->last_error; }
    usort($rows, fn($first, $second) => strcmp(json_encode($first), json_encode($second)));
    $tables[$table] = $rows;
}
$uploads = wp_upload_dir();
$files = [];
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($uploads['basedir'], FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST) as $entry) {
    if ($entry->isLink()) { throw new RuntimeException('Unexpected upload symlink'); }
    $relative = substr($entry->getPathname(), strlen($uploads['basedir'])+1);
    $files[$relative] = $entry->isDir() ? 'directory' : hash_file('sha256', $entry->getPathname());
}
ksort($files);
echo json_encode([
    'core' => get_bloginfo('version'), 'php' => PHP_VERSION, 'uid' => posix_geteuid(), 'selected_release' => getenv('GDPR_RELEASE'),
    'version' => get_plugin_data(WP_PLUGIN_DIR.'/wp-gdpr-compliance/wp-gdpr-compliance.php', false, false)['Version'],
    'active_plugins' => array_values(get_option('active_plugins')),
    'guest_action_handler' => has_action('wp_ajax_nopriv_wpgdprc_process_action', [WPGDPRC\Includes\Ajax::getInstance(), 'processAction']) !== false,
    'guest_settings_handler' => has_action('wp_ajax_nopriv_wpgdprc_process_settings') !== false,
    'authenticated_settings_handler' => has_action('wp_ajax_wpgdprc_process_settings', [WPGDPRC\Includes\Ajax::getInstance(), 'processSettings']) !== false,
    'archive_sha256' => hash_file('sha256', '/opt/module-target/plugin.zip'), 'installed_sha256' => $hashes,
    'database' => DB_NAME, 'table_prefix' => $wpdb->prefix, 'role' => $wpdb->get_var('SELECT CURRENT_USER()'), 'server' => $wpdb->get_var('SELECT VERSION()'), 'grants' => $wpdb->get_col('SHOW GRANTS'),
    'users' => $users, 'usermeta' => $wpdb->get_results("SELECT user_id,meta_key,meta_value FROM {$wpdb->usermeta} ORDER BY umeta_id", ARRAY_A),
    'plugin_options' => $wpdb->get_results("SELECT option_name,option_value,autoload FROM {$wpdb->options} WHERE option_name LIKE 'wpgdprc_%' ORDER BY option_name", ARRAY_A),
    'options' => ['users_can_register' => get_option('users_can_register'), 'default_role' => get_option('default_role'), 'admin_email' => get_option('admin_email')],
    'tables' => $tables, 'table_errors' => $tableErrors, 'files' => $files, 'mail' => $mail, 'mail_command' => ini_get('sendmail_path'),
    'posts' => $wpdb->get_results("SELECT ID,post_name,post_type,post_status,post_content FROM {$wpdb->posts} ORDER BY ID", ARRAY_A),
    'permalink_structure' => get_option('permalink_structure'), 'home' => get_option('home'), 'siteurl' => get_option('siteurl'), 'config_sha256' => hash_file('sha256', ABSPATH.'wp-config.php'),
    'filesystem' => ['writable' => is_writable($uploads['basedir']), 'upload_error' => $uploads['error'], 'free_bytes' => disk_free_space(ABSPATH)],
    'operation_result' => $result, 'bootstrap_output_base64' => base64_encode($bootstrap), 'db_error' => $wpdb->last_error
], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), PHP_EOL;
