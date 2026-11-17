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
if ($operation === 'clear-sessions') {
    $agent = $argv[2] ?? '';
    $user = get_user_by('login', 'module_admin');
    if (!$user || $user->ID !== 1 || $agent !== 'module-target-masterstudy-native-control') { throw new RuntimeException('Unknown native administrator session'); }
    $manager = WP_Session_Tokens::get_instance($user->ID);
    $tokens = $manager->get_all();
    if (!$tokens || count($tokens) > 2) { throw new RuntimeException('Unexpected native administrator tokens'); }
    foreach ($tokens as $token) {
        if (($token['ua'] ?? '') !== $agent || $token['login'] < time()-300 || $token['login'] > time()+5) { throw new RuntimeException('Unowned native administrator session'); }
    }
    $manager->destroy_all();
    $result = ['tokens_removed' => count($tokens), 'user_id' => $user->ID];
}
if ($operation === 'delete-public') {
    $owned = json_decode(base64_decode($argv[2], true), true, 512, JSON_THROW_ON_ERROR);
    $name = $owned['name'];
    $user = get_user_by('login', $name);
    if (!$user || $user->ID <= 4 || $user->ID !== $owned['id'] || $user->user_email !== $owned['email'] || !wp_check_password($owned['password'], $user->user_pass, $user->ID) || !preg_match('/^module-target-masterstudy-public-[0-9]+-[a-z]+$/D', $owned['agent'])) { throw new RuntimeException('Public account ownership differs'); }
    $tokens = WP_Session_Tokens::get_instance($user->ID)->get_all();
    if (count($tokens) > 4) { throw new RuntimeException('Unexpected public token count'); }
    foreach ($tokens as $token) {
        if (($token['ua'] ?? '') !== $owned['agent'] || $token['login'] < time()-300 || $token['login'] > time()+5) { throw new RuntimeException('Unowned public session'); }
    }
    $identifier = $user->ID;
    if (!wp_delete_user($identifier) || get_userdata($identifier) || get_user_meta($identifier)) { throw new RuntimeException('Owned public deletion failed'); }
    $result = ['deleted_user_id' => $identifier, 'tokens_removed' => count($tokens)];
}
if ($operation === 'cookie') {
    $cookie = base64_decode($argv[2], true);
    if ($cookie === false) { throw new RuntimeException('Invalid cookie encoding'); }
    $result = ['validated_user_id' => wp_validate_auth_cookie($cookie, 'logged_in')];
}
if ($operation === 'password' || $operation === 'delete-user') {
    $name = $argv[2] ?? '';
    $password = $argv[3] ?? '';
    $user = get_user_by('login', $name);
    if (!$user || !preg_match('/^native_masterstudy_[a-z]+$/D', $name) || $user->ID <= 4 || $user->user_email !== str_replace('_', '-', $name).'@example.test' || !wp_check_password($password, $user->user_pass, $user->ID)) { throw new RuntimeException('Owned account identity differs'); }
    $result = ['user_id' => $user->ID, 'valid_password' => true];
    if ($operation === 'delete-user') {
        $agent = $argv[4] ?? '';
        if (!preg_match('/^module-target-masterstudy-native-[a-z]+$/D', $agent)) { throw new RuntimeException('Unknown native session owner'); }
        $tokens = WP_Session_Tokens::get_instance($user->ID)->get_all();
        if (count($tokens) > 4) { throw new RuntimeException('Unexpected token count'); }
        foreach ($tokens as $token) {
            if (($token['ua'] ?? '') !== $agent || $token['login'] < time()-300 || $token['login'] > time()+5) { throw new RuntimeException('Unowned session token'); }
        }
        $identifier = $user->ID;
        if (!wp_delete_user($identifier) || get_userdata($identifier) || get_user_meta($identifier)) { throw new RuntimeException('Owned deletion failed'); }
        $result = ['deleted_user_id' => $identifier, 'tokens_removed' => count($tokens)];
    }
}
$release = json_decode(file_get_contents('/opt/module-target/releases.json'), true, 512, JSON_THROW_ON_ERROR)[getenv('MASTERSTUDY_RELEASE')];
$hashes = [];
foreach ($release['installed_sha256'] as $path => $digest) { $hashes[$path] = hash_file('sha256', WP_PLUGIN_DIR.'/masterstudy-lms-learning-management-system/'.$path); }
$users = [];
foreach (get_users(['orderby' => 'ID', 'order' => 'ASC']) as $user) {
    $users[] = ['ID' => $user->ID, 'user_login' => $user->user_login, 'user_pass' => $user->user_pass, 'user_email' => $user->user_email, 'roles' => $user->roles, 'install_plugins' => user_can($user, 'install_plugins'), 'promote_users' => user_can($user, 'promote_users'), 'sessions' => WP_Session_Tokens::get_instance($user->ID)->get_all()];
}
$tables = [];
$table_errors = [];
foreach ($wpdb->get_col("SHOW TABLES LIKE '{$wpdb->prefix}stm_lms_%'") as $table) {
    if (!preg_match('/^[A-Za-z0-9_]+$/D', $table) || !str_starts_with($table, $wpdb->prefix.'stm_lms_')) { throw new RuntimeException('Unexpected vendor table'); }
    $rows = $wpdb->get_results('SELECT * FROM `'.$table.'`', ARRAY_A);
    if ($wpdb->last_error) { $table_errors[$table] = $wpdb->last_error; }
    usort($rows, function($first, $second) { return strcmp(json_encode($first), json_encode($second)); });
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
    'core' => get_bloginfo('version'), 'php' => PHP_VERSION, 'uid' => posix_geteuid(),
    'selected_release' => getenv('MASTERSTUDY_RELEASE'), 'constant_version' => STM_LMS_VERSION,
    'version' => get_plugin_data(WP_PLUGIN_DIR.'/masterstudy-lms-learning-management-system/masterstudy-lms-learning-management-system.php', false, false)['Version'],
    'active_plugins' => array_values(get_option('active_plugins')), 'registration_handler' => has_action('wp_ajax_nopriv_stm_lms_register', ['STM_LMS_User', 'stm_lms_register']) !== false,
    'users_can_register' => (bool)get_option('users_can_register'), 'premoderation' => STM_LMS_Options::get_option('user_premoderation', false), 'recaptcha' => STM_LMS_Helpers::g_recaptcha_enabled(),
    'archive_sha256' => hash_file('sha256', '/opt/module-target/plugin.zip'), 'installed_sha256' => $hashes,
    'database' => DB_NAME, 'table_prefix' => $wpdb->prefix, 'role' => $wpdb->get_var('SELECT CURRENT_USER()'), 'server' => $wpdb->get_var('SELECT VERSION()'), 'grants' => $wpdb->get_col('SHOW GRANTS'),
    'users' => $users, 'usermeta' => $wpdb->get_results("SELECT user_id,meta_key,meta_value FROM {$wpdb->usermeta} ORDER BY umeta_id", ARRAY_A),
    'plugin_options' => $wpdb->get_results("SELECT option_name,option_value,autoload FROM {$wpdb->options} WHERE option_name LIKE 'stm_%' OR option_name LIKE 'fs_%' ORDER BY option_name", ARRAY_A),
    'tables' => $tables, 'table_errors' => $table_errors, 'files' => $files,
    'posts' => $wpdb->get_results("SELECT ID,post_name,post_type,post_status,post_content FROM {$wpdb->posts} ORDER BY ID", ARRAY_A),
    'permalink_structure' => get_option('permalink_structure'), 'home' => get_option('home'), 'siteurl' => get_option('siteurl'), 'config_sha256' => hash_file('sha256', ABSPATH.'wp-config.php'),
    'filesystem' => ['writable' => is_writable($uploads['basedir']), 'upload_error' => $uploads['error'], 'free_bytes' => disk_free_space(ABSPATH)],
    'operation_result' => $result, 'bootstrap_output_base64' => base64_encode($bootstrap), 'db_error' => $wpdb->last_error
], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), PHP_EOL;
