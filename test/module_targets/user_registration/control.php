<?php
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = '/';
ob_start();
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
$output = ob_get_clean();
if (($argv[1] ?? '') === 'delete-plugin') {
    $file = WP_PLUGIN_DIR . '/native_membership_probe/native-proof.php';
    if (!is_file($file) || !hash_equals($argv[2],hash_file('sha256',$file))) { throw new RuntimeException('Owned native plugin source differs'); }
    wp_set_current_user(get_user_by('login','module_admin')->ID);
    $result = delete_plugins(['native_membership_probe/native-proof.php']);
    if (is_wp_error($result) || !$result || is_dir(dirname($file))) { throw new RuntimeException('Native plugin removal failed'); }
}
if (($argv[1] ?? '') === 'delete') {
    $name = $argv[2] ?? '';
    if (!preg_match('/^(?:native|module)_membership_[a-z0-9_]+$/', $name)) { throw new RuntimeException('Refusing non-probe cleanup'); }
    $user = get_user_by('login', $name);
    if (!$user || $user->ID <= 4) { throw new RuntimeException('Probe account not found or is baseline'); }
    // Orders also reference created_by without a delete cascade. Remove only
    // this owned user's orders/subscriptions before the native user deletion.
    $wpdb->delete(\WPEverest\URMembership\TableList::orders_table(), ['user_id'=>$user->ID]);
    $wpdb->delete(\WPEverest\URMembership\TableList::subscriptions_table(), ['user_id'=>$user->ID]);
    require_once ABSPATH . 'wp-admin/includes/user.php';
    if (!wp_delete_user($user->ID)) { throw new RuntimeException('Native probe cleanup failed'); }
}
$release = json_decode(file_get_contents('/opt/module-target/releases.json'), true, 512, JSON_THROW_ON_ERROR)[getenv('UR_RELEASE')];
$hashes = [];
foreach ($release['installed_sha256'] as $path => $expected) { $hashes[$path] = hash_file('sha256', WP_PLUGIN_DIR . '/user-registration/' . $path); }
$users = [];
foreach (get_users(['orderby'=>'ID','order'=>'ASC']) as $user) {
    $users[] = ['ID'=>$user->ID,'user_login'=>$user->user_login,'user_pass'=>$user->user_pass,'user_email'=>$user->user_email,'roles'=>$user->roles,'create_users'=>user_can($user,'create_users'),'install_plugins'=>user_can($user,'install_plugins')];
}
$tables = [];
$ddl = [];
foreach (\WPEverest\URMembership\Admin\Database\Database::get_tables() as $name) {
    if (!preg_match('/^wp_[a-z_]+$/',$name)) { throw new RuntimeException('Unexpected native table name'); }
    $tables[$name] = $wpdb->get_results("SELECT * FROM `$name` ORDER BY 1",ARRAY_A);
    $ddl[$name] = $wpdb->get_row("SHOW CREATE TABLE `$name`",ARRAY_N)[1];
}
$plans = [];
foreach (get_posts(['post_type'=>'ur_membership','post_status'=>'publish','numberposts'=>-1]) as $post) { $plans[]=['ID'=>$post->ID,'content'=>$post->post_content,'meta'=>get_post_meta($post->ID,'ur_membership',true)]; }
$posts = $wpdb->get_results("SELECT ID,post_name,post_type,post_status,post_content FROM {$wpdb->posts} WHERE post_type IN ('page','user_registration','ur_membership') ORDER BY ID",ARRAY_A);
$entries = [];
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(WP_PLUGIN_DIR,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::SELF_FIRST) as $entry) {
    $relative = substr($entry->getPathname(),strlen(WP_PLUGIN_DIR)+1);
    $entries[$relative] = $entry->isDir() ? 'directory' : hash_file('sha256',$entry->getPathname());
}
ksort($entries);
$uploads = wp_upload_dir();
$filesystem = [];
foreach (['plugins'=>WP_PLUGIN_DIR,'upload_base'=>$uploads['basedir'],'upload_current'=>$uploads['path']] as $label=>$path) {
    $filesystem[$label] = ['path'=>$path,'uid'=>fileowner($path),'mode'=>decoct(fileperms($path)&07777),'writable'=>is_writable($path)];
}
$filesystem['upload_error'] = $uploads['error'];
$filesystem['disk_free_bytes'] = disk_free_space(ABSPATH);
$probe = null;
if (($argv[1] ?? '') === 'password') {
    $user = get_user_by('login',$argv[2]);
    $probe = $user ? ['ID'=>$user->ID,'valid'=>wp_check_password($argv[3],$user->user_pass,$user->ID)] : null;
}
echo json_encode([
    'core'=>get_bloginfo('version'),'php'=>PHP_VERSION,'uid'=>posix_geteuid(),
    'version'=>get_plugin_data(WP_PLUGIN_DIR.'/user-registration/user-registration.php',false,false)['Version'],
    'active_plugins'=>array_values(get_option('active_plugins')),'features'=>get_option('user_registration_enabled_features'),
    'membership_active'=>ur_check_module_activation('membership'),'registration_handler'=>has_action('wp_ajax_nopriv_user_registration_user_form_submit'),
    'membership_handler'=>has_action('wp_ajax_nopriv_user_registration_membership_register_member'),
    'installed_sha256'=>$hashes,'archive_sha256'=>hash_file('sha256','/opt/module-target/plugin.zip'),
    'database'=>DB_NAME,'role'=>$wpdb->get_var('SELECT CURRENT_USER()'),'grants'=>$wpdb->get_col('SHOW GRANTS'),'server'=>$wpdb->get_var('SELECT VERSION()'),
    'table_prefix'=>$wpdb->prefix,'permalink_structure'=>get_option('permalink_structure'),'config_sha256'=>hash_file('sha256',ABSPATH.'wp-config.php'),
    'options'=>['users_can_register'=>get_option('users_can_register'),'prevent_core_login'=>get_option('user_registration_login_options_prevent_core_login')],
    'users'=>$users,'usermeta'=>$wpdb->get_results("SELECT user_id,meta_key,meta_value FROM {$wpdb->usermeta} ORDER BY umeta_id",ARRAY_A),
    'plans'=>$plans,'posts'=>$posts,'tables'=>$tables,'table_ddl'=>$ddl,'plugin_entries'=>$entries,'filesystem'=>$filesystem,'password_check'=>$probe,
    'bootstrap_output_base64'=>base64_encode($output),'db_error'=>$wpdb->last_error
],JSON_PRETTY_PRINT|JSON_THROW_ON_ERROR),PHP_EOL;
