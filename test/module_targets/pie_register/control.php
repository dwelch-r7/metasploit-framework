<?php
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = '/';
ob_start();
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
require_once ABSPATH . 'wp-admin/includes/file.php';
$bootstrap = ob_get_clean();
$operation = $argv[1] ?? '';
$operation_result = null;
if ($operation === 'clear-sessions') {
    $name = $argv[2] ?? '';
    $agent = $argv[3] ?? '';
    if (!in_array($name, ['module_admin','module_author','module_subscriber','module_editor'], true) || !preg_match('/^module-target-pie-(?:native|public)-[a-z0-9_-]+$/D', $agent)) { throw new RuntimeException('Refusing unowned session cleanup'); }
    $user = get_user_by('login', $name);
    $manager = WP_Session_Tokens::get_instance($user->ID);
    $sessions = $manager->get_all();
    if (count($sessions) > 4) { throw new RuntimeException('Unexpected owned session count'); }
    foreach ($sessions as $session) {
        if (($session['ua'] ?? '') !== $agent || $session['login'] < time()-300 || $session['login'] > time()+5) { throw new RuntimeException('Refusing cleanup of an unrelated session'); }
    }
    $manager->destroy_all();
    $operation_result = ['removed'=>count($sessions),'username'=>$name,'agent'=>$agent];
}
if ($operation === 'delete-plugin') {
    $path = WP_PLUGIN_DIR . '/native_pie_probe/native-proof.php';
    if (!is_file($path) || !hash_equals($argv[2],hash_file('sha256',$path))) { throw new RuntimeException('Owned native plugin differs'); }
    wp_set_current_user(get_user_by('login','module_admin')->ID);
    $result = delete_plugins(['native_pie_probe/native-proof.php']);
    if (is_wp_error($result) || !$result || is_dir(dirname($path))) { throw new RuntimeException('Native plugin cleanup failed'); }
    $operation_result = ['plugin_removed'=>true];
}
if ($operation === 'cookie') {
    $cookie = base64_decode($argv[2], true);
    if ($cookie === false) { throw new RuntimeException('Invalid cookie encoding'); }
    $identifier = wp_validate_auth_cookie($cookie, 'logged_in');
    $parsed = wp_parse_auth_cookie($cookie, 'logged_in');
    $operation_result = ['validated_user_id'=>$identifier,'parsed_username'=>$parsed['username'] ?? null];
}
$release = json_decode(file_get_contents('/opt/module-target/releases.json'), true, 512, JSON_THROW_ON_ERROR)[getenv('PIE_RELEASE')];
$hashes = [];
foreach ($release['installed_sha256'] as $name=>$digest) { $hashes[$name] = hash_file('sha256',WP_PLUGIN_DIR.'/pie-register/'.$name); }
$users = [];
foreach (get_users(['orderby'=>'ID','order'=>'ASC']) as $user) { $users[]=['ID'=>$user->ID,'user_login'=>$user->user_login,'user_pass'=>$user->user_pass,'user_email'=>$user->user_email,'roles'=>$user->roles,'install_plugins'=>user_can($user,'install_plugins'),'sessions'=>WP_Session_Tokens::get_instance($user->ID)->get_all()]; }
$entries = [];
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(WP_PLUGIN_DIR,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::SELF_FIRST) as $entry) { $relative=substr($entry->getPathname(),strlen(WP_PLUGIN_DIR)+1); $entries[$relative]=$entry->isDir()?'directory':hash_file('sha256',$entry->getPathname()); }
ksort($entries);
$tables=[];
foreach ($wpdb->get_col($wpdb->prepare('SHOW TABLES LIKE %s',$wpdb->esc_like($wpdb->prefix.'piereg').'%')) as $name) {
    if (!preg_match('/^wp_[a-z0-9_]+$/D',$name)) { throw new RuntimeException('Unexpected native table name'); }
    $tables[$name]=$wpdb->get_results("SELECT * FROM `$name` ORDER BY 1",ARRAY_A);
}
$uploads=wp_upload_dir();$filesystem=[];
foreach (['plugins'=>WP_PLUGIN_DIR,'upload_base'=>$uploads['basedir'],'upload_current'=>$uploads['path']]as$label=>$path) { $filesystem[$label]=['path'=>$path,'uid'=>fileowner($path),'writable'=>is_writable($path)]; }
$filesystem['upload_error']=$uploads['error'];$filesystem['disk_free_bytes']=disk_free_space(ABSPATH);
echo json_encode([
    'core'=>get_bloginfo('version'),'php'=>PHP_VERSION,'uid'=>posix_geteuid(),'version'=>get_plugin_data(WP_PLUGIN_DIR.'/pie-register/pie-register.php',false,false)['Version'],
    'active_plugins'=>array_values(get_option('active_plugins')),'class_loaded'=>class_exists('PieRegister'),'native_init_handler'=>isset($GLOBALS['pie_register']) && has_action('init',[$GLOBALS['pie_register'],'pie_main'])!==false,
    'archive_sha256'=>hash_file('sha256','/opt/module-target/plugin.zip'),'installed_sha256'=>$hashes,'plugin_entries'=>$entries,
    'database'=>DB_NAME,'role'=>$wpdb->get_var('SELECT CURRENT_USER()'),'server'=>$wpdb->get_var('SELECT VERSION()'),'grants'=>$wpdb->get_col('SHOW GRANTS'),
    'users'=>$users,'usermeta'=>$wpdb->get_results("SELECT user_id,meta_key,meta_value FROM {$wpdb->usermeta} ORDER BY umeta_id",ARRAY_A),'plugin_options'=>get_option(OPTION_PIE_REGISTER),'plugin_tables'=>$tables,
    'pages'=>$wpdb->get_results("SELECT ID,post_name,post_type,post_status,post_content FROM {$wpdb->posts} WHERE post_type='page' ORDER BY ID",ARRAY_A),'home'=>get_option('home'),'siteurl'=>get_option('siteurl'),'permalink_structure'=>get_option('permalink_structure'),'config_sha256'=>hash_file('sha256',ABSPATH.'wp-config.php'),
    'filesystem'=>$filesystem,'operation_result'=>$operation_result,'bootstrap_output_base64'=>base64_encode($bootstrap),'db_error'=>$wpdb->last_error
],JSON_PRETTY_PRINT|JSON_THROW_ON_ERROR),PHP_EOL;
