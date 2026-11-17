<?php
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['REQUEST_URI'] = '/';
ob_start();
require getcwd().'/wp-load.php';
require_once ABSPATH.'wp-admin/includes/plugin.php';
require_once ABSPATH.'wp-admin/includes/file.php';
require_once ABSPATH.'wp-admin/includes/user.php';
$bootstrap = ob_get_clean();
$operation = $argv[1] ?? '';
$operation_result = null;
$option_name = \SureTriggers\Controllers\OptionController::$option;
$option_row = static function () use ($wpdb,$option_name) { return $wpdb->get_row($wpdb->prepare("SELECT option_value,autoload FROM {$wpdb->options} WHERE option_name=%s",$option_name),ARRAY_A); };
if ($operation === 'cookie') {
    $cookie = base64_decode($argv[2],true);
    if ($cookie === false) { throw new RuntimeException('Invalid native cookie encoding'); }
    $operation_result = ['validated_user_id'=>wp_validate_auth_cookie($cookie,'logged_in')];
}
if ($operation === 'password') {
    $user = get_user_by('login',$argv[2]);
    if (!$user) { throw new RuntimeException('Owned password target absent'); }
    $operation_result = ['valid'=>wp_check_password($argv[3],$user->user_pass,$user->ID),'user_id'=>$user->ID];
}
if ($operation === 'delete-user') {
    $name = $argv[2] ?? '';
    $user = get_user_by('login',$name);
    $native = $name==='native_sure_probe';
    $public = preg_match('/^module_sure_[a-z0-9_]+$/D',$name)===1;
    $email = $native?'native-sure@example.test':str_replace('_','-',$name).'@example.test';
    if ((!$native && !$public) || !$user || $user->ID<=4 || $user->user_email!==$email || !wp_check_password($argv[3],$user->user_pass,$user->ID)) { throw new RuntimeException('Refusing unowned user deletion'); }
    if ($public) {
        $agent=$argv[4]??'';
        if (!preg_match('/^module-target-sure-public-[a-z0-9_-]+$/D',$agent)) { throw new RuntimeException('Unknown public session owner'); }
        $sessions=WP_Session_Tokens::get_instance($user->ID)->get_all();
        if (count($sessions)>4) { throw new RuntimeException('Unexpected public token count'); }
        foreach ($sessions as $session) { if (($session['ua']??'')!==$agent || $session['login']<time()-300 || $session['login']>time()+5) { throw new RuntimeException('Refusing unrelated public sessions'); } }
    }
    $identifier = $user->ID;
    if (!wp_delete_user($identifier) || get_userdata($identifier) || get_user_meta($identifier)) { throw new RuntimeException('Owned native user deletion failed'); }
    $operation_result = ['deleted'=>$identifier,'username'=>$name];
}
if ($operation === 'clear-sessions') {
    $name = $argv[2] ?? '';$agent = $argv[3] ?? '';
    if ($name!=='module_admin' || !preg_match('/^module-target-sure-native-[a-z0-9_-]+-control$/D',$agent)) { throw new RuntimeException('Refusing unowned session cleanup'); }
    $user = get_user_by('login',$name);$manager = WP_Session_Tokens::get_instance($user->ID);$sessions = $manager->get_all();
    if (!$sessions || count($sessions)>2) { throw new RuntimeException('Unexpected native token count'); }
    foreach ($sessions as $session) {
        if (($session['ua']??'')!==$agent || $session['login']<time()-300 || $session['login']>time()+5) { throw new RuntimeException('Refusing unrelated session cleanup'); }
    }
    $login = get_user_meta($user->ID,'st_last_login',true);
    $times = array_column($sessions,'login');
    if (!ctype_digit((string)$login) || (int)$login<min($times)-1 || (int)$login>max($times)+5) { throw new RuntimeException('Native login timestamp is not owned'); }
    $snapshot = json_decode(file_get_contents('/tmp/module-target-sure-admin.json'),true,512,JSON_THROW_ON_ERROR);
    if ($snapshot['admin_id']!==$user->ID || count($snapshot['st_last_login'])>1) { throw new RuntimeException('Native login baseline differs'); }
    $manager->destroy_all();
    if ($snapshot['st_last_login']) { update_user_meta($user->ID,'st_last_login',$snapshot['st_last_login'][0]); }
    else { delete_user_meta($user->ID,'st_last_login'); }
    if (get_user_meta($user->ID,'st_last_login',false)!==$snapshot['st_last_login']) { throw new RuntimeException('Native login metadata restoration failed'); }
    $operation_result = ['removed'=>count($sessions),'username'=>$name,'agent'=>$agent,'login_timestamp_restored'=>true];
}
if ($operation === 'delete-plugin') {
    $path = WP_PLUGIN_DIR.'/native_sure_probe/native-proof.php';
    if (!is_file($path) || !hash_equals($argv[2],hash_file('sha256',$path))) { throw new RuntimeException('Owned native plugin differs'); }
    wp_set_current_user(get_user_by('login','module_admin')->ID);
    $result = delete_plugins(['native_sure_probe/native-proof.php']);
    if (is_wp_error($result) || !$result || is_dir(dirname($path))) { throw new RuntimeException('Native plugin deletion failed'); }
    $operation_result = ['plugin_removed'=>true];
}
if ($operation === 'record-options') {
    $path = '/tmp/module-target-sure-options.json';
    $snapshot = ['row'=>$option_row(),'value'=>get_option($option_name,[])];
    if (!is_array($snapshot['value'])) { throw new RuntimeException('Unexpected options type'); }
    if (file_exists($path)) {
        $recorded=json_decode(file_get_contents($path),true,512,JSON_THROW_ON_ERROR);
        if ($snapshot!==$recorded) { throw new RuntimeException('Recorded native options baseline changed'); }
    } else { file_put_contents($path,json_encode($snapshot,JSON_THROW_ON_ERROR));chmod($path,0600); }
    $operation_result = ['baseline_recorded'=>true];
}
if ($operation === 'restore-options') {
    $token = $argv[2] ?? '';$email = $argv[3] ?? '';
    $native=preg_match('/^native-sure-key-[a-z0-9-]+$/D',$token)===1 && $email==='native-sure@example.test';
    $public=preg_match('/^module-sure-key-[a-z0-9-]+$/D',$token)===1 && preg_match('/^module-sure-[a-z0-9-]+@example\.test$/D',$email)===1;
    if ((!$native && !$public) || \SureTriggers\Models\SaasApiToken::get()!==$token || \SureTriggers\Controllers\OptionController::get_option('connected_email_key')!==$email) { throw new RuntimeException('Refusing unowned options restoration'); }
    $snapshot = json_decode(file_get_contents('/tmp/module-target-sure-options.json'),true,512,JSON_THROW_ON_ERROR);
    $current = get_option($option_name,[]);$original = $snapshot['value'];
    $untouched_current = $current;$untouched_original = $original;
    foreach (['secret_key','connected_email_key'] as $key) { unset($untouched_current[$key],$untouched_original[$key]); }
    if ($untouched_current!==$untouched_original) { throw new RuntimeException('Unowned plugin options changed'); }
    foreach (['secret_key','connected_email_key'] as $key) {
        if (array_key_exists($key,$original)) { $current[$key] = $original[$key]; }
        else { unset($current[$key]); }
    }
    if ($snapshot['row']===null) { if ($current) { throw new RuntimeException('Cannot remove nonempty baseline options'); }delete_option($option_name); }
    else { update_option($option_name,$current,false); }
    \SureTriggers\Controllers\OptionController::$options = $current;
    if ($option_row()!==$snapshot['row']) { throw new RuntimeException('Exact stored option baseline did not restore'); }
    $operation_result = ['owned_options_restored'=>true,'raw_storage_restored'=>true];
}
$release = json_decode(file_get_contents('/opt/module-target/releases.json'),true,512,JSON_THROW_ON_ERROR)[getenv('SURE_RELEASE')];
$hashes = [];
foreach ($release['installed_sha256'] as $path=>$digest) { $hashes[$path] = hash_file('sha256',WP_PLUGIN_DIR.'/suretriggers/'.$path); }
$users = [];
foreach (get_users(['orderby'=>'ID','order'=>'ASC']) as $user) { $users[] = ['ID'=>$user->ID,'user_login'=>$user->user_login,'user_pass'=>$user->user_pass,'user_email'=>$user->user_email,'roles'=>$user->roles,'install_plugins'=>user_can($user,'install_plugins'),'sessions'=>WP_Session_Tokens::get_instance($user->ID)->get_all()]; }
$entries = [];
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(WP_PLUGIN_DIR,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::SELF_FIRST) as $entry) { $relative=substr($entry->getPathname(),strlen(WP_PLUGIN_DIR)+1);$entries[$relative]=$entry->isDir()?'directory':hash_file('sha256',$entry->getPathname()); }
ksort($entries);
$uploads = wp_upload_dir();$filesystem = [];
foreach (['plugins'=>WP_PLUGIN_DIR,'upload_base'=>$uploads['basedir'],'upload_current'=>$uploads['path']] as $label=>$path) { $filesystem[$label]=['path'=>$path,'uid'=>fileowner($path),'writable'=>is_writable($path)]; }
$filesystem['upload_error']=$uploads['error'];$filesystem['disk_free_bytes']=disk_free_space(ABSPATH);
$routes = rest_get_server()->get_routes();$handlers = [];
foreach (['/sure-triggers/v1/automation/action','/sure-triggers/v1/connection/create-wp-connection'] as $route) {
    $handlers[$route]=[];
    foreach (($routes[$route]??[]) as $endpoint) {
        if (!is_array($endpoint) || !isset($endpoint['callback'])) { continue; }
        $callback=$endpoint['callback'];$permission=$endpoint['permission_callback']??null;
        $format = static function ($handler) {
            return is_array($handler)?(is_object($handler[0])?get_class($handler[0]):$handler[0]).'::'.$handler[1]:$handler;
        };
        $handlers[$route][]=['callback'=>$format($callback),'permission'=>$format($permission)];
    }
}
echo json_encode([
    'core'=>get_bloginfo('version'),'php'=>PHP_VERSION,'uid'=>posix_geteuid(),'selected_release'=>getenv('SURE_RELEASE'),
    'version'=>get_plugin_data(WP_PLUGIN_DIR.'/suretriggers/suretriggers.php',false,false)['Version'],'constant_version'=>SURE_TRIGGERS_VER,
    'active_plugins'=>array_values(get_option('active_plugins')),'routes'=>$handlers,'route_urls'=>['action'=>wp_make_link_relative(rest_url('sure-triggers/v1/automation/action')),'connection'=>wp_make_link_relative(rest_url('sure-triggers/v1/connection/create-wp-connection')),'namespace'=>wp_make_link_relative(rest_url('sure-triggers/v1'))],'archive_sha256'=>hash_file('sha256','/opt/module-target/plugin.zip'),'installed_sha256'=>$hashes,'plugin_entries'=>$entries,
    'database'=>DB_NAME,'role'=>$wpdb->get_var('SELECT CURRENT_USER()'),'server'=>$wpdb->get_var('SELECT VERSION()'),'grants'=>$wpdb->get_col('SHOW GRANTS'),
    'users'=>$users,'usermeta'=>$wpdb->get_results("SELECT user_id,meta_key,meta_value FROM {$wpdb->usermeta} ORDER BY umeta_id",ARRAY_A),
    'plugin_options'=>$wpdb->get_results("SELECT option_name,option_value,autoload FROM {$wpdb->options} WHERE option_name LIKE 'suretrigger%' OR option_name LIKE 'sure_trigger%' OR option_name LIKE 'st_%' OR option_name LIKE 'fs_%' ORDER BY option_name",ARRAY_A),
    'option_value'=>get_option($option_name,[]),'option_row'=>$option_row(),'logical_token'=>\SureTriggers\Models\SaasApiToken::get(),
    'pages'=>$wpdb->get_results("SELECT ID,post_name,post_type,post_status,post_content FROM {$wpdb->posts} WHERE post_type='page' ORDER BY ID",ARRAY_A),
    'home'=>get_option('home'),'siteurl'=>get_option('siteurl'),'permalink_structure'=>get_option('permalink_structure'),'config_sha256'=>hash_file('sha256',ABSPATH.'wp-config.php'),
    'filesystem'=>$filesystem,'operation_result'=>$operation_result,'bootstrap_output_base64'=>base64_encode($bootstrap),'db_error'=>$wpdb->last_error
],JSON_PRETTY_PRINT|JSON_THROW_ON_ERROR),PHP_EOL;
