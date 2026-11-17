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
if ($operation === 'cookie') {
    $cookie = base64_decode($argv[2],true);
    if ($cookie === false) { throw new RuntimeException('Invalid native cookie encoding'); }
    $operation_result=['validated_user_id'=>wp_validate_auth_cookie($cookie,'logged_in')];
}
if ($operation === 'password') {
    $user = get_user_by('login',$argv[2]);
    if (!$user) { throw new RuntimeException('Owned password target absent'); }
    $operation_result = ['valid'=>wp_check_password($argv[3],$user->user_pass,$user->ID),'user_id'=>$user->ID];
}
if ($operation === 'delete-user') {
    $name = $argv[2] ?? '';
    $user = get_user_by('login',$name);
    $native = $name === 'native_king_probe';
    $public = preg_match('/^module_king_[a-z0-9_]+$/D',$name) === 1;
    $email = $native ? 'native-king@example.test' : str_replace('_','-',$name).'@example.test';
    if ((!$native && !$public) || $name === 'module_king_existing' || !$user || $user->ID <= 4 || $user->user_email !== $email || !wp_check_password($argv[3],$user->user_pass,$user->ID)) { throw new RuntimeException('Refusing unowned user deletion'); }
    if ($public) {
        $agent = $argv[4] ?? '';
        if (!preg_match('/^module-target-king-public-[a-z0-9_-]+$/D',$agent)) { throw new RuntimeException('Refusing unknown public session owner'); }
        $sessions = WP_Session_Tokens::get_instance($user->ID)->get_all();
        if (count($sessions)>4) { throw new RuntimeException('Unexpected public token count'); }
        foreach ($sessions as $session) { if (($session['ua'] ?? '') !== $agent || $session['login']<time()-300 || $session['login']>time()+5) { throw new RuntimeException('Refusing unrelated public session deletion'); } }
    }
    $identifier = $user->ID;
    if (!wp_delete_user($identifier) || get_userdata($identifier) || get_user_meta($identifier)) { throw new RuntimeException('Owned native user deletion failed'); }
    $operation_result = ['deleted'=>$identifier,'username'=>$name];
}
if ($operation === 'clear-public-sessions') {
    $name = $argv[2] ?? '';$agent = $argv[4] ?? '';
    $user = get_user_by('login',$name);
    if ($name !== 'module_king_existing' || !$user || $user->ID !== 5 || $user->user_email !== 'module-king-existing@example.test' || !wp_check_password($argv[3],$user->user_pass,$user->ID) || !preg_match('/^module-target-king-public-[a-z0-9_-]+$/D',$agent)) { throw new RuntimeException('Refusing unowned existing-account cleanup'); }
    $manager = WP_Session_Tokens::get_instance($user->ID);$sessions=$manager->get_all();
    if (count($sessions)>4) { throw new RuntimeException('Unexpected existing-account token count'); }
    foreach ($sessions as $session) { if (($session['ua'] ?? '') !== $agent || $session['login']<time()-300 || $session['login']>time()+5) { throw new RuntimeException('Refusing unrelated existing-account session cleanup'); } }
    $manager->destroy_all();$operation_result=['removed'=>count($sessions),'username'=>$name,'agent'=>$agent];
}
if ($operation === 'clear-sessions') {
    $name = $argv[2] ?? '';$agent = $argv[3] ?? '';
    $user = get_user_by('login',$name);
    $owned = $user && (($name === 'module_admin' && $user->ID === 1) || ($name === 'module_king_existing' && $user->ID === 5 && $user->user_email === 'module-king-existing@example.test' && getenv('KING_EXISTING_ROLE')));
    if (!$owned || !preg_match('/^module-target-king-native-[a-z0-9_-]+-control$/D',$agent)) { throw new RuntimeException('Refusing unowned session cleanup'); }
    $manager = WP_Session_Tokens::get_instance(get_user_by('login',$name)->ID);$sessions=$manager->get_all();
    if (count($sessions)>2 || !$sessions) { throw new RuntimeException('Unexpected native token count'); }
    foreach ($sessions as $session) { if (($session['ua'] ?? '') !== $agent || $session['login']<time()-300 || $session['login']>time()+5) { throw new RuntimeException('Refusing unrelated session cleanup'); } }
    $manager->destroy_all();$operation_result=['removed'=>count($sessions),'username'=>$name,'agent'=>$agent];
}
if ($operation === 'delete-plugin') {
    $path = WP_PLUGIN_DIR.'/native_king_probe/native-proof.php';
    if (!is_file($path) || !hash_equals($argv[2],hash_file('sha256',$path))) { throw new RuntimeException('Owned native plugin differs'); }
    wp_set_current_user(get_user_by('login','module_admin')->ID);
    $result=delete_plugins(['native_king_probe/native-proof.php']);
    if (is_wp_error($result) || !$result || is_dir(dirname($path))) { throw new RuntimeException('Native plugin deletion failed'); }
    $operation_result=['plugin_removed'=>true];
}
$catalogs=[
    'elementor'=>json_decode(file_get_contents('/opt/module-target/elementor-releases.json'),true,512,JSON_THROW_ON_ERROR)['3.21.0'],
    'king-addons'=>json_decode(file_get_contents('/opt/module-target/releases.json'),true,512,JSON_THROW_ON_ERROR)[getenv('KING_RELEASE')]
];
$hashes=[];$archives=[];
foreach ($catalogs as $slug=>$catalog) {
    $archives[$slug]=hash_file('sha256','/opt/module-target/'.$slug.'.zip');
    foreach ($catalog['installed_sha256'] as $path=>$digest) { $hashes[$slug][$path]=hash_file('sha256',WP_PLUGIN_DIR.'/'.$slug.'/'.$path); }
}
$users=[];
foreach (get_users(['orderby'=>'ID','order'=>'ASC']) as $user) { $users[]=['ID'=>$user->ID,'user_login'=>$user->user_login,'user_pass'=>$user->user_pass,'user_email'=>$user->user_email,'roles'=>$user->roles,'install_plugins'=>user_can($user,'install_plugins'),'sessions'=>WP_Session_Tokens::get_instance($user->ID)->get_all()]; }
$entries=[];
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(WP_PLUGIN_DIR,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::SELF_FIRST) as $entry) { $relative=substr($entry->getPathname(),strlen(WP_PLUGIN_DIR)+1);$entries[$relative]=$entry->isDir()?'directory':hash_file('sha256',$entry->getPathname()); }
ksort($entries);
$uploads=wp_upload_dir();$filesystem=[];
foreach (['plugins'=>WP_PLUGIN_DIR,'upload_base'=>$uploads['basedir'],'upload_current'=>$uploads['path']]as$label=>$path) { $filesystem[$label]=['path'=>$path,'uid'=>fileowner($path),'writable'=>is_writable($path)]; }
$filesystem['upload_error']=$uploads['error'];$filesystem['disk_free_bytes']=disk_free_space(ABSPATH);
$options=$wpdb->get_results("SELECT option_name,option_value FROM {$wpdb->options} WHERE option_name LIKE 'king_addons%' OR option_name LIKE 'elementor%' OR option_name LIKE 'fs_%' ORDER BY option_name",ARRAY_A);
echo json_encode([
    'core'=>get_bloginfo('version'),'php'=>PHP_VERSION,'uid'=>posix_geteuid(),'selected_release'=>getenv('KING_RELEASE'),
    'version'=>get_plugin_data(WP_PLUGIN_DIR.'/king-addons/king-addons.php',false,false)['Version'],'constant_version'=>KING_ADDONS_VERSION,'elementor'=>ELEMENTOR_VERSION,
    'active_plugins'=>array_values(get_option('active_plugins')),'registration_handler'=>has_action('wp_ajax_nopriv_king_addons_user_register',['King_Addons\Widgets\Login_Register_Form\Login_Register_Form_Ajax','handle_register_ajax'])!==false,
    'users_can_register'=>(bool)get_option('users_can_register'),'archive_sha256'=>$archives,'installed_sha256'=>$hashes,'plugin_entries'=>$entries,
    'database'=>DB_NAME,'role'=>$wpdb->get_var('SELECT CURRENT_USER()'),'server'=>$wpdb->get_var('SELECT VERSION()'),'grants'=>$wpdb->get_col('SHOW GRANTS'),
    'users'=>$users,'usermeta'=>$wpdb->get_results("SELECT user_id,meta_key,meta_value FROM {$wpdb->usermeta} ORDER BY umeta_id",ARRAY_A),'plugin_options'=>$options,
    'pages'=>$wpdb->get_results("SELECT ID,post_name,post_type,post_status,post_content FROM {$wpdb->posts} WHERE post_type='page' ORDER BY ID",ARRAY_A),
    'page_metadata'=>$wpdb->get_results("SELECT post_id,meta_key,meta_value FROM {$wpdb->postmeta} WHERE meta_key LIKE '_elementor%' OR meta_key='_wp_page_template' ORDER BY meta_id",ARRAY_A),
    'home'=>get_option('home'),'siteurl'=>get_option('siteurl'),'permalink_structure'=>get_option('permalink_structure'),'registration_route'=>wp_make_link_relative(get_permalink(get_page_by_path('register'))),'config_sha256'=>hash_file('sha256',ABSPATH.'wp-config.php'),
    'filesystem'=>$filesystem,'operation_result'=>$operation_result,'bootstrap_output_base64'=>base64_encode($bootstrap),'db_error'=>$wpdb->last_error
],JSON_PRETTY_PRINT|JSON_THROW_ON_ERROR),PHP_EOL;
