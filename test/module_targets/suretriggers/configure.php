<?php
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
require getcwd().'/wp-load.php';
require_once ABSPATH.'wp-admin/includes/plugin.php';
if (!is_plugin_active('suretriggers/suretriggers.php') || !class_exists('SureTriggers\Controllers\RestController')) { throw new RuntimeException('Native SureTriggers prerequisites absent'); }
$routes = rest_get_server()->get_routes();
foreach (['/sure-triggers/v1/automation/action','/sure-triggers/v1/connection/create-wp-connection'] as $route) {
    if (!isset($routes[$route])) { throw new RuntimeException('Native route absent: '.$route); }
}
$token = getenv('SURE_CONFIGURED_TOKEN') ?: '';
if ($token !== '') {
    if ($token !== 'fixture-sure-configured-secret') { throw new RuntimeException('Unknown owned configured token'); }
    \SureTriggers\Models\SaasApiToken::save($token);
}
$admin = get_user_by('login','module_admin');
$metadata = get_user_meta($admin->ID,'st_last_login',false);
if (count($metadata)>1) { throw new RuntimeException('Unexpected baseline login metadata'); }
$snapshot = ['admin_id'=>$admin->ID,'st_last_login'=>$metadata];
file_put_contents('/tmp/module-target-sure-admin.json',json_encode($snapshot,JSON_THROW_ON_ERROR));
chmod('/tmp/module-target-sure-admin.json',0600);
file_put_contents('/tmp/module-target-sure-ready',"ready\n");
echo json_encode(['ready'=>true,'version'=>SURE_TRIGGERS_VER,'configured'=>$token!==''],JSON_THROW_ON_ERROR),PHP_EOL;
