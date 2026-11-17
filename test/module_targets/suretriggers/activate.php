<?php
define('WP_ADMIN', true);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['PHP_SELF'] = '/wp-admin/plugins.php';
require getcwd().'/wp-load.php';
require_once ABSPATH.'wp-admin/includes/plugin.php';
wp_set_current_user(get_user_by('login','module_admin')->ID);
$result = activate_plugin('suretriggers/suretriggers.php');
if (is_wp_error($result) || !is_plugin_active('suretriggers/suretriggers.php')) { throw new RuntimeException(is_wp_error($result)?$result->get_error_message():'Native activation failed'); }
echo json_encode(['active'=>true,'version'=>SURE_TRIGGERS_VER],JSON_THROW_ON_ERROR),PHP_EOL;
