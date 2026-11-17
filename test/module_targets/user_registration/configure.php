<?php
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
require_once WP_PLUGIN_DIR . '/user-registration/includes/RestApi/controllers/version1/class-ur-getting-started.php';
wp_set_current_user(get_user_by('login', 'module_admin')->ID);
$request = new WP_REST_Request('POST');
$request->set_param('registrationType', 'user_registration_membership_registration');
$response = UR_Getting_Started::ur_registration_type_install_pages($request);
if (!$response instanceof WP_REST_Response || !$response->get_data()['success']) { throw new RuntimeException('Native onboarding failed'); }
// Exercise the supported core-login setting separately from onboarding's
// default plugin-login route, without modifying vendor authentication code.
if (getenv('UR_AUTH_MODE') === 'core') {
    update_option('user_registration_login_options_prevent_core_login', '0');
}
echo json_encode($response->get_data(), JSON_THROW_ON_ERROR), PHP_EOL;
