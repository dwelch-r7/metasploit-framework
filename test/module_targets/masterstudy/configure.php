<?php
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
require getcwd().'/wp-load.php';
if (!class_exists('STM_LMS_User') || !has_action('wp_ajax_nopriv_stm_lms_register', ['STM_LMS_User', 'stm_lms_register'])) { throw new RuntimeException('Registration handler absent'); }
if (STM_LMS_Options::get_option('user_premoderation', false) || STM_LMS_Helpers::g_recaptcha_enabled()) { throw new RuntimeException('Unexpected external registration prerequisite'); }
update_option('users_can_register', 1);
if (get_option('default_role') !== 'subscriber') { throw new RuntimeException('Unexpected default role'); }
file_put_contents('/tmp/module-target-masterstudy-ready', "ready\n");
echo "Native registration prerequisites ready\n";
