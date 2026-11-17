<?php
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
if (!is_plugin_active('user-registration/user-registration.php') || !ur_check_module_activation('membership')) { throw new RuntimeException('Native activation/onboarding did not persist'); }
if (!has_action('wp_ajax_nopriv_user_registration_membership_register_member') || !has_action('wp_ajax_nopriv_user_registration_user_form_submit')) { throw new RuntimeException('Native registration handlers absent'); }
$plans = get_posts(['post_type'=>'ur_membership','post_status'=>'publish','numberposts'=>-1]);
$forms = get_posts(['post_type'=>'user_registration','post_status'=>'publish','numberposts'=>-1]);
if (count($plans)!==1 || count($forms)!==1) { throw new RuntimeException('Native plan/form count differs'); }
flush_rewrite_rules(false);
file_put_contents(getcwd() . '/.htaccess', $wp_rewrite->mod_rewrite_rules());
file_put_contents('/tmp/module-target-registration-ready', "ready\n");
echo json_encode(['ready'=>true,'plan'=>$plans[0]->ID,'form'=>$forms[0]->ID], JSON_THROW_ON_ERROR), PHP_EOL;
