<?php
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
require getcwd().'/wp-load.php';
require_once ABSPATH.'wp-admin/includes/plugin.php';
if (!is_plugin_active('elementor/elementor.php') || !is_plugin_active('king-addons/king-addons.php') || !has_action('wp_ajax_nopriv_king_addons_user_register')) { throw new RuntimeException('Native plugin/registration prerequisites absent'); }
$widget = \Elementor\Plugin::$instance->widgets_manager->get_widget_types('king-addons-login-register-form');
if (!$widget || get_class($widget) !== 'King_Addons\Login_Register_Form') { throw new RuntimeException('Native widget unavailable: '.($widget?get_class($widget):'null')); }
update_option('users_can_register',getenv('KING_REGISTRATION') === '0' ? 0 : 1);
wp_set_current_user(get_user_by('login','module_admin')->ID);
$existing_role = getenv('KING_EXISTING_ROLE') ?: '';
if ($existing_role !== '') {
    if (!in_array($existing_role,['administrator','subscriber'],true)) { throw new RuntimeException('Unknown owned existing-account role'); }
    $existing = wp_insert_user(['user_login'=>'module_king_existing','user_email'=>'module-king-existing@example.test','user_pass'=>'Module-target-king+2026!','role'=>$existing_role]);
    if (is_wp_error($existing) || $existing !== 5) { throw new RuntimeException('Owned existing-account setup failed'); }
}
$page = get_page_by_path('register');
if ($page) { throw new RuntimeException('Owned native page unexpectedly exists'); }
$page = wp_insert_post(['post_type'=>'page','post_status'=>'publish','post_title'=>'Register','post_name'=>'register','post_content'=>'','post_author'=>1],true);
if (is_wp_error($page)) { throw new RuntimeException($page->get_error_message()); }
$data = [['id'=>'c0ffee1','elType'=>'section','settings'=>[],'elements'=>[['id'=>'c0ffee2','elType'=>'column','settings'=>['_column_size'=>100],'elements'=>[['id'=>'c0ffee3','elType'=>'widget','widgetType'=>'king-addons-login-register-form','settings'=>['default_form_type'=>'register']]]]]]];
update_post_meta($page,'_elementor_data',wp_slash(wp_json_encode($data)));
update_post_meta($page,'_elementor_edit_mode','builder');
update_post_meta($page,'_elementor_template_type','page');
update_post_meta($page,'_elementor_version',ELEMENTOR_VERSION);
update_post_meta($page,'_wp_page_template','elementor_canvas');
\Elementor\Plugin::$instance->files_manager->clear_cache();
flush_rewrite_rules(false);
file_put_contents(getcwd().'/.htaccess',$wp_rewrite->mod_rewrite_rules());
$route = wp_make_link_relative(get_permalink($page));
if (!str_starts_with($route,'/') || str_contains($route,"\n")) { throw new RuntimeException('Unexpected native page route'); }
file_put_contents('/tmp/module-target-king-widget-route',$route);
file_put_contents('/tmp/module-target-king-ready',"ready\n");
echo json_encode(['ready'=>true,'page'=>$page,'widget'=>get_class($widget),'elementor'=>ELEMENTOR_VERSION,'king'=>KING_ADDONS_VERSION],JSON_THROW_ON_ERROR),PHP_EOL;
