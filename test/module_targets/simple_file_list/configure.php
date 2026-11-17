<?php
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['SERVER_SOFTWARE'] = 'Apache';
$_SERVER['REQUEST_URI'] = '/';
require getcwd().'/wp-load.php';
require_once ABSPATH.'wp-admin/includes/plugin.php';
if (!is_plugin_active('simple-file-list/ee-simple-file-list.php') || !($eeSFL instanceof eeSFL_MainClass)) { throw new RuntimeException('Native plugin prerequisites absent'); }
$settings=get_option('eeSFL-Settings');
if (!is_array($settings) || !isset($settings[1])) { throw new RuntimeException('Native settings absent'); }
// File operations are under test; keep all notification mail in this owned lab off.
$settings[1]['Notify']='NO';update_option('eeSFL-Settings',$settings);
$page=wp_insert_post(['post_type'=>'page','post_title'=>'Native Simple File List','post_name'=>'native-simple-file-list','post_content'=>'[eeSFL]','post_status'=>'publish','post_author'=>1],true);
if (is_wp_error($page)) { throw new RuntimeException($page->get_error_message()); }
$eeSFL->eeSFL_UpdateFileListArray(1);
file_put_contents('/tmp/module-target-sfl-ready',"ready\n");
echo json_encode(['ready'=>true,'version'=>eeSFL_Version,'page'=>$page,'page_url'=>wp_make_link_relative(get_permalink($page))],JSON_THROW_ON_ERROR),PHP_EOL;
