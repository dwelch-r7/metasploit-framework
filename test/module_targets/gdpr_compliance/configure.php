<?php
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
require getcwd().'/wp-load.php';
if (!class_exists('WPGDPRC\WPGDPRC') || !has_action('wp_ajax_nopriv_wpgdprc_process_action', [WPGDPRC\Includes\Ajax::getInstance(), 'processAction'])) { throw new RuntimeException('Guest action handler absent'); }
if (get_option('default_role') !== 'subscriber' || get_option('users_can_register')) { throw new RuntimeException('Initial registration settings differ'); }
file_put_contents('/tmp/module-target-gdpr-ready', "ready\n");
echo "Native registration/configuration prerequisites ready\n";
