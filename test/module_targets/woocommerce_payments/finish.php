<?php
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'module-target.test';
require getcwd() . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$mode = getenv('WOO_PAYMENTS_MODE') ?: 'enabled';
if (is_plugin_active('woocommerce-payments/woocommerce-payments.php') !== ($mode !== 'absent')) { throw new RuntimeException('Native activation did not persist'); }
if ($mode === 'inactive') { deactivate_plugins('woocommerce-payments/woocommerce-payments.php'); }
flush_rewrite_rules(false);
file_put_contents(getcwd() . '/.htaccess', $wp_rewrite->mod_rewrite_rules());
file_put_contents('/tmp/module-target-woo-payments-ready', "ready\n");
echo "Native WooPayments ready\n";
