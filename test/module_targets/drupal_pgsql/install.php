<?php
const MODULE_TARGET_ROOT = '/var/www/module-target-drupal';
chdir(MODULE_TARGET_ROOT);
$_SERVER['HTTP_HOST'] = 'module-target.test';
$_SERVER['SERVER_NAME'] = 'module-target.test';
$_SERVER['SERVER_PORT'] = '80';
$_SERVER['SERVER_SOFTWARE'] = 'Apache';
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['REQUEST_URI'] = (getenv('LAB_PREFIX') ?: '') . '/core/install.php';
$_SERVER['SCRIPT_NAME'] = (getenv('LAB_PREFIX') ?: '') . '/core/install.php';
$_SERVER['PHP_SELF'] = (getenv('LAB_PREFIX') ?: '') . '/core/install.php';
$_SERVER['SCRIPT_FILENAME'] = MODULE_TARGET_ROOT . '/core/install.php';
$loader = require MODULE_TARGET_ROOT . '/autoload.php';
require_once MODULE_TARGET_ROOT . '/core/includes/install.core.inc';
$driver = getenv('DRUPAL_DB_DRIVER') ?: 'pgsql';
$namespace = $driver === 'mysql' ? 'Drupal\\mysql\\Driver\\Database\\mysql' : 'Drupal\\pgsql\\Driver\\Database\\pgsql';
install_drupal($loader, [
  'interactive' => false,
  'parameters' => ['profile' => 'standard', 'langcode' => 'en'],
  'forms' => [
    'install_settings_form' => [
      'driver' => $namespace,
      $namespace => ['database' => 'drupal_root', 'username' => 'module_target', 'password' => 'module-target-db-password', 'host' => ($driver === 'mysql' ? 'mysql' : 'db'), 'port' => ($driver === 'mysql' ? '3306' : '5432'), 'prefix' => ''],
    ],
    'install_configure_form' => [
      'site_name' => 'Module target Drupal',
      'site_mail' => 'module-site@example.test',
      'account' => ['name' => 'module_admin', 'mail' => 'module-admin@example.test', 'pass' => ['pass1' => 'module-target-password', 'pass2' => 'module-target-password']],
      'site_default_country' => 'GB',
      'date_default_timezone' => 'UTC',
      'enable_update_status_module' => false,
      'enable_update_status_emails' => false,
    ],
  ],
]);
file_put_contents(MODULE_TARGET_ROOT . '/sites/default/settings.php', "\n\$settings['trusted_host_patterns'] = ['^module-target\\\\.test$', '^localhost$', '^127\\\\.0\\\\.0\\\\.1$'];\n", FILE_APPEND);
echo "Genuine Core noninteractive installation completed\n";
